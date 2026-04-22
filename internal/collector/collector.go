package collector

import (
	"context"
	"errors"
	"fmt"
	"math"
	"slices"
	"strings"
	"time"

	"google.golang.org/api/googleapi"

	"github.com/locktivity/epack-collector-google-workspace/internal/googleworkspace"
)

// Collector gathers Google Workspace posture metrics.
type Collector struct {
	client   googleworkspace.Client
	config   Config
	now      func() time.Time
	warnings []string
}

// New creates a collector backed by the Google Admin SDK.
func New(ctx context.Context, config Config) (*Collector, error) {
	if config.AdminEmail == "" {
		return nil, fmt.Errorf("admin_email is required")
	}

	client, err := googleworkspace.NewClient(ctx, config.AdminEmail, config.CredentialsJSON)
	if err != nil {
		return nil, fmt.Errorf("creating google workspace client: %w", err)
	}

	return newCollector(config, client), nil
}

// NewWithClient creates a collector with an injected client for testing.
func NewWithClient(config Config, client googleworkspace.Client) *Collector {
	return newCollector(config, client)
}

func newCollector(config Config, client googleworkspace.Client) *Collector {
	now := config.Now
	if now == nil {
		now = time.Now
	}

	return &Collector{
		client: client,
		config: config,
		now:    now,
	}
}

func (c *Collector) warn(format string, args ...interface{}) {
	c.warnings = append(c.warnings, fmt.Sprintf(format, args...))
}

func (c *Collector) diagnostics() *Diagnostics {
	if len(c.warnings) == 0 {
		return nil
	}

	return &Diagnostics{Warnings: append([]string(nil), c.warnings...)}
}

func (c *Collector) status(message string) {
	if c.config.OnStatus != nil {
		c.config.OnStatus(message)
	}
}

func (c *Collector) progress(current, total int64, message string) {
	if c.config.OnProgress != nil {
		c.config.OnProgress(current, total, message)
	}
}

func (c *Collector) customerKey() string {
	if c.config.Customer != "" {
		return c.config.Customer
	}
	return googleworkspace.DefaultCustomerKey
}

// Collect gathers the Google Workspace identity posture.
func (c *Collector) Collect(ctx context.Context) (*OrgPosture, error) {
	customerKey := c.customerKey()
	c.warnings = nil

	// Step 1: Resolve customer metadata.
	c.status(fmt.Sprintf("Resolving Google Workspace customer %s...", customerKey))
	customer, err := c.client.GetCustomer(ctx, customerKey)
	if err != nil {
		return nil, fmt.Errorf("getting customer metadata: %w", err)
	}
	if customer.PrimaryDomain == "" {
		return nil, fmt.Errorf("customer %s did not return a primary domain", customerKey)
	}

	collectedAt := c.now().UTC()

	// Step 2: Fetch usage report from Reports API.
	// Google Workspace usage reports have a 2-3 day lag. We try progressively
	// older dates starting from yesterday (Pacific Time) until we find one
	// that has data, or exhaust our attempts.
	report, reportDate, err := c.fetchUsageReport(ctx, customer.ID, collectedAt)
	if err != nil {
		return nil, fmt.Errorf("getting usage report: %w", err)
	}

	posture := NewOrgPosture(customer.PrimaryDomain, customer.ID, reportDate, collectedAt)

	if report.NumUsers == 0 {
		c.warn("usage report for %s returned no user data; tenant may be too new for report generation", reportDate)
	}

	posture.Users = UserMetrics{
		Total:        int(report.NumUsers),
		Suspended:    int(report.NumSuspendedUsers),
		Archived:     int(report.NumArchivedUsers),
		LockedPct:    percentFloat(int(report.NumLockedUsers), int(report.NumUsers)),
		InactiveDays: DefaultInactiveDays,
	}
	posture.Activity = ActivityMetrics{
		Active7dPct:  percentFloat(int(report.Num7DayLogins), int(report.NumUsers)),
		Active30dPct: percentFloat(int(report.Num30DayLogins), int(report.NumUsers)),
	}
	posture.Authentication = AuthMetrics{
		TwoSVEnrolledPct:  percentFloat(int(report.NumUsers2SVEnrolled), int(report.NumUsers)),
		TwoSVEnforcedPct:  percentFloat(int(report.NumUsers2SVEnforced), int(report.NumUsers)),
		TwoSVProtectedPct: percentFloat(int(report.NumUsers2SVProtected), int(report.NumUsers)),
		PasskeyUsersPct:   percentFloat(int(report.NumUsersWithPasskeysEnrolled), int(report.NumUsers)),
		SecurityKeysTotal: int(report.NumSecurityKeys),
	}
	posture.Passwords = PasswordMetrics{
		WeakPasswordPct:               percentFloat(int(report.NumUsersPasswordStrengthWeak), int(report.NumUsers)),
		PasswordLengthNonCompliantPct: percentFloat(int(report.NumUsersPasswordLengthNonCompliant), int(report.NumUsers)),
	}
	posture.Apps = AppMetrics{
		AuthorizedAppsCount: int(report.NumAuthorizedApps),
	}

	// Step 3: List users for admin counts and 90-day inactivity.
	c.status("Scanning users for admin status and inactivity...")
	inactiveThreshold := collectedAt.AddDate(0, 0, -DefaultInactiveDays)
	userScan, err := c.scanUsers(ctx, customerKey, inactiveThreshold)
	if err != nil {
		return nil, fmt.Errorf("scanning users: %w", err)
	}
	posture.Admins = userScan.admins
	posture.Users.InactivePct = percentFloat(userScan.inactiveCount, userScan.activeCount)

	report2SVEnforcedPct := posture.Authentication.TwoSVEnforcedPct
	posture.Authentication.TwoSVEnforcedPct = percentFloat(userScan.enforced2SVCount, userScan.activeCount)
	if math.Abs(report2SVEnforcedPct-posture.Authentication.TwoSVEnforcedPct) >= 1 {
		c.warn("2SV enforcement coverage differs between the lagged usage report (%.2f%%) and live Directory user flags (%.2f%%); using the live Directory value", report2SVEnforcedPct, posture.Authentication.TwoSVEnforcedPct)
	}

	// Step 4: Query Context-Aware Access deny events for evidence that Google
	// evaluated device-state conditions for tenant access. These logs are
	// deny-only and can include monitor-mode hits, so they are a useful positive
	// signal but not a complete policy model.
	c.status("Scanning Context-Aware Access audit events for device-state deny evidence...")
	deviceAccess, err := c.scanDeviceAccess(ctx, customer.ID, collectedAt.AddDate(0, 0, -DefaultContextAwareAccessLookbackDays))
	if err != nil {
		c.warn("context-aware access audit scan failed; device access posture omitted: %v", err)
	} else {
		posture.DeviceAccess = &deviceAccess
		if deviceAccess.ManagedDeviceRequirementEvidenced {
			c.warn("device access posture is inferred from deny-only Context-Aware Access audit events; absence of events is not evidence of absence, and monitor-mode access levels may produce similar deny events")
		}
	}

	if posture.DeviceAccess != nil && c.hasAccessContextManagerConfig() {
		c.status("Scanning Access Context Manager access-level config...")
		acm, err := c.scanAccessContextManager(ctx)
		if err != nil {
			c.warn("access context manager scan failed; config enrichment omitted: %v", err)
		} else {
			posture.DeviceAccess.AccessContextManager = acm
			if acm.CustomAccessLevelsCount > 0 {
				c.warn("access context manager includes %d custom access levels; device-policy summary only analyzes basic access levels", acm.CustomAccessLevelsCount)
			}
			if posture.DeviceAccess.ManagedDeviceRequirementEvidenced && acm.BasicDevicePolicyAccessLevelsCount == 0 && acm.CustomAccessLevelsCount == 0 {
				c.warn("device-state deny evidence was observed, but no basic Access Context Manager device-policy levels were found; this can indicate Workspace-side assignment gaps or monitor-mode ambiguity")
			}
		}
	}

	c.warn("usage report metrics are as of %s; 2SV enforcement, admin counts, and inactivity reflect current Directory state and may differ slightly", reportDate)
	posture.Diagnostics = c.diagnostics()

	c.status("Collection complete")
	return posture, nil
}

type userScanResult struct {
	admins           AdminMetrics
	activeCount      int
	inactiveCount    int
	enforced2SVCount int
}

type deviceAccessScanResult struct {
	contextAwareAccessDeniedEvents int
	deviceStateDeniedEvents        int
}

func (c *Collector) hasAccessContextManagerConfig() bool {
	return strings.TrimSpace(c.config.AccessPolicy) != "" || strings.TrimSpace(c.config.OrganizationID) != ""
}

func (c *Collector) scanUsers(ctx context.Context, customerKey string, inactiveThreshold time.Time) (userScanResult, error) {
	var (
		superAdmins           int
		delegatedAdmins       int
		privilegedTotal       int
		privileged2SVEnrolled int
		privileged2SVEnforced int
		activeCount           int
		inactiveCount         int
		enforced2SVCount      int
		processed             int64
	)

	err := c.client.ListUsers(ctx, customerKey, func(users []googleworkspace.User) error {
		for _, user := range users {
			processed++
			if processed%500 == 0 {
				c.progress(processed, 0, "Scanning users")
			}

			if user.Suspended || user.Archived {
				continue
			}
			activeCount++
			if user.IsEnforcedIn2Sv {
				enforced2SVCount++
			}

			// Inactivity: never logged in or last login before threshold.
			if user.LastLoginMissing || user.LastLoginTime.Before(inactiveThreshold) {
				inactiveCount++
			}

			// Admin counts.
			isPrivileged := false
			if user.IsAdmin {
				superAdmins++
				isPrivileged = true
			}
			if user.IsDelegatedAdmin {
				delegatedAdmins++
				isPrivileged = true
			}
			if isPrivileged {
				if user.IsEnrolledIn2Sv {
					privileged2SVEnrolled++
				}
				if user.IsEnforcedIn2Sv {
					privileged2SVEnforced++
				}
				privilegedTotal++
			}
		}
		return nil
	})
	if err != nil {
		return userScanResult{}, err
	}

	return userScanResult{
		admins: AdminMetrics{
			PrivilegedUsersCount:          privilegedTotal,
			SuperAdminCount:               superAdmins,
			DelegatedAdminCount:           delegatedAdmins,
			PrivilegedUsers2SVEnrolledPct: percentFloat(privileged2SVEnrolled, privilegedTotal),
			PrivilegedUsers2SVEnforcedPct: percentFloat(privileged2SVEnforced, privilegedTotal),
		},
		activeCount:      activeCount,
		inactiveCount:    inactiveCount,
		enforced2SVCount: enforced2SVCount,
	}, nil
}

func (c *Collector) scanDeviceAccess(ctx context.Context, customerID string, startTime time.Time) (DeviceAccessMetrics, error) {
	var result deviceAccessScanResult

	err := c.client.ListContextAwareAccessEvents(ctx, customerID, startTime, func(events []googleworkspace.ContextAwareAccessEvent) error {
		result.contextAwareAccessDeniedEvents += len(events)
		for _, event := range events {
			if strings.TrimSpace(event.DeviceState) == "" {
				continue
			}
			result.deviceStateDeniedEvents++
		}
		return nil
	})
	if err != nil {
		return DeviceAccessMetrics{}, err
	}

	return DeviceAccessMetrics{
		LookbackDays:                      DefaultContextAwareAccessLookbackDays,
		ContextAwareAccessDeniedEvents:    result.contextAwareAccessDeniedEvents,
		DeviceStateDeniedEvents:           result.deviceStateDeniedEvents,
		ManagedDeviceRequirementEvidenced: result.deviceStateDeniedEvents > 0,
	}, nil
}

func (c *Collector) scanAccessContextManager(ctx context.Context) (*AccessContextManagerMetrics, error) {
	policy, err := c.resolveAccessPolicy(ctx)
	if err != nil {
		return nil, err
	}

	summary := &AccessContextManagerMetrics{
		AccessPolicyName:   policy.Name,
		AccessPolicyParent: policy.Parent,
	}

	err = c.client.ListAccessLevels(ctx, policy.Name, func(levels []googleworkspace.AccessLevel) error {
		for _, level := range levels {
			if level.Custom {
				summary.CustomAccessLevelsCount++
				continue
			}

			summary.BasicAccessLevelsCount++
			if !level.HasDevicePolicy {
				continue
			}

			summary.BasicDevicePolicyAccessLevelsCount++
			summary.BasicDevicePolicyAccessLevelTitles = append(summary.BasicDevicePolicyAccessLevelTitles, accessLevelDisplayName(level))
			if levelExplicitlyRequiresManagedDevice(level) {
				summary.BasicManagedDeviceAccessLevelsCount++
			}
		}
		return nil
	})
	if err != nil {
		return nil, err
	}

	slices.Sort(summary.BasicDevicePolicyAccessLevelTitles)
	return summary, nil
}

func (c *Collector) resolveAccessPolicy(ctx context.Context) (googleworkspace.AccessPolicy, error) {
	if policy := normalizeAccessPolicyName(c.config.AccessPolicy); policy != "" {
		return googleworkspace.AccessPolicy{
			Name:   policy,
			Parent: normalizeOrganizationParent(c.config.OrganizationID),
		}, nil
	}

	parent := normalizeOrganizationParent(c.config.OrganizationID)
	if parent == "" {
		return googleworkspace.AccessPolicy{}, fmt.Errorf("organization_id or access_policy is required for access context manager enrichment")
	}

	var policies []googleworkspace.AccessPolicy
	err := c.client.ListAccessPolicies(ctx, parent, func(batch []googleworkspace.AccessPolicy) error {
		policies = append(policies, batch...)
		return nil
	})
	if err != nil {
		return googleworkspace.AccessPolicy{}, err
	}
	if len(policies) == 0 {
		return googleworkspace.AccessPolicy{}, fmt.Errorf("no access context manager policy found for %s", parent)
	}

	slices.SortFunc(policies, func(a, b googleworkspace.AccessPolicy) int {
		return strings.Compare(a.Name, b.Name)
	})
	if len(policies) > 1 {
		c.warn("multiple access context manager policies found for %s; using %s", parent, policies[0].Name)
	}

	return policies[0], nil
}

func normalizeOrganizationParent(raw string) string {
	value := strings.TrimSpace(raw)
	if value == "" {
		return ""
	}
	if strings.HasPrefix(value, "organizations/") {
		return value
	}
	return "organizations/" + value
}

func normalizeAccessPolicyName(raw string) string {
	value := strings.TrimSpace(raw)
	if value == "" {
		return ""
	}
	if strings.HasPrefix(value, "accessPolicies/") {
		return value
	}
	return "accessPolicies/" + value
}

func accessLevelDisplayName(level googleworkspace.AccessLevel) string {
	if strings.TrimSpace(level.Title) != "" {
		return level.Title
	}
	return level.Name
}

func levelExplicitlyRequiresManagedDevice(level googleworkspace.AccessLevel) bool {
	if len(level.AllowedDeviceManagementLevels) == 0 {
		return false
	}

	for _, managementLevel := range level.AllowedDeviceManagementLevels {
		if managementLevel == "NONE" || managementLevel == "MANAGEMENT_UNSPECIFIED" {
			return false
		}
	}
	return true
}

// maxReportRetries is the number of progressively older dates to try when
// the Reports API returns a "data not yet available" error.
const maxReportRetries = 4

// fetchUsageReport tries progressively older report dates (yesterday minus 0..3
// extra days in Pacific Time) until it finds one with data. Google Workspace
// usage reports typically lag 2-3 days behind the current date.
//
// The Reports API can signal "no data" in two ways:
//   - HTTP 400 with "not yet available" (caught as an error)
//   - HTTP 200 with a warnings[] entry like "Data is not available"
//
// Both are treated as retryable. A "Partial data is available" warning is
// surfaced as a diagnostic but the report is still used.
func (c *Collector) fetchUsageReport(ctx context.Context, customerID string, collectedAt time.Time) (googleworkspace.CustomerUsageReport, string, error) {
	pacific := collectedAt.In(pacificLocation)

	for i := range maxReportRetries {
		date := pacific.AddDate(0, 0, -(1 + i)).Format("2006-01-02")
		c.status(fmt.Sprintf("Fetching usage report for %s...", date))

		report, err := c.client.GetCustomerUsageReport(ctx, customerID, date)
		if err != nil {
			if isDataNotYetAvailable(err) {
				c.warn("usage report for %s is not yet available; trying an older date", date)
				continue
			}
			return googleworkspace.CustomerUsageReport{}, "", err
		}

		// Check for 200-level warnings that indicate missing or partial data.
		if hasDataNotAvailableWarning(report.Warnings) {
			c.warn("usage report for %s returned a 'data not available' warning; trying an older date", date)
			continue
		}
		for _, w := range report.Warnings {
			if strings.Contains(w.Message, "Partial data") {
				c.warn("usage report for %s returned a partial-data warning: %s", date, w.Message)
			}
		}

		if i > 0 {
			c.warn("usage report for the most recent date was not available; fell back to %s", date)
		}
		return report, date, nil
	}

	return googleworkspace.CustomerUsageReport{}, "", fmt.Errorf("no usage report available for the last %d days", maxReportRetries)
}

// isDataNotYetAvailable checks whether a Google API error indicates the
// requested report date hasn't been generated yet.
func isDataNotYetAvailable(err error) bool {
	var apiErr *googleapi.Error
	if errors.As(err, &apiErr) && apiErr.Code == 400 {
		return strings.Contains(apiErr.Message, "not yet available")
	}
	return false
}

// hasDataNotAvailableWarning checks whether a 200 response carries a warning
// indicating the report data is not available for the requested date.
func hasDataNotAvailableWarning(warnings []googleworkspace.ReportWarning) bool {
	for _, w := range warnings {
		if strings.Contains(w.Message, "Data is not available") {
			return true
		}
	}
	return false
}

// pacificLocation is the timezone Google uses for usage report day boundaries.
// The main binary imports time/tzdata to guarantee this succeeds in minimal
// container environments without system tzdata.
var pacificLocation = func() *time.Location {
	loc, err := time.LoadLocation("America/Los_Angeles")
	if err != nil {
		panic("failed to load America/Los_Angeles timezone: " + err.Error())
	}
	return loc
}()

// reportDateFor returns the most recent fully-closed report date.
// Google Workspace usage reports are keyed to Pacific Time days, so we
// convert to Pacific before subtracting a day to avoid requesting a
// report that hasn't fully closed yet.
func reportDateFor(now time.Time) string {
	return now.In(pacificLocation).AddDate(0, 0, -1).Format("2006-01-02")
}

func percentFloat(part, total int) float64 {
	if total == 0 {
		return 0
	}
	pct := float64(part) / float64(total) * 100
	return math.Round(pct*100) / 100
}
