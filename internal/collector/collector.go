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
	"github.com/locktivity/epack/componentsdk"
)

// Collector gathers Google Workspace posture metrics.
type Collector struct {
	client           googleworkspace.Client
	config           Config
	now              func() time.Time
	warnings         []string
	permissionErrors []string
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

func (c *Collector) permissionError(format string, args ...interface{}) {
	c.permissionErrors = append(c.permissionErrors, fmt.Sprintf(format, args...))
}

func (c *Collector) diagnostics() *Diagnostics {
	if len(c.warnings) == 0 && len(c.permissionErrors) == 0 {
		return nil
	}

	d := &Diagnostics{}
	if len(c.permissionErrors) > 0 {
		d.PermissionErrors = append([]string(nil), c.permissionErrors...)
	}
	if len(c.warnings) > 0 {
		d.Warnings = append([]string(nil), c.warnings...)
	}
	return d
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

// Collect gathers the Google Workspace identity posture. level controls the
// depth of collection (trust / audit / internal). Unknown or empty levels are
// treated as LevelTrust by the SDK reader; callers should not pre-validate.
// See the README for the per-surface field availability per level.
func (c *Collector) Collect(ctx context.Context, level componentsdk.Level) (*OrgPosture, error) {
	customerKey := c.customerKey()
	c.warnings = nil
	c.permissionErrors = nil

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
	scope := scanScope{
		customerKey:   customerKey,
		customerID:    customer.ID,
		primaryDomain: customer.PrimaryDomain,
		collectedAt:   collectedAt,
		level:         level,
	}

	// Step 2: Fetch usage report from Reports API.
	// Google Workspace usage reports have a 2-3 day lag. We try progressively
	// older dates starting from yesterday (Pacific Time) until we find one
	// that has data, or exhaust our attempts.
	report, reportDate, reportErr := c.fetchUsageReport(ctx, customer.ID, collectedAt)
	if reportErr != nil {
		c.warnSurfaceScan("usage_report", "admin.reports.usage.readonly", "Reports Admin (or Super Admin)", reportErr)
		report = googleworkspace.CustomerUsageReport{}
	}

	posture := NewOrgPosture(customer.PrimaryDomain, customer.ID, reportDate, collectedAt)
	posture.CollectedAtLevel = string(level)

	if reportErr == nil && report.NumUsers == 0 {
		c.warn("usage report for %s returned no user data; tenant may be too new for report generation", reportDate)
	}

	applyUsageReport(posture, report, level)

	// Step 3: List users for admin counts and 90-day inactivity.
	c.status("Scanning users for admin status and inactivity...")
	userScan, scanErr := c.scanUsers(ctx, scope)
	if scanErr != nil {
		c.warnSurfaceScan("users", "admin.directory.user.readonly", "User Management Admin (or Super Admin)", scanErr)
		userScan = userScanResult{}
	}
	posture.Admins = userScan.admins
	posture.Users.Inventory = userScan.inventory
	posture.Users.TruncatedInventory = userScan.inventoryTruncated
	posture.Users.TruncatedInventoryDropped = userScan.inventoryDropped

	if scanErr == nil {
		posture.Users.InactivePct = percentFloat(userScan.inactiveCount, userScan.activeCount)

		if level.AtLeast(componentsdk.LevelAudit) {
			c.status("Scanning admin roles and assignments...")
			posture.Admins.Inventory, posture.Admins.CustomRoles = c.enrichAdminInventory(ctx, scope, userScan)
		}

		report2SVEnforcedPct := posture.Authentication.TwoSVEnforcedPct
		posture.Authentication.TwoSVEnforcedPct = percentFloat(userScan.enforced2SVCount, userScan.activeCount)
		if math.Abs(report2SVEnforcedPct-posture.Authentication.TwoSVEnforcedPct) >= 1 {
			c.warn("2SV enforcement coverage differs between the lagged usage report (%.2f%%) and live Directory user flags (%.2f%%); using the live Directory value", report2SVEnforcedPct, posture.Authentication.TwoSVEnforcedPct)
		}
	}

	// Step 4: Query Context-Aware Access deny events for evidence that Google
	// evaluated device-state conditions for tenant access. These logs are
	// deny-only and can include monitor-mode hits, so they are a useful positive
	// signal but not a complete policy model.
	c.status("Scanning Context-Aware Access audit events for device-state deny evidence...")
	deviceAccess, err := c.scanDeviceAccess(ctx, scope)
	if err != nil {
		c.warnSurfaceScan("device_access", "admin.reports.audit.readonly", "Reports Admin (or Super Admin)", err)
	} else {
		posture.DeviceAccess = &deviceAccess
		if deviceAccess.ManagedDeviceRequirementEvidenced {
			c.warn("device access posture is inferred from deny-only Context-Aware Access audit events; absence of events is not evidence of absence, and monitor-mode access levels may produce similar deny events")
		}
	}

	if posture.DeviceAccess != nil && c.hasAccessContextManagerConfig() {
		c.status("Scanning Access Context Manager access-level config...")
		acm, err := c.scanAccessContextManager(ctx, scope)
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

	c.status("Scanning groups...")
	posture.Groups = c.scanGroups(ctx, scope)

	c.status("Scanning org units...")
	posture.OrgUnits = c.scanOrgUnits(ctx, scope, userScan.usersByOU)

	c.status("Scanning managed devices...")
	posture.Endpoint = c.scanEndpoint(ctx, scope)

	c.status("Scanning audit logs...")
	posture.DriveExternalSharing = c.scanDriveExternalSharing(ctx, scope)
	posture.AdminAuditLog = c.scanAdminAuditLog(ctx, scope)
	posture.LoginAuditLog = c.scanLoginAuditLog(ctx, scope)
	posture.OAuthTokens = c.scanOAuthTokens(ctx, scope)

	c.status("Scanning domain and SSO settings...")
	posture.DomainSettings = c.scanDomainSettings(ctx, scope)

	c.status("Scanning Vault...")
	posture.Vault = c.scanVault(ctx, scope)

	if reportErr == nil {
		c.warn("usage report metrics are as of %s; 2SV enforcement, admin counts, and inactivity reflect current Directory state and may differ slightly", reportDate)
	}
	posture.Diagnostics = c.diagnostics()

	c.status("Collection complete")
	return posture, nil
}

// scanScope carries the per-collection parameters shared by the surface
// scanners: the customer identifiers, primary domain, collection timestamp, and
// level. ctx is passed as a separate argument, not embedded. Scanners derive
// their own time windows from collectedAt.
type scanScope struct {
	customerKey   string // unresolved key for directory.users.list ("my_customer" or config)
	customerID    string // resolved customer ID used by every other endpoint
	primaryDomain string
	collectedAt   time.Time
	level         componentsdk.Level
}

type userScanResult struct {
	admins             AdminMetrics
	activeCount        int
	inactiveCount      int
	enforced2SVCount   int
	inventory          []User
	inventoryTruncated bool
	inventoryDropped   int
	adminRows          []Admin        // per-privileged-user rows (audit+), aligned with adminIDs
	adminIDs           []string       // directory user IDs, for role-assignment correlation
	usersByOU          map[string]int // user count per org-unit path, for the OrgUnits surface
}

type deviceAccessScanResult struct {
	contextAwareAccessDeniedEvents int
	deviceStateDeniedEvents        int
}

func (c *Collector) hasAccessContextManagerConfig() bool {
	return strings.TrimSpace(c.config.AccessPolicy) != "" || strings.TrimSpace(c.config.OrganizationID) != ""
}

func (c *Collector) scanUsers(ctx context.Context, scope scanScope) (userScanResult, error) {
	inactiveThreshold := scope.collectedAt.AddDate(0, 0, -DefaultInactiveDays)
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
		inventory             []User
		adminRows             []Admin
		adminIDs              []string
		usersByOU             = make(map[string]int)
	)

	collectInventory := scope.level.AtLeast(componentsdk.LevelAudit)
	includeInternal := scope.level.AtLeast(componentsdk.LevelInternal)
	active7dThreshold := scope.collectedAt.AddDate(0, 0, -7)
	active30dThreshold := scope.collectedAt.AddDate(0, 0, -30)

	err := c.client.ListUsers(ctx, scope.customerKey, func(users []googleworkspace.User) error {
		for _, user := range users {
			processed++
			if processed%500 == 0 {
				c.progress(processed, 0, "Scanning users")
			}

			if collectInventory {
				inventory = append(inventory, buildUserRow(user, active7dThreshold, active30dThreshold, includeInternal))
			}
			if user.OrgUnitPath != "" {
				usersByOU[user.OrgUnitPath]++
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

				if collectInventory {
					adminRows = append(adminRows, Admin{
						PrimaryEmail:   user.PrimaryEmail,
						SuperAdmin:     user.IsAdmin,
						DelegatedAdmin: user.IsDelegatedAdmin,
						TwoSVEnrolled:  user.IsEnrolledIn2Sv,
						TwoSVEnforced:  user.IsEnforcedIn2Sv,
					})
					adminIDs = append(adminIDs, user.ID)
				}
			}
		}
		return nil
	})
	if err != nil {
		return userScanResult{}, err
	}

	var inventoryDropped int
	var inventoryTruncated bool
	if collectInventory {
		inventory, inventoryDropped, inventoryTruncated = truncateAndWarn(c, inventory, UsersCap, "user inventory", lessUserRow)
	}

	return userScanResult{
		admins: AdminMetrics{
			PrivilegedUsersCount:          privilegedTotal,
			SuperAdminCount:               superAdmins,
			DelegatedAdminCount:           delegatedAdmins,
			PrivilegedUsers2SVEnrolledPct: percentFloat(privileged2SVEnrolled, privilegedTotal),
			PrivilegedUsers2SVEnforcedPct: percentFloat(privileged2SVEnforced, privilegedTotal),
		},
		activeCount:        activeCount,
		inactiveCount:      inactiveCount,
		enforced2SVCount:   enforced2SVCount,
		inventory:          inventory,
		inventoryTruncated: inventoryTruncated,
		inventoryDropped:   inventoryDropped,
		adminRows:          adminRows,
		adminIDs:           adminIDs,
		usersByOU:          usersByOU,
	}, nil
}

// buildUserRow maps a directory user to a per-user inventory row. includeInternal
// adds the internal-only fields (last-login timestamp, change-password flag).
func buildUserRow(user googleworkspace.User, active7d, active30d time.Time, includeInternal bool) User {
	row := User{
		PrimaryEmail:  user.PrimaryEmail,
		Suspended:     user.Suspended,
		Archived:      user.Archived,
		OrgUnitPath:   user.OrgUnitPath,
		AgreedToTerms: user.AgreedToTerms,
		IPAllowlisted: user.IPWhitelisted,
		TwoSVEnrolled: user.IsEnrolledIn2Sv,
		TwoSVEnforced: user.IsEnforcedIn2Sv,
	}
	if !user.CreationTime.IsZero() {
		row.CreatedAt = user.CreationTime.UTC().Format(time.RFC3339)
	}
	if !user.LastLoginMissing {
		row.Active7d = !user.LastLoginTime.Before(active7d)
		row.Active30d = !user.LastLoginTime.Before(active30d)
	}
	if includeInternal {
		row.ChangePasswordAtNextLogin = user.ChangePasswordAtNextLogin
		if !user.LastLoginMissing {
			row.LastLoginAt = user.LastLoginTime.UTC().Format(time.RFC3339)
		}
	}
	return row
}

// lessUserRow sorts active (non-suspended, non-archived) users first, then by
// primary email ascending, so the most posture-relevant rows survive the cap.
func lessUserRow(a, b User) bool {
	aInactive := a.Suspended || a.Archived
	bInactive := b.Suspended || b.Archived
	if aInactive != bInactive {
		return !aInactive
	}
	return a.PrimaryEmail < b.PrimaryEmail
}

// enrichAdminInventory attaches per-admin role names (and, at internal, the
// org-unit-scoped flag) to the admin rows collected during scanUsers, and
// returns the custom-role inventory. It degrades gracefully: if the role-
// management scope is missing or the impersonation user lacks the role, the
// per-admin role list is omitted with a diagnostic and the admin emails / 2SV
// flags still ship.
func (c *Collector) enrichAdminInventory(ctx context.Context, scope scanScope, scan userScanResult) ([]Admin, []CustomRole) {
	rows := scan.adminRows

	roleByID := make(map[string]googleworkspace.Role)
	var customRoles []CustomRole
	err := c.client.ListRoles(ctx, scope.customerID, func(roles []googleworkspace.Role) error {
		for _, r := range roles {
			roleByID[r.ID] = r
			if !r.IsSystem {
				customRoles = append(customRoles, CustomRole{
					Name:           r.Name,
					Description:    r.Description,
					PrivilegeCount: r.PrivilegeCount,
				})
			}
		}
		return nil
	})
	if err != nil {
		c.warnSurfaceScan("admins", "admin.directory.rolemanagement.readonly", "User Management Admin (or Super Admin)", err)
		return rows, nil
	}

	assignmentsByUser := make(map[string][]googleworkspace.RoleAssignment)
	err = c.client.ListRoleAssignments(ctx, scope.customerID, func(assignments []googleworkspace.RoleAssignment) error {
		for _, a := range assignments {
			assignmentsByUser[a.AssignedTo] = append(assignmentsByUser[a.AssignedTo], a)
		}
		return nil
	})
	if err != nil {
		c.warnSurfaceScan("admins", "admin.directory.rolemanagement.readonly", "User Management Admin (or Super Admin)", err)
		return rows, customRoles
	}

	includeInternal := scope.level.AtLeast(componentsdk.LevelInternal)
	for i := range rows {
		userID := scan.adminIDs[i]
		seen := make(map[string]struct{})
		for _, a := range assignmentsByUser[userID] {
			if role, ok := roleByID[a.RoleID]; ok {
				if _, dup := seen[role.Name]; !dup {
					rows[i].Roles = append(rows[i].Roles, role.Name)
					seen[role.Name] = struct{}{}
				}
			}
			if includeInternal && a.ScopeType == "ORG_UNIT" {
				rows[i].OrgUnitScoped = true
			}
		}
		slices.Sort(rows[i].Roles)
	}

	slices.SortFunc(customRoles, func(a, b CustomRole) int {
		return strings.Compare(a.Name, b.Name)
	})
	return rows, customRoles
}

func (c *Collector) scanDeviceAccess(ctx context.Context, scope scanScope) (DeviceAccessMetrics, error) {
	var result deviceAccessScanResult

	startTime := scope.collectedAt.AddDate(0, 0, -DefaultContextAwareAccessLookbackDays)
	err := c.client.ListContextAwareAccessEvents(ctx, scope.customerID, startTime, func(events []googleworkspace.ContextAwareAccessEvent) error {
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

func (c *Collector) scanAccessContextManager(ctx context.Context, scope scanScope) (*AccessContextManagerMetrics, error) {
	policy, err := c.resolveAccessPolicy(ctx)
	if err != nil {
		return nil, err
	}

	summary := &AccessContextManagerMetrics{
		AccessPolicyName:   policy.Name,
		AccessPolicyParent: policy.Parent,
	}

	collectLevels := scope.level.AtLeast(componentsdk.LevelAudit)
	includeRuleDetails := scope.level.AtLeast(componentsdk.LevelInternal)

	err = c.client.ListAccessLevels(ctx, policy.Name, func(levels []googleworkspace.AccessLevel) error {
		for _, lvl := range levels {
			if collectLevels {
				summary.Levels = append(summary.Levels, buildAccessLevelSummary(lvl, includeRuleDetails))
			}

			if lvl.Custom {
				summary.CustomAccessLevelsCount++
				continue
			}

			summary.BasicAccessLevelsCount++
			if !lvl.HasDevicePolicy {
				continue
			}

			summary.BasicDevicePolicyAccessLevelsCount++
			summary.BasicDevicePolicyAccessLevelTitles = append(summary.BasicDevicePolicyAccessLevelTitles, accessLevelDisplayName(lvl))
			if levelExplicitlyRequiresManagedDevice(lvl) {
				summary.BasicManagedDeviceAccessLevelsCount++
			}
		}
		return nil
	})
	if err != nil {
		return nil, err
	}

	slices.Sort(summary.BasicDevicePolicyAccessLevelTitles)
	slices.SortFunc(summary.Levels, func(a, b AccessLevelSummary) int {
		return strings.Compare(a.Title, b.Title)
	})
	return summary, nil
}

// buildAccessLevelSummary maps an access level to a per-level row. At internal,
// includeRuleDetails adds the IP subnetworks, regions, required access levels,
// and device management / encryption status lists.
func buildAccessLevelSummary(lvl googleworkspace.AccessLevel, includeRuleDetails bool) AccessLevelSummary {
	row := AccessLevelSummary{
		Title:                 accessLevelDisplayName(lvl),
		Custom:                lvl.Custom,
		HasDevicePolicy:       lvl.HasDevicePolicy,
		RequiresScreenlock:    lvl.RequiresScreenlock,
		RequiresAdminApproval: lvl.RequiresAdminApproval,
		RequiresCorpOwned:     lvl.RequiresCorpOwned,
		OSConstraintCount:     lvl.OSConstraintCount,
	}
	if includeRuleDetails {
		row.AllowedDeviceManagementLevels = lvl.AllowedDeviceManagementLevels
		row.AllowedEncryptionStatuses = lvl.AllowedEncryptionStatuses
		row.IPSubnetworks = lvl.IPSubnetworks
		row.Regions = lvl.Regions
		row.RequiredAccessLevels = lvl.RequiredAccessLevels
	}
	return row
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
const maxReportRetries = 10

// fetchUsageReport tries progressively older report dates (yesterday minus 0..9
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
	for i := range maxReportRetries {
		date := reportDateFor(collectedAt, 1+i)
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

// reportDateFor returns the report date daysBack days before now, in Pacific
// Time. Google Workspace usage reports are keyed to Pacific Time days, so we
// convert to Pacific before subtracting to avoid requesting a report that
// hasn't fully closed yet. fetchUsageReport walks daysBack from 1 upward to
// absorb the report's 2-3 day publishing lag.
func reportDateFor(now time.Time, daysBack int) string {
	return now.In(pacificLocation).AddDate(0, 0, -daysBack).Format("2006-01-02")
}

// applyUsageReport maps the customer usage report into the posture metric
// blocks. Activity (7/30-day login percentages) is audit+ only; Apps
// (authorized app count) is internal only. The per-user inactivity percentage
// and live 2SV enforcement percentage are overwritten later from the Directory
// user scan.
func applyUsageReport(posture *OrgPosture, report googleworkspace.CustomerUsageReport, level componentsdk.Level) {
	posture.Users = UserMetrics{
		Total:        int(report.NumUsers),
		Suspended:    int(report.NumSuspendedUsers),
		Archived:     int(report.NumArchivedUsers),
		LockedPct:    percentFloat(int(report.NumLockedUsers), int(report.NumUsers)),
		InactiveDays: DefaultInactiveDays,
	}
	if level.AtLeast(componentsdk.LevelAudit) {
		posture.Activity = &ActivityMetrics{
			Active7dPct:  percentFloat(int(report.Num7DayLogins), int(report.NumUsers)),
			Active30dPct: percentFloat(int(report.Num30DayLogins), int(report.NumUsers)),
		}
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
	if level.AtLeast(componentsdk.LevelInternal) {
		posture.Apps = &AppMetrics{
			AuthorizedAppsCount: int(report.NumAuthorizedApps),
		}
	}
}

func percentFloat(part, total int) float64 {
	if total == 0 {
		return 0
	}
	pct := float64(part) / float64(total) * 100
	return math.Round(pct*100) / 100
}
