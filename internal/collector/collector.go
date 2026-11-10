package collector

import (
	"context"
	"errors"
	"fmt"
	"math"
	"slices"
	"strings"
	"time"
	_ "time/tzdata" // Embed timezone database for minimal container environments.

	"google.golang.org/api/googleapi"

	"github.com/locktivity/epack-collector-google-workspace/internal/googleworkspace"
	"github.com/locktivity/epack/componentsdk"
)

// Collector gathers Google Workspace posture metrics.
type Collector struct {
	client           googleworkspace.Client
	config           Config
	now              func() time.Time
	level            componentsdk.Level
	warnings         []string
	permissionErrors []string
	gaps             *gapLog
}

// New creates a collector backed by the Google Admin SDK. Every request goes
// out through config.HTTPClient's transport.
func New(ctx context.Context, config Config) (*Collector, error) {
	if config.AdminEmail == "" {
		return nil, fmt.Errorf("admin_email is required")
	}

	client, err := googleworkspace.NewClient(ctx, config.AdminEmail, config.authConfig(), config.HTTPClient.Transport)
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
		gaps:   newGapLog(config.Recorder),
	}
}

func (config Config) authConfig() googleworkspace.AuthConfig {
	return googleworkspace.AuthConfig{
		Mode:                     config.AuthMode,
		CredentialsJSON:          config.CredentialsJSON,
		WorkloadIdentityProvider: config.WorkloadIdentityProvider,
		ServiceAccount:           config.ServiceAccount,
	}
}

func (c *Collector) warn(format string, args ...interface{}) {
	c.warnings = append(c.warnings, fmt.Sprintf(format, args...))
}

func (c *Collector) permissionError(format string, args ...interface{}) {
	c.permissionErrors = append(c.permissionErrors, fmt.Sprintf(format, args...))
}

// audit reports whether the run writes the customer's own IDs, which it does
// from the audit level.
func (c *Collector) audit() bool { return c.level.AtLeast(componentsdk.LevelAudit) }

// named is how diagnostics text names one of the customer's own resources,
// such as the customer or a Cloud organization: by id from the audit level,
// and as name below it.
func (c *Collector) named(id, name string) string {
	if c.audit() {
		return id
	}
	return name
}

// errorText is how diagnostics text gives err: its message from the audit
// level, and its code below it. Google's messages and the URLs in them can
// name the customer, the Cloud organization, or an access policy.
func (c *Collector) errorText(err error) string {
	if c.audit() {
		return err.Error()
	}
	return string(componentsdk.Classify(err))
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
//
// Only a failed sign-in fails the collection. Every value a later call could
// not read is left out of the posture with a gap in config.Recorder.
func (c *Collector) Collect(ctx context.Context, level componentsdk.Level) (*OrgPosture, error) {
	customerKey := c.customerKey()
	c.level = level
	c.warnings = nil
	c.permissionErrors = nil
	c.gaps = newGapLog(c.config.Recorder)

	c.status("Signing in to Google Workspace...")
	if err := c.client.SignIn(ctx); err != nil {
		return nil, fmt.Errorf("signing in as %s: %w", c.config.AdminEmail, err)
	}

	collectedAt := c.now().UTC()
	posture := NewOrgPosture(collectedAt)
	posture.CollectedAtLevel = string(level)
	scope := scanScope{
		customerKey: customerKey,
		customerID:  customerKey,
		collectedAt: collectedAt,
		level:       level,
	}

	// Step 1: Resolve customer metadata. Only a Super Admin can read the
	// tenant record, so the run goes on without it: the customer key stands
	// in for the customer ID in the calls below, which all accept it.
	c.status(fmt.Sprintf("Resolving Google Workspace customer %s...", customerKey))
	c.resolveCustomer(ctx, posture, &scope)

	// Step 2: Fetch usage report from Reports API.
	// Google Workspace usage reports have a 2-3 day lag. We try progressively
	// older dates starting from yesterday (Pacific Time) until we find one
	// that has data, or exhaust our attempts.
	report, reportDate, reportErr := c.fetchUsageReport(ctx, scope.customerID, collectedAt)
	if reportErr != nil {
		c.warnSurfaceScan("usage_report", "admin.reports.usage.readonly", "a role with the Reports privilege (or Super Admin)", reportErr)
	}
	c.applyUsageReport(posture, report, reportDate, reportErr, level)

	// Step 3: List users for admin counts, 2SV coverage, and inactivity.
	c.status("Scanning users for admin status and inactivity...")
	userScan, scanErr := c.scanUsers(ctx, scope)
	if scanErr != nil {
		c.warnSurfaceScan("users", "admin.directory.user.readonly", "User Management Admin (or Super Admin)", scanErr)
	}
	c.applyUserScan(posture, report, reportErr, userScan, scanErr, level)

	if level.AtLeast(componentsdk.LevelAudit) {
		c.status("Scanning admin roles and assignments...")
		c.enrichAdminInventory(ctx, scope, posture, userScan, scanErr)
	}

	// Step 4: Query Context-Aware Access deny events for evidence that Google
	// evaluated device-state conditions for tenant access. These logs are
	// deny-only and can include monitor-mode hits, so they are a useful positive
	// signal but not a complete policy model.
	c.status("Scanning Context-Aware Access audit events for device-state deny evidence...")
	deviceAccess, err := c.scanDeviceAccess(ctx, scope)
	if err != nil {
		c.warnSurfaceScan("device_access", "admin.reports.audit.readonly", "a role with the Reports privilege (or Super Admin)", err)
		c.gaps.leaveOut(failed(err), "/device_access")
	} else {
		posture.DeviceAccess = &deviceAccess
		if deviceAccess.ManagedDeviceRequirementEvidenced {
			c.warn("device access posture is inferred from deny-only Context-Aware Access audit events; absence of events is not evidence of absence, and monitor-mode access levels may produce similar deny events")
		}
	}

	if posture.DeviceAccess != nil && c.hasAccessContextManagerConfig() {
		c.status("Scanning Access Context Manager access-level config...")
		acm, err := c.scanAccessContextManager(ctx, scope)
		switch {
		case err != nil:
			c.warn("access context manager scan failed; config enrichment omitted: %s", c.errorText(err))
			c.gaps.leaveOut(failed(err), "/device_access/access_context_manager")
		case acm != nil:
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
	posture.OrgUnits = c.scanOrgUnits(ctx, scope, userScan.usersByOU, scanErr)

	c.status("Scanning managed devices...")
	posture.Endpoint = c.scanEndpoint(ctx, scope)

	c.status("Scanning audit logs...")
	posture.DriveExternalSharing = c.scanDriveExternalSharing(ctx, scope)
	posture.AdminAuditLog = c.scanAdminAuditLog(ctx, scope)
	posture.LoginAuditLog = c.scanLoginAuditLog(ctx, scope)
	posture.OAuthTokens = c.scanOAuthTokens(ctx, scope)

	c.status("Scanning domain and SSO settings...")
	posture.DomainSettings = c.scanDomainSettings(ctx, scope)

	c.status("Scanning password policy...")
	posture.Passwords.Policy = c.scanPasswordPolicy(ctx, scope)

	c.status("Scanning session and sign-in settings...")
	posture.SignIn = c.scanSignInPolicy(ctx, scope)

	c.status("Scanning Vault...")
	posture.Vault = c.scanVault(ctx, scope)

	if reportErr == nil {
		c.warn("usage report metrics are as of %s; 2SV enrollment and enforcement, login activity, admin counts, and inactivity reflect current Directory state and may differ slightly", reportDate)
	}
	posture.Diagnostics = c.diagnostics()

	c.status("Collection complete")
	return posture, nil
}

// resolveCustomer reads the tenant record into posture. When it cannot be
// read, the customer ID, the primary domain, and what depends on the domain
// are left out, and scope keeps the customer key. The customer ID is written
// from the audit level, so below it the run records no gap for it.
func (c *Collector) resolveCustomer(ctx context.Context, posture *OrgPosture, scope *scanScope) {
	posture.CustomerID.Write = c.audit()
	customer, err := c.client.GetCustomer(ctx, scope.customerKey)
	if err != nil {
		c.warnSurfaceScan("customer", "admin.directory.customer.readonly", "Super Admin", err)
		if c.audit() {
			c.gaps.leaveOut(failed(err), "/customer_id")
		}
		c.gaps.leaveOut(failed(err), "/org_domain")
		return
	}
	customerName := c.named("customer "+scope.customerKey, "the customer")
	if customer.ID == "" {
		c.warn("%s did not return a customer ID", customerName)
		if c.audit() {
			c.gaps.leaveOut(failed(invalidResponse("customer %s did not return a customer ID", scope.customerKey)), "/customer_id")
		}
	} else {
		scope.customerID = customer.ID
		if c.audit() {
			posture.CustomerID.Value = &customer.ID
		}
	}
	if customer.PrimaryDomain == "" {
		c.warn("%s did not return a primary domain", customerName)
		c.gaps.leaveOut(failed(invalidResponse("customer %s did not return a primary domain", scope.customerKey)), "/org_domain")
	} else {
		posture.OrgDomain = &customer.PrimaryDomain
		scope.primaryDomain = customer.PrimaryDomain
	}
}

func invalidResponse(format string, args ...any) error {
	return componentsdk.CodeError(componentsdk.CodeInvalidResponse, fmt.Errorf(format, args...))
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
	superAdmins           int
	delegatedAdmins       int
	privilegedTotal       int
	privileged2SVEnrolled int
	privileged2SVEnforced int
	activeCount           int
	inactiveCount         int
	enrolled2SVCount      int
	enforced2SVCount      int
	active7dCount         int
	active30dCount        int
	inventory             []User
	inventoryTruncated    bool
	inventoryDropped      int
	adminRows             []Admin        // per-privileged-user rows (audit+), aligned with adminIDs
	adminIDs              []string       // directory user IDs, for role-assignment correlation
	usersByOU             map[string]int // user count per org-unit path, for the OrgUnits surface
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
		enrolled2SVCount      int
		enforced2SVCount      int
		active7dCount         int
		active30dCount        int
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
			if user.IsEnrolledIn2Sv {
				enrolled2SVCount++
			}
			if user.IsEnforcedIn2Sv {
				enforced2SVCount++
			}

			// Inactivity: never logged in or last login before threshold.
			if user.LastLoginMissing || user.LastLoginTime.Before(inactiveThreshold) {
				inactiveCount++
			}

			if !user.LastLoginMissing {
				if !user.LastLoginTime.Before(active7dThreshold) {
					active7dCount++
				}
				if !user.LastLoginTime.Before(active30dThreshold) {
					active30dCount++
				}
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
		inventory, inventoryDropped, inventoryTruncated = truncateAndWarn(c, inventory, UsersCap, "user inventory", "/users/inventory", lessUserRow)
	}

	return userScanResult{
		superAdmins:           superAdmins,
		delegatedAdmins:       delegatedAdmins,
		privilegedTotal:       privilegedTotal,
		privileged2SVEnrolled: privileged2SVEnrolled,
		privileged2SVEnforced: privileged2SVEnforced,
		activeCount:           activeCount,
		inactiveCount:         inactiveCount,
		enrolled2SVCount:      enrolled2SVCount,
		enforced2SVCount:      enforced2SVCount,
		active7dCount:         active7dCount,
		active30dCount:        active30dCount,
		inventory:             inventory,
		inventoryTruncated:    inventoryTruncated,
		inventoryDropped:      inventoryDropped,
		adminRows:             adminRows,
		adminIDs:              adminIDs,
		usersByOU:             usersByOU,
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

// applyUserScan fills in the values the live Directory user scan gives, and
// warns where the lagged usage report disagrees. When the scan failed they are
// left out.
func (c *Collector) applyUserScan(posture *OrgPosture, report googleworkspace.CustomerUsageReport, reportErr error, scan userScanResult, scanErr error, level componentsdk.Level) {
	audit := level.AtLeast(componentsdk.LevelAudit)
	if audit {
		posture.Activity = &ActivityMetrics{}
	}
	if scanErr != nil {
		pointers := []string{
			"/users/active", "/users/inactive_pct",
			"/authentication/2sv_enrolled_pct", "/authentication/2sv_enforced_pct",
			"/admins/privileged_users_count", "/admins/super_admin_count", "/admins/delegated_admin_count",
			"/admins/privileged_users_2sv_enrolled_pct", "/admins/privileged_users_2sv_enforced_pct",
		}
		if audit {
			pointers = append(pointers, "/activity/active_7d_pct", "/activity/active_30d_pct", "/users/inventory", "/admins/inventory")
		}
		c.gaps.leaveOut(failed(scanErr), pointers...)
		return
	}

	posture.Users.Active = intPtr(scan.activeCount)
	posture.Users.InactivePct = percentFloat(scan.inactiveCount, scan.activeCount)
	posture.Users.Inventory = scan.inventory
	posture.Users.TruncatedInventory = scan.inventoryTruncated
	posture.Users.TruncatedInventoryDropped = scan.inventoryDropped

	posture.Admins.PrivilegedUsersCount = intPtr(scan.privilegedTotal)
	posture.Admins.SuperAdminCount = intPtr(scan.superAdmins)
	posture.Admins.DelegatedAdminCount = intPtr(scan.delegatedAdmins)
	posture.Admins.PrivilegedUsers2SVEnrolledPct = percentFloat(scan.privileged2SVEnrolled, scan.privilegedTotal)
	posture.Admins.PrivilegedUsers2SVEnforcedPct = percentFloat(scan.privileged2SVEnforced, scan.privilegedTotal)
	if audit {
		posture.Admins.Inventory = scan.adminRows
	}
	posture.counts.inactiveUsers = intPtr(scan.inactiveCount)
	posture.counts.enrolled2SVUsers = intPtr(scan.enrolled2SVCount)
	posture.counts.enforced2SVUsers = intPtr(scan.enforced2SVCount)
	posture.counts.privileged2SVEnrolled = intPtr(scan.privileged2SVEnrolled)

	lagged := func(param string) *float64 {
		if reportErr != nil {
			return nil
		}
		return reportShare(report, param)
	}
	posture.Authentication.TwoSVEnrolledPct = c.reconcileWithLive("2SV enrollment coverage", lagged("accounts:num_users_2sv_enrolled"), scan.enrolled2SVCount, scan.activeCount)
	posture.Authentication.TwoSVEnforcedPct = c.reconcileWithLive("2SV enforcement coverage", lagged("accounts:num_users_2sv_enforced"), scan.enforced2SVCount, scan.activeCount)
	if audit {
		posture.Activity.Active7dPct = c.reconcileWithLive("7-day login activity", lagged("accounts:num_7day_logins"), scan.active7dCount, scan.activeCount)
		posture.Activity.Active30dPct = c.reconcileWithLive("30-day login activity", lagged("accounts:num_30day_logins"), scan.active30dCount, scan.activeCount)
	}
}

// enrichAdminInventory lists the custom-role inventory and attaches per-admin
// role names (and, at internal, the org-unit-scoped flag) to the admin rows
// collected during scanUsers. It degrades gracefully: if the role-management
// scope is missing or the impersonation user lacks the role, the role names
// are left out with a gap and the admin emails / 2SV flags still ship.
func (c *Collector) enrichAdminInventory(ctx context.Context, scope scanScope, posture *OrgPosture, scan userScanResult, scanErr error) {
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
		c.warnSurfaceScan("admins", "admin.directory.rolemanagement.readonly", "Super Admin", err)
		c.gaps.leaveOut(failed(err), "/admins/custom_roles")
		c.leaveOutAdminRoles(posture, scope, failed(err))
		return
	}
	slices.SortFunc(customRoles, func(a, b CustomRole) int {
		return strings.Compare(a.Name, b.Name)
	})
	posture.Admins.CustomRoles = customRoles
	if scanErr != nil {
		return
	}

	assignmentsByUser := make(map[string][]googleworkspace.RoleAssignment)
	err = c.client.ListRoleAssignments(ctx, scope.customerID, func(assignments []googleworkspace.RoleAssignment) error {
		for _, a := range assignments {
			assignmentsByUser[a.AssignedTo] = append(assignmentsByUser[a.AssignedTo], a)
		}
		return nil
	})
	if err != nil {
		c.warnSurfaceScan("admins", "admin.directory.rolemanagement.readonly", "Super Admin", err)
		c.leaveOutAdminRoles(posture, scope, failed(err))
		return
	}

	rows := posture.Admins.Inventory
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
}

// leaveOutAdminRoles records why each admin row has no role names.
func (c *Collector) leaveOutAdminRoles(posture *OrgPosture, scope scanScope, why *missing) {
	for i := range posture.Admins.Inventory {
		c.gaps.leaveOut(why, itemPointer("/admins/inventory", i, "roles"))
		if scope.level.AtLeast(componentsdk.LevelInternal) {
			c.gaps.leaveOut(why, itemPointer("/admins/inventory", i, "org_unit_scoped"))
		}
	}
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

// scanAccessContextManager summarizes the access levels of the configured
// policy. It returns nil, with a warning, when the organization has no policy.
func (c *Collector) scanAccessContextManager(ctx context.Context, scope scanScope) (*AccessContextManagerMetrics, error) {
	policy, found, err := c.resolveAccessPolicy(ctx)
	if err != nil || !found {
		return nil, err
	}

	collectLevels := scope.level.AtLeast(componentsdk.LevelAudit)
	includeRuleDetails := scope.level.AtLeast(componentsdk.LevelInternal)

	summary := &AccessContextManagerMetrics{}
	if collectLevels {
		summary.AccessPolicyName = policy.Name
		summary.AccessPolicyParent = policy.Parent
	}

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
			summary.BasicDevicePolicyAccessLevelTitles = append(summary.BasicDevicePolicyAccessLevelTitles, accessLevelDisplayName(lvl, collectLevels))
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
		Title:                 accessLevelDisplayName(lvl, true),
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

func (c *Collector) resolveAccessPolicy(ctx context.Context) (googleworkspace.AccessPolicy, bool, error) {
	if policy := normalizeAccessPolicyName(c.config.AccessPolicy); policy != "" {
		return googleworkspace.AccessPolicy{
			Name:   policy,
			Parent: normalizeOrganizationParent(c.config.OrganizationID),
		}, true, nil
	}

	parent := normalizeOrganizationParent(c.config.OrganizationID)
	var policies []googleworkspace.AccessPolicy
	err := c.client.ListAccessPolicies(ctx, parent, func(batch []googleworkspace.AccessPolicy) error {
		policies = append(policies, batch...)
		return nil
	})
	if err != nil {
		return googleworkspace.AccessPolicy{}, false, err
	}
	organization := c.named(parent, "the configured organization")
	if len(policies) == 0 {
		c.warn("no access context manager policy found for %s; config enrichment omitted", organization)
		return googleworkspace.AccessPolicy{}, false, nil
	}

	slices.SortFunc(policies, func(a, b googleworkspace.AccessPolicy) int {
		return strings.Compare(a.Name, b.Name)
	})
	if len(policies) > 1 {
		c.warn("multiple access context manager policies found for %s; using %s", organization, c.named(policies[0].Name, "the first by name"))
	}

	return policies[0], true, nil
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

// accessLevelDisplayName is the level's title. A level with none goes by its
// resource name from the audit level, and below it by the name's last
// segment, since the resource name holds the access policy's number.
func accessLevelDisplayName(level googleworkspace.AccessLevel, audit bool) string {
	if strings.TrimSpace(level.Title) != "" {
		return level.Title
	}
	if audit {
		return level.Name
	}
	return level.Name[strings.LastIndex(level.Name, "/")+1:]
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
//   - HTTP 200 with a "data is not available" warning
//
// Both are treated as retryable. A "partial data is available" warning is
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
			if isPartialDataWarning(w) {
				c.warn("usage report for %s returned a partial-data warning: %s", date, w.Message)
			}
		}

		if i > 0 {
			c.warn("usage report for the most recent date was not available; fell back to %s", date)
		}
		return report, date, nil
	}

	return googleworkspace.CustomerUsageReport{}, "", componentsdk.CodeError(componentsdk.CodeVendorError, fmt.Errorf("no usage report available for the last %d days", maxReportRetries))
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
// that the report has no data for the requested date.
//
// The Reports API reference gives two messages, for the no-data warning and
// then the partial-data warning.
//   - Sorry, data for date yyyy-mm-dd for application "name" is not available.
//   - Data for date yyyy-mm-dd for application "name" is not available right
//     now, please try again after a few hours.
//
// Messages that start with the warnings' names, "Data is not available" and
// "Partial data", are matched too.
func hasDataNotAvailableWarning(warnings []googleworkspace.ReportWarning) bool {
	for _, w := range warnings {
		if isPartialDataWarning(w) {
			continue
		}
		if strings.Contains(w.Message, "Sorry, data for date") || strings.Contains(w.Message, "Data is not available") {
			return true
		}
	}
	return false
}

// isPartialDataWarning checks whether a warning says the report's data for
// the date is partial. hasDataNotAvailableWarning lists the messages.
func isPartialDataWarning(w googleworkspace.ReportWarning) bool {
	return strings.Contains(w.Message, "not available right now") || strings.Contains(w.Message, "Partial data")
}

// pacificLocation is the timezone Google uses for usage report day boundaries.
// This package imports time/tzdata so the load succeeds in minimal container
// environments without system tzdata.
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

// reportPointers lists the values the usage report gives at level.
func reportPointers(level componentsdk.Level) []string {
	pointers := []string{
		"/usage_report_date",
		"/users/total", "/users/suspended", "/users/archived", "/users/locked_pct",
		"/authentication/2sv_protected_pct", "/authentication/passkey_users_pct", "/authentication/security_keys_total",
		"/passwords/weak_password_pct", "/passwords/password_length_non_compliant_pct",
	}
	if level.AtLeast(componentsdk.LevelInternal) {
		pointers = append(pointers, "/apps/authorized_apps_count")
	}
	return pointers
}

// applyUsageReport maps the customer usage report into the posture metric
// blocks. Apps (authorized app count) is internal only. The report lags the
// live Directory by days, so the user scan, not the report, gives the 2SV
// enrollment and enforcement, activity, and inactivity percentages. A value
// the report could not give is left out.
func (c *Collector) applyUsageReport(posture *OrgPosture, report googleworkspace.CustomerUsageReport, date string, reportErr error, level componentsdk.Level) {
	if level.AtLeast(componentsdk.LevelInternal) {
		posture.Apps = &AppMetrics{}
	}
	if reportErr != nil {
		c.gaps.leaveOut(failed(reportErr), reportPointers(level)...)
		return
	}
	posture.UsageReportDate = &date

	value := func(pointer, param string, v int64) *int {
		if slices.Contains(report.Missing, param) {
			c.gaps.leaveOut(failed(invalidResponse("the usage report for %s has no %s", date, param)), pointer)
			return nil
		}
		return intPtr(int(v))
	}
	share := func(pointer, param string) *float64 {
		for _, p := range []string{param, "accounts:num_users"} {
			if slices.Contains(report.Missing, p) {
				c.gaps.leaveOut(failed(invalidResponse("the usage report for %s has no %s", date, p)), pointer)
				return nil
			}
		}
		return reportShare(report, param)
	}

	posture.Users.Total = value("/users/total", "accounts:num_users", report.NumUsers)
	posture.Users.Suspended = value("/users/suspended", "accounts:num_suspended_users", report.NumSuspendedUsers)
	posture.Users.Archived = value("/users/archived", "accounts:num_archived_users", report.NumArchivedUsers)
	posture.Users.LockedPct = share("/users/locked_pct", "accounts:num_locked_users")
	posture.Authentication.TwoSVProtectedPct = share("/authentication/2sv_protected_pct", "accounts:num_users_2sv_protected")
	posture.Authentication.PasskeyUsersPct = share("/authentication/passkey_users_pct", "accounts:num_users_with_passkeys_enrolled")
	posture.Authentication.SecurityKeysTotal = value("/authentication/security_keys_total", "accounts:num_security_keys", report.NumSecurityKeys)
	posture.Passwords.WeakPasswordPct = share("/passwords/weak_password_pct", "accounts:num_users_password_strength_weak")
	posture.Passwords.PasswordLengthNonCompliantPct = share("/passwords/password_length_non_compliant_pct", "accounts:num_users_password_length_non_compliant")
	if posture.Apps != nil {
		posture.Apps.AuthorizedAppsCount = value("/apps/authorized_apps_count", "accounts:num_authorized_apps", report.NumAuthorizedApps)
	}

	// count is the report's count of users with param, under the same
	// conditions share gives their percentage.
	count := func(param string, v int64) *int {
		if slices.Contains(report.Missing, param) || slices.Contains(report.Missing, "accounts:num_users") {
			return nil
		}
		return intPtr(int(v))
	}
	posture.counts.passkeyUsers = count("accounts:num_users_with_passkeys_enrolled", report.NumUsersWithPasskeysEnrolled)
	posture.counts.lockedUsers = count("accounts:num_locked_users", report.NumLockedUsers)
	posture.counts.weakPasswordUsers = count("accounts:num_users_password_strength_weak", report.NumUsersPasswordStrengthWeak)
	posture.counts.shortPasswordUsers = count("accounts:num_users_password_length_non_compliant", report.NumUsersPasswordLengthNonCompliant)

	if posture.Users.Total != nil && *posture.Users.Total == 0 {
		c.warn("usage report for %s returned no user data; tenant may be too new for report generation", date)
	}
}

// reportShare is the report's percentage of users with param, or nil when the
// report left it out or counts no users.
func reportShare(report googleworkspace.CustomerUsageReport, param string) *float64 {
	if slices.Contains(report.Missing, param) || slices.Contains(report.Missing, "accounts:num_users") {
		return nil
	}
	counts := map[string]int64{
		"accounts:num_locked_users":                        report.NumLockedUsers,
		"accounts:num_7day_logins":                         report.Num7DayLogins,
		"accounts:num_30day_logins":                        report.Num30DayLogins,
		"accounts:num_users_2sv_enrolled":                  report.NumUsers2SVEnrolled,
		"accounts:num_users_2sv_enforced":                  report.NumUsers2SVEnforced,
		"accounts:num_users_2sv_protected":                 report.NumUsers2SVProtected,
		"accounts:num_users_with_passkeys_enrolled":        report.NumUsersWithPasskeysEnrolled,
		"accounts:num_users_password_strength_weak":        report.NumUsersPasswordStrengthWeak,
		"accounts:num_users_password_length_non_compliant": report.NumUsersPasswordLengthNonCompliant,
	}
	return percentFloat(int(counts[param]), int(report.NumUsers))
}

// reconcileWithLive returns the percentage computed from the live Directory
// scan, warning when the lagged usage report's differs by a percentage point
// or more.
func (c *Collector) reconcileWithLive(metric string, reportPct *float64, liveCount, liveTotal int) *float64 {
	livePct := percentFloat(liveCount, liveTotal)
	if reportPct != nil && livePct != nil && math.Abs(*reportPct-*livePct) >= 1 {
		c.warn("%s differs between the lagged usage report (%.2f%%) and live Directory data (%.2f%%); using the live Directory value", metric, *reportPct, *livePct)
	}
	return livePct
}

// percentFloat is part of total as a percentage rounded to two places, or
// nil over no population.
func percentFloat(part, total int) *float64 {
	if total == 0 {
		return nil
	}
	pct := float64(part) / float64(total) * 100
	rounded := math.Round(pct*100) / 100
	return &rounded
}

func intPtr(v int) *int { return &v }
