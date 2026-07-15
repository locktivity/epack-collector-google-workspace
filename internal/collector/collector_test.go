package collector

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"google.golang.org/api/googleapi"

	"github.com/locktivity/epack-collector-google-workspace/internal/googleworkspace"
	"github.com/locktivity/epack/componentsdk"
)

type mockClient struct {
	customer    googleworkspace.Customer
	customerErr error

	usageReport    googleworkspace.CustomerUsageReport
	usageReportErr error

	// usageReportByDate overrides usageReport/usageReportErr when set.
	// Keys are date strings ("2026-04-07"). Return error to simulate failures.
	usageReportByDate map[string]mockReportResult

	users    []googleworkspace.User
	usersErr error

	roles              []googleworkspace.Role
	rolesErr           error
	roleAssignments    []googleworkspace.RoleAssignment
	roleAssignmentsErr error

	groups            []googleworkspace.Group
	groupsErr         error
	groupSettings     map[string]googleworkspace.GroupSettings
	groupSettingsErr  error
	groupMembers      map[string][]googleworkspace.GroupMember
	groupMembersErr   error
	lastGroupSettings []string

	orgUnits    []googleworkspace.OrgUnit
	orgUnitsErr error

	mobileDevices    []googleworkspace.Device
	mobileDevicesErr error
	chromeDevices    []googleworkspace.Device
	chromeDevicesErr error

	activitiesByApp map[string][]googleworkspace.AuditEvent
	activitiesErr   error

	samlProfiles    []googleworkspace.SAMLProfile
	samlProfilesErr error
	domains         []googleworkspace.Domain
	domainsErr      error

	vaultMatters    []googleworkspace.VaultMatter
	vaultMattersErr error
	vaultHolds      map[string][]googleworkspace.VaultHold
	vaultHoldsErr   error

	contextAwareAccessEvents []googleworkspace.ContextAwareAccessEvent
	contextAwareAccessErr    error

	accessPolicies    []googleworkspace.AccessPolicy
	accessPoliciesErr error
	accessLevels      []googleworkspace.AccessLevel
	accessLevelsErr   error

	lastCustomerKey        string
	lastCustomerID         string
	lastReportDate         string
	lastAccessPolicyParent string
	lastAccessLevelsPolicy string
}

type mockReportResult struct {
	report googleworkspace.CustomerUsageReport
	err    error
}

func (m *mockClient) GetCustomer(ctx context.Context, customerKey string) (googleworkspace.Customer, error) {
	m.lastCustomerKey = customerKey
	if m.customerErr != nil {
		return googleworkspace.Customer{}, m.customerErr
	}
	return m.customer, nil
}

func (m *mockClient) GetCustomerUsageReport(ctx context.Context, customerID, date string) (googleworkspace.CustomerUsageReport, error) {
	m.lastCustomerID = customerID
	m.lastReportDate = date
	if m.usageReportByDate != nil {
		if result, ok := m.usageReportByDate[date]; ok {
			return result.report, result.err
		}
		return googleworkspace.CustomerUsageReport{}, m.usageReportErr
	}
	if m.usageReportErr != nil {
		return googleworkspace.CustomerUsageReport{}, m.usageReportErr
	}
	return m.usageReport, nil
}

func (m *mockClient) ListUsers(ctx context.Context, customerKey string, callback func([]googleworkspace.User) error) error {
	if m.usersErr != nil {
		return m.usersErr
	}
	return callback(m.users)
}

func (m *mockClient) ListRoles(ctx context.Context, customerID string, callback func([]googleworkspace.Role) error) error {
	if m.rolesErr != nil {
		return m.rolesErr
	}
	if len(m.roles) == 0 {
		return nil
	}
	return callback(m.roles)
}

func (m *mockClient) ListRoleAssignments(ctx context.Context, customerID string, callback func([]googleworkspace.RoleAssignment) error) error {
	if m.roleAssignmentsErr != nil {
		return m.roleAssignmentsErr
	}
	if len(m.roleAssignments) == 0 {
		return nil
	}
	return callback(m.roleAssignments)
}

func (m *mockClient) ListOrgUnits(ctx context.Context, customerID string) ([]googleworkspace.OrgUnit, error) {
	if m.orgUnitsErr != nil {
		return nil, m.orgUnitsErr
	}
	return m.orgUnits, nil
}

func (m *mockClient) ListMobileDevices(ctx context.Context, customerID string, callback func([]googleworkspace.Device) error) error {
	if m.mobileDevicesErr != nil {
		return m.mobileDevicesErr
	}
	if len(m.mobileDevices) == 0 {
		return nil
	}
	return callback(m.mobileDevices)
}

func (m *mockClient) ListChromeOSDevices(ctx context.Context, customerID string, callback func([]googleworkspace.Device) error) error {
	if m.chromeDevicesErr != nil {
		return m.chromeDevicesErr
	}
	if len(m.chromeDevices) == 0 {
		return nil
	}
	return callback(m.chromeDevices)
}

func (m *mockClient) ListVaultMatters(ctx context.Context, callback func([]googleworkspace.VaultMatter) error) error {
	if m.vaultMattersErr != nil {
		return m.vaultMattersErr
	}
	if len(m.vaultMatters) == 0 {
		return nil
	}
	return callback(m.vaultMatters)
}

func (m *mockClient) ListVaultHolds(ctx context.Context, matterID string, callback func([]googleworkspace.VaultHold) error) error {
	if m.vaultHoldsErr != nil {
		return m.vaultHoldsErr
	}
	holds := m.vaultHolds[matterID]
	if len(holds) == 0 {
		return nil
	}
	return callback(holds)
}

func (m *mockClient) ListSAMLProfiles(ctx context.Context, callback func([]googleworkspace.SAMLProfile) error) error {
	if m.samlProfilesErr != nil {
		return m.samlProfilesErr
	}
	if len(m.samlProfiles) == 0 {
		return nil
	}
	return callback(m.samlProfiles)
}

func (m *mockClient) ListDomains(ctx context.Context, customerID string) ([]googleworkspace.Domain, error) {
	if m.domainsErr != nil {
		return nil, m.domainsErr
	}
	return m.domains, nil
}

func (m *mockClient) ListActivities(ctx context.Context, customerID, application string, eventNames []string, startTime time.Time, callback func([]googleworkspace.AuditEvent) error) error {
	if m.activitiesErr != nil {
		return m.activitiesErr
	}
	all := m.activitiesByApp[application]
	var filtered []googleworkspace.AuditEvent
	if len(eventNames) == 0 {
		filtered = all
	} else {
		want := map[string]bool{}
		for _, n := range eventNames {
			want[n] = true
		}
		for _, e := range all {
			if want[e.Name] {
				filtered = append(filtered, e)
			}
		}
	}
	if len(filtered) == 0 {
		return nil
	}
	return callback(filtered)
}

func (m *mockClient) ListGroups(ctx context.Context, customerID string, callback func([]googleworkspace.Group) error) error {
	if m.groupsErr != nil {
		return m.groupsErr
	}
	if len(m.groups) == 0 {
		return nil
	}
	return callback(m.groups)
}

func (m *mockClient) GetGroupSettings(ctx context.Context, groupEmail string) (googleworkspace.GroupSettings, error) {
	m.lastGroupSettings = append(m.lastGroupSettings, groupEmail)
	if m.groupSettingsErr != nil {
		return googleworkspace.GroupSettings{}, m.groupSettingsErr
	}
	return m.groupSettings[groupEmail], nil
}

func (m *mockClient) ListGroupMembers(ctx context.Context, groupEmail string, callback func([]googleworkspace.GroupMember) error) error {
	if m.groupMembersErr != nil {
		return m.groupMembersErr
	}
	members := m.groupMembers[groupEmail]
	if len(members) == 0 {
		return nil
	}
	return callback(members)
}

func (m *mockClient) ListContextAwareAccessEvents(ctx context.Context, customerID string, startTime time.Time, callback func([]googleworkspace.ContextAwareAccessEvent) error) error {
	if m.contextAwareAccessErr != nil {
		return m.contextAwareAccessErr
	}
	if len(m.contextAwareAccessEvents) == 0 {
		return nil
	}
	return callback(m.contextAwareAccessEvents)
}

func (m *mockClient) ListAccessPolicies(ctx context.Context, parent string, callback func([]googleworkspace.AccessPolicy) error) error {
	m.lastAccessPolicyParent = parent
	if m.accessPoliciesErr != nil {
		return m.accessPoliciesErr
	}
	if len(m.accessPolicies) == 0 {
		return nil
	}
	return callback(m.accessPolicies)
}

func (m *mockClient) ListAccessLevels(ctx context.Context, policyName string, callback func([]googleworkspace.AccessLevel) error) error {
	m.lastAccessLevelsPolicy = policyName
	if m.accessLevelsErr != nil {
		return m.accessLevelsErr
	}
	if len(m.accessLevels) == 0 {
		return nil
	}
	return callback(m.accessLevels)
}

func TestCollect_ComputesPostureFromReportsAndDirectory(t *testing.T) {
	now := time.Date(2026, 4, 8, 12, 0, 0, 0, time.UTC)

	client := &mockClient{
		customer: googleworkspace.Customer{
			ID:            "C123",
			PrimaryDomain: "example.com",
		},
		usageReport: googleworkspace.CustomerUsageReport{
			Date:                               "2026-04-07",
			NumUsers:                           100,
			NumSuspendedUsers:                  5,
			NumArchivedUsers:                   3,
			Num7DayLogins:                      80,
			Num30DayLogins:                     90,
			NumUsers2SVEnrolled:                75,
			NumUsers2SVEnforced:                60,
			NumUsers2SVProtected:               70,
			NumUsersWithPasskeysEnrolled:       10,
			NumSecurityKeys:                    25,
			NumUsersPasswordStrengthWeak:       8,
			NumUsersPasswordLengthNonCompliant: 4,
			NumAuthorizedApps:                  42,
			NumLockedUsers:                     2,
		},
		users: []googleworkspace.User{
			{PrimaryEmail: "admin1@example.com", IsAdmin: true, IsEnrolledIn2Sv: true, IsEnforcedIn2Sv: true, LastLoginTime: now},
			{PrimaryEmail: "admin2@example.com", IsAdmin: true, IsEnrolledIn2Sv: false, IsEnforcedIn2Sv: false, LastLoginTime: now},
			{PrimaryEmail: "deleg@example.com", IsDelegatedAdmin: true, IsEnrolledIn2Sv: true, IsEnforcedIn2Sv: true, LastLoginTime: now},
			{PrimaryEmail: "both@example.com", IsAdmin: true, IsDelegatedAdmin: true, IsEnrolledIn2Sv: true, IsEnforcedIn2Sv: true, LastLoginTime: now},
			{PrimaryEmail: "suspended-admin@example.com", IsAdmin: true, Suspended: true},
			{PrimaryEmail: "archived-admin@example.com", IsDelegatedAdmin: true, Archived: true},
			{PrimaryEmail: "active-user@example.com", LastLoginTime: now},
			{PrimaryEmail: "inactive-user@example.com", LastLoginTime: now.AddDate(0, 0, -120)},
			{PrimaryEmail: "never-logged-in@example.com", LastLoginMissing: true},
		},
		contextAwareAccessEvents: []googleworkspace.ContextAwareAccessEvent{
			{UserEmail: "admin1@example.com", Application: "Gmail", DeviceState: "Unmanaged"},
			{UserEmail: "active-user@example.com", Application: "Drive"},
		},
	}

	c := NewWithClient(Config{
		AdminEmail: "admin@example.com",
		Now:        func() time.Time { return now },
	}, client)

	posture, err := c.Collect(context.Background(), componentsdk.LevelTrust)
	if err != nil {
		t.Fatalf("Collect() error = %v", err)
	}

	// Verify resolved customer ID was used for reports.
	if client.lastCustomerID != "C123" {
		t.Fatalf("reports customerID = %q, want C123", client.lastCustomerID)
	}
	if client.lastReportDate != "2026-04-07" {
		t.Fatalf("report date = %q, want 2026-04-07", client.lastReportDate)
	}

	// Top-level fields.
	if posture.OrgDomain != "example.com" {
		t.Fatalf("OrgDomain = %q, want example.com", posture.OrgDomain)
	}
	if posture.CustomerID != "C123" {
		t.Fatalf("CustomerID = %q, want C123", posture.CustomerID)
	}
	if posture.UsageReportDate != "2026-04-07" {
		t.Fatalf("UsageReportDate = %q, want 2026-04-07", posture.UsageReportDate)
	}
	if posture.CollectedAt != now.Format(time.RFC3339) {
		t.Fatalf("CollectedAt = %q, want %q", posture.CollectedAt, now.Format(time.RFC3339))
	}

	// Users (from Reports API).
	if posture.Users.Total != 100 {
		t.Fatalf("Users.Total = %d, want 100", posture.Users.Total)
	}
	if posture.Users.Suspended != 5 {
		t.Fatalf("Users.Suspended = %d, want 5", posture.Users.Suspended)
	}
	if posture.Users.Archived != 3 {
		t.Fatalf("Users.Archived = %d, want 3", posture.Users.Archived)
	}

	// Activity must not appear at trust (audit+ only).
	if posture.Activity != nil {
		t.Fatalf("Activity must be nil at trust, got %+v", posture.Activity)
	}

	// Authentication.
	if posture.Authentication.TwoSVEnrolledPct != 75.0 {
		t.Fatalf("Authentication.TwoSVEnrolledPct = %.2f, want 75.00", posture.Authentication.TwoSVEnrolledPct)
	}
	if posture.Authentication.TwoSVEnforcedPct != 42.86 {
		t.Fatalf("Authentication.TwoSVEnforcedPct = %.2f, want 42.86 from live Directory enforcement", posture.Authentication.TwoSVEnforcedPct)
	}
	if posture.Authentication.TwoSVProtectedPct != 70.0 {
		t.Fatalf("Authentication.TwoSVProtectedPct = %.2f, want 70.00", posture.Authentication.TwoSVProtectedPct)
	}
	if posture.Authentication.PasskeyUsersPct != 10.0 {
		t.Fatalf("Authentication.PasskeyUsersPct = %.2f, want 10.00", posture.Authentication.PasskeyUsersPct)
	}
	if posture.Authentication.SecurityKeysTotal != 25 {
		t.Fatalf("Authentication.SecurityKeysTotal = %d, want 25", posture.Authentication.SecurityKeysTotal)
	}

	// Passwords.
	if posture.Passwords.WeakPasswordPct != 8.0 {
		t.Fatalf("Passwords.WeakPasswordPct = %.2f, want 8.00", posture.Passwords.WeakPasswordPct)
	}
	if posture.Passwords.PasswordLengthNonCompliantPct != 4.0 {
		t.Fatalf("Passwords.PasswordLengthNonCompliantPct = %.2f, want 4.00", posture.Passwords.PasswordLengthNonCompliantPct)
	}

	// Apps must not appear at trust (internal only).
	if posture.Apps != nil {
		t.Fatalf("Apps must be nil at trust, got %+v", posture.Apps)
	}

	// Admins (from Directory API, active only).
	// super admins: admin1, admin2, both (suspended-admin excluded)
	if posture.Admins.SuperAdminCount != 3 {
		t.Fatalf("Admins.SuperAdminCount = %d, want 3", posture.Admins.SuperAdminCount)
	}
	// delegated admins: deleg, both (archived-admin excluded)
	if posture.Admins.DelegatedAdminCount != 2 {
		t.Fatalf("Admins.DelegatedAdminCount = %d, want 2", posture.Admins.DelegatedAdminCount)
	}
	// privileged total: admin1, admin2, deleg, both = 4
	// privileged with 2SV enforced: admin1, deleg, both = 3
	// 3/4 = 75.0
	if posture.Admins.PrivilegedUsersCount != 4 {
		t.Fatalf("Admins.PrivilegedUsersCount = %d, want 4", posture.Admins.PrivilegedUsersCount)
	}
	if posture.Admins.PrivilegedUsers2SVEnrolledPct != 75.0 {
		t.Fatalf("Admins.PrivilegedUsers2SVEnrolledPct = %.2f, want 75.00", posture.Admins.PrivilegedUsers2SVEnrolledPct)
	}
	if posture.Admins.PrivilegedUsers2SVEnforcedPct != 75.0 {
		t.Fatalf("Admins.PrivilegedUsers2SVEnforcedPct = %.2f, want 75.00", posture.Admins.PrivilegedUsers2SVEnforcedPct)
	}

	// Locked (from Reports API): 2/100 = 2.0%
	if posture.Users.LockedPct != 2.0 {
		t.Fatalf("Users.LockedPct = %.2f, want 2.00", posture.Users.LockedPct)
	}

	// Inactive (from Directory API): 7 active users, 2 inactive (inactive-user + never-logged-in)
	// 2/7 = 28.57%
	if posture.Users.InactivePct != 28.57 {
		t.Fatalf("Users.InactivePct = %.2f, want 28.57", posture.Users.InactivePct)
	}
	if posture.Users.InactiveDays != DefaultInactiveDays {
		t.Fatalf("Users.InactiveDays = %d, want %d", posture.Users.InactiveDays, DefaultInactiveDays)
	}
	if posture.DeviceAccess == nil {
		t.Fatal("DeviceAccess = nil, want context-aware access evidence block")
	}
	if posture.DeviceAccess.LookbackDays != DefaultContextAwareAccessLookbackDays {
		t.Fatalf("DeviceAccess.LookbackDays = %d, want %d", posture.DeviceAccess.LookbackDays, DefaultContextAwareAccessLookbackDays)
	}
	if posture.DeviceAccess.ContextAwareAccessDeniedEvents != 2 {
		t.Fatalf("DeviceAccess.ContextAwareAccessDeniedEvents = %d, want 2", posture.DeviceAccess.ContextAwareAccessDeniedEvents)
	}
	if posture.DeviceAccess.DeviceStateDeniedEvents != 1 {
		t.Fatalf("DeviceAccess.DeviceStateDeniedEvents = %d, want 1", posture.DeviceAccess.DeviceStateDeniedEvents)
	}
	if !posture.DeviceAccess.ManagedDeviceRequirementEvidenced {
		t.Fatal("DeviceAccess.ManagedDeviceRequirementEvidenced = false, want true")
	}

	// Diagnostics should exist (report date skew warning).
	if posture.Diagnostics == nil {
		t.Fatal("Diagnostics = nil, want warnings")
	}

	// Trust level omits the per-user inventory entirely (byte-stable contract).
	if posture.Users.Inventory != nil {
		t.Fatalf("Users.Inventory at trust = %v, want nil", posture.Users.Inventory)
	}
	if posture.CollectedAtLevel != "trust" {
		t.Fatalf("CollectedAtLevel = %q, want trust", posture.CollectedAtLevel)
	}
}

func TestCollect_UserInventoryByLevel(t *testing.T) {
	now := time.Date(2026, 4, 8, 12, 0, 0, 0, time.UTC)
	created := time.Date(2024, 1, 2, 3, 4, 5, 0, time.UTC)

	newClient := func() *mockClient {
		return &mockClient{
			customer:    googleworkspace.Customer{ID: "C123", PrimaryDomain: "example.com"},
			usageReport: googleworkspace.CustomerUsageReport{NumUsers: 2},
			users: []googleworkspace.User{
				{
					PrimaryEmail: "active@example.com", OrgUnitPath: "/Eng",
					CreationTime: created, AgreedToTerms: true, IPWhitelisted: true,
					IsEnrolledIn2Sv: true, IsEnforcedIn2Sv: true,
					ChangePasswordAtNextLogin: true, LastLoginTime: now.AddDate(0, 0, -3),
				},
				{
					PrimaryEmail: "stale@example.com", OrgUnitPath: "/Sales",
					CreationTime: created, LastLoginTime: now.AddDate(0, 0, -45),
				},
			},
		}
	}

	collectAt := func(level componentsdk.Level) *OrgPosture {
		c := NewWithClient(Config{AdminEmail: "admin@example.com", Now: func() time.Time { return now }}, newClient())
		posture, err := c.Collect(context.Background(), level)
		if err != nil {
			t.Fatalf("Collect(%s) error = %v", level, err)
		}
		return posture
	}

	t.Run("trust omits inventory", func(t *testing.T) {
		if inv := collectAt(componentsdk.LevelTrust).Users.Inventory; inv != nil {
			t.Fatalf("inventory = %v, want nil at trust", inv)
		}
	})

	t.Run("audit populates inventory without internal fields", func(t *testing.T) {
		inv := collectAt(componentsdk.LevelAudit).Users.Inventory
		if len(inv) != 2 {
			t.Fatalf("len(inventory) = %d, want 2", len(inv))
		}
		row := inv[0]
		if row.PrimaryEmail != "active@example.com" {
			t.Fatalf("row[0].PrimaryEmail = %q", row.PrimaryEmail)
		}
		if row.OrgUnitPath != "/Eng" || !row.AgreedToTerms || !row.IPAllowlisted {
			t.Fatalf("row[0] audit fields wrong: %+v", row)
		}
		if row.CreatedAt != created.Format(time.RFC3339) {
			t.Fatalf("row[0].CreatedAt = %q, want %q", row.CreatedAt, created.Format(time.RFC3339))
		}
		if !row.TwoSVEnrolled || !row.TwoSVEnforced {
			t.Fatalf("row[0] 2sv flags wrong: %+v", row)
		}
		if !row.Active7d || !row.Active30d {
			t.Fatalf("row[0] active flags: want both true (login 3d ago); got 7d=%v 30d=%v", row.Active7d, row.Active30d)
		}
		// Internal-only fields must be absent at audit.
		if row.LastLoginAt != "" || row.ChangePasswordAtNextLogin {
			t.Fatalf("row[0] leaked internal fields at audit: %+v", row)
		}
		// Stale user: login 45d ago is neither active-7d nor active-30d.
		if inv[1].Active7d || inv[1].Active30d {
			t.Fatalf("row[1] active flags: want both false; got 7d=%v 30d=%v", inv[1].Active7d, inv[1].Active30d)
		}
	})

	t.Run("internal adds last-login and change-password", func(t *testing.T) {
		inv := collectAt(componentsdk.LevelInternal).Users.Inventory
		row := inv[0]
		if row.LastLoginAt != now.AddDate(0, 0, -3).Format(time.RFC3339) {
			t.Fatalf("row[0].LastLoginAt = %q", row.LastLoginAt)
		}
		if !row.ChangePasswordAtNextLogin {
			t.Fatalf("row[0].ChangePasswordAtNextLogin = false, want true at internal")
		}
	})
}

func TestCollect_AdminInventoryByLevel(t *testing.T) {
	now := time.Date(2026, 4, 8, 12, 0, 0, 0, time.UTC)

	newClient := func() *mockClient {
		return &mockClient{
			customer:    googleworkspace.Customer{ID: "C123", PrimaryDomain: "example.com"},
			usageReport: googleworkspace.CustomerUsageReport{NumUsers: 2},
			users: []googleworkspace.User{
				{ID: "u1", PrimaryEmail: "super@example.com", IsAdmin: true, IsEnrolledIn2Sv: true, IsEnforcedIn2Sv: true, LastLoginTime: now},
				{ID: "u2", PrimaryEmail: "helpdesk@example.com", IsDelegatedAdmin: true, LastLoginTime: now},
			},
			roles: []googleworkspace.Role{
				{ID: "1", Name: "_SEED_ADMIN_ROLE", IsSystem: true, IsSuperAdmin: true, PrivilegeCount: 99},
				{ID: "2", Name: "Helpdesk Lite", Description: "reset passwords", IsSystem: false, PrivilegeCount: 3},
			},
			roleAssignments: []googleworkspace.RoleAssignment{
				{AssignedTo: "u1", RoleID: "1", ScopeType: "CUSTOMER"},
				{AssignedTo: "u2", RoleID: "2", ScopeType: "ORG_UNIT", OrgUnitID: "ou1"},
			},
		}
	}

	collectWith := func(client *mockClient, level componentsdk.Level) *OrgPosture {
		c := NewWithClient(Config{AdminEmail: "admin@example.com", Now: func() time.Time { return now }}, client)
		posture, err := c.Collect(context.Background(), level)
		if err != nil {
			t.Fatalf("Collect(%s) error = %v", level, err)
		}
		return posture
	}

	t.Run("trust omits admin inventory and custom roles", func(t *testing.T) {
		admins := collectWith(newClient(), componentsdk.LevelTrust).Admins
		if admins.Inventory != nil || admins.CustomRoles != nil {
			t.Fatalf("trust leaked admin detail: inv=%v custom=%v", admins.Inventory, admins.CustomRoles)
		}
	})

	t.Run("audit attaches role names and custom-role inventory", func(t *testing.T) {
		admins := collectWith(newClient(), componentsdk.LevelAudit).Admins
		if len(admins.Inventory) != 2 {
			t.Fatalf("len(Inventory) = %d, want 2", len(admins.Inventory))
		}
		byEmail := map[string]Admin{}
		for _, a := range admins.Inventory {
			byEmail[a.PrimaryEmail] = a
		}
		if got := byEmail["super@example.com"].Roles; len(got) != 1 || got[0] != "_SEED_ADMIN_ROLE" {
			t.Fatalf("super roles = %v", got)
		}
		if byEmail["super@example.com"].OrgUnitScoped {
			t.Fatalf("OrgUnitScoped must be omitted at audit")
		}
		if len(admins.CustomRoles) != 1 || admins.CustomRoles[0].Name != "Helpdesk Lite" || admins.CustomRoles[0].PrivilegeCount != 3 {
			t.Fatalf("custom roles = %+v, want only Helpdesk Lite (system roles excluded)", admins.CustomRoles)
		}
	})

	t.Run("internal flags org-unit-scoped grants", func(t *testing.T) {
		admins := collectWith(newClient(), componentsdk.LevelInternal).Admins
		var helpdesk Admin
		for _, a := range admins.Inventory {
			if a.PrimaryEmail == "helpdesk@example.com" {
				helpdesk = a
			}
		}
		if !helpdesk.OrgUnitScoped {
			t.Fatalf("helpdesk OrgUnitScoped = false, want true at internal")
		}
	})

	t.Run("scope-denied keeps emails, drops roles, warns", func(t *testing.T) {
		client := newClient()
		client.rolesErr = &googleapi.Error{Code: 403, Errors: []googleapi.ErrorItem{{Reason: "ACCESS_TOKEN_SCOPE_INSUFFICIENT"}}}
		posture := collectWith(client, componentsdk.LevelAudit)
		if len(posture.Admins.Inventory) != 2 {
			t.Fatalf("inventory should survive scope denial; got %d rows", len(posture.Admins.Inventory))
		}
		for _, a := range posture.Admins.Inventory {
			if a.Roles != nil {
				t.Fatalf("roles should be absent on scope denial; got %v", a.Roles)
			}
		}
		if !hasPermissionError(posture, "scope denied") {
			t.Fatalf("expected scope-denied permission error; permission_errors = %v", permissionErrorsOf(posture))
		}
	})
}

func TestCollect_AccessLevelsByLevel(t *testing.T) {
	now := time.Date(2026, 4, 8, 12, 0, 0, 0, time.UTC)

	newClient := func() *mockClient {
		return &mockClient{
			customer:    googleworkspace.Customer{ID: "C123", PrimaryDomain: "example.com"},
			usageReport: googleworkspace.CustomerUsageReport{NumUsers: 10},
			users:       []googleworkspace.User{{PrimaryEmail: "user@example.com", LastLoginTime: now}},
			contextAwareAccessEvents: []googleworkspace.ContextAwareAccessEvent{
				{UserEmail: "user@example.com", Application: "Drive", DeviceState: "Unmanaged"},
			},
			accessLevels: []googleworkspace.AccessLevel{
				{
					Name: "accessPolicies/111/accessLevels/corp_net", Title: "Corp Net",
					HasDevicePolicy: true, RequiresScreenlock: true,
					AllowedDeviceManagementLevels: []string{"COMPLETE"},
					IPSubnetworks:                 []string{"203.0.113.0/24"},
					Regions:                       []string{"US"},
				},
			},
		}
	}

	collectAt := func(level componentsdk.Level) *AccessContextManagerMetrics {
		c := NewWithClient(Config{AdminEmail: "admin@example.com", AccessPolicy: "111", Now: func() time.Time { return now }}, newClient())
		posture, err := c.Collect(context.Background(), level)
		if err != nil {
			t.Fatalf("Collect(%s) error = %v", level, err)
		}
		if posture.DeviceAccess == nil || posture.DeviceAccess.AccessContextManager == nil {
			t.Fatalf("ACM summary missing at %s", level)
		}
		return posture.DeviceAccess.AccessContextManager
	}

	t.Run("trust omits per-level rows", func(t *testing.T) {
		if levels := collectAt(componentsdk.LevelTrust).Levels; levels != nil {
			t.Fatalf("Levels at trust = %v, want nil", levels)
		}
	})

	t.Run("audit emits summary without rule details", func(t *testing.T) {
		levels := collectAt(componentsdk.LevelAudit).Levels
		if len(levels) != 1 {
			t.Fatalf("len(Levels) = %d, want 1", len(levels))
		}
		row := levels[0]
		if row.Title != "Corp Net" || !row.HasDevicePolicy || !row.RequiresScreenlock {
			t.Fatalf("audit summary wrong: %+v", row)
		}
		if row.IPSubnetworks != nil || row.Regions != nil || row.AllowedDeviceManagementLevels != nil {
			t.Fatalf("rule details must be omitted at audit: %+v", row)
		}
	})

	t.Run("internal adds rule details", func(t *testing.T) {
		row := collectAt(componentsdk.LevelInternal).Levels[0]
		if len(row.IPSubnetworks) != 1 || row.IPSubnetworks[0] != "203.0.113.0/24" {
			t.Fatalf("IPSubnetworks = %v", row.IPSubnetworks)
		}
		if len(row.Regions) != 1 || row.Regions[0] != "US" {
			t.Fatalf("Regions = %v", row.Regions)
		}
		if len(row.AllowedDeviceManagementLevels) != 1 {
			t.Fatalf("AllowedDeviceManagementLevels = %v", row.AllowedDeviceManagementLevels)
		}
	})
}

func TestCollect_GroupsByLevel(t *testing.T) {
	now := time.Date(2026, 4, 8, 12, 0, 0, 0, time.UTC)

	newClient := func() *mockClient {
		return &mockClient{
			customer:    googleworkspace.Customer{ID: "C123", PrimaryDomain: "example.com"},
			usageReport: googleworkspace.CustomerUsageReport{NumUsers: 5},
			users:       []googleworkspace.User{{PrimaryEmail: "u@example.com", LastLoginTime: now}},
			groups: []googleworkspace.Group{
				{Email: "eng@example.com", Name: "Eng", DirectMembersCount: 3, AdminCreated: true},
				{Email: "social@example.com", Name: "Social", DirectMembersCount: 1, AdminCreated: false},
			},
			groupSettings: map[string]googleworkspace.GroupSettings{
				"eng@example.com":    {AllowExternalMembers: false, WhoCanJoin: "INVITED_CAN_JOIN", WhoCanPostMessage: "ALL_MEMBERS_CAN_POST"},
				"social@example.com": {AllowExternalMembers: true, WhoCanJoin: "ALL_IN_DOMAIN_CAN_JOIN"},
			},
			groupMembers: map[string][]googleworkspace.GroupMember{
				"eng@example.com":    {{Email: "u@example.com", Role: "OWNER", Type: "USER", Status: "ACTIVE"}},
				"social@example.com": {{Email: "ext@vendor.com", Role: "MEMBER", Type: "USER"}},
			},
		}
	}

	collectAt := func(level componentsdk.Level) *Groups {
		c := NewWithClient(Config{AdminEmail: "admin@example.com", Now: func() time.Time { return now }}, newClient())
		posture, err := c.Collect(context.Background(), level)
		if err != nil {
			t.Fatalf("Collect(%s) error = %v", level, err)
		}
		if posture.Groups == nil {
			t.Fatalf("Groups nil at %s", level)
		}
		return posture.Groups
	}

	t.Run("trust omits the surface", func(t *testing.T) {
		c := NewWithClient(Config{AdminEmail: "admin@example.com", Now: func() time.Time { return now }}, newClient())
		posture, err := c.Collect(context.Background(), componentsdk.LevelTrust)
		if err != nil {
			t.Fatalf("Collect error = %v", err)
		}
		if posture.Groups != nil {
			t.Fatalf("Groups must be omitted at trust, got %+v", posture.Groups)
		}
	})

	t.Run("audit adds counts + inventory + settings + external count, no members", func(t *testing.T) {
		g := collectAt(componentsdk.LevelAudit)
		if g.Total != 2 || g.AdminCreated != 1 || g.UserCreated != 1 {
			t.Fatalf("counts wrong: %+v", g)
		}
		if len(g.Inventory) != 2 {
			t.Fatalf("len(Inventory) = %d, want 2", len(g.Inventory))
		}
		if g.ExternalMembersAllowed != 1 {
			t.Fatalf("ExternalMembersAllowed = %d, want 1 (social)", g.ExternalMembersAllowed)
		}
		// Inventory sorts by member count desc: eng (3) before social (1).
		if g.Inventory[0].Email != "eng@example.com" {
			t.Fatalf("inventory[0] = %q, want eng (highest member count first)", g.Inventory[0].Email)
		}
		if g.Inventory[1].WhoCanJoin != "ALL_IN_DOMAIN_CAN_JOIN" || !g.Inventory[1].AllowExternalMembers {
			t.Fatalf("social settings wrong: %+v", g.Inventory[1])
		}
		for _, row := range g.Inventory {
			if row.Members != nil {
				t.Fatalf("members must be omitted at audit: %+v", row)
			}
		}
	})

	t.Run("internal adds member lists", func(t *testing.T) {
		g := collectAt(componentsdk.LevelInternal)
		var eng Group
		for _, row := range g.Inventory {
			if row.Email == "eng@example.com" {
				eng = row
			}
		}
		if len(eng.Members) != 1 || eng.Members[0].Role != "OWNER" {
			t.Fatalf("eng members wrong: %+v", eng.Members)
		}
	})
}

func TestCollect_OrgUnitsByLevel(t *testing.T) {
	now := time.Date(2026, 4, 8, 12, 0, 0, 0, time.UTC)

	newClient := func() *mockClient {
		return &mockClient{
			customer:    googleworkspace.Customer{ID: "C123", PrimaryDomain: "example.com"},
			usageReport: googleworkspace.CustomerUsageReport{NumUsers: 3},
			users: []googleworkspace.User{
				{PrimaryEmail: "a@example.com", OrgUnitPath: "/Eng", LastLoginTime: now},
				{PrimaryEmail: "b@example.com", OrgUnitPath: "/Eng/Backend", LastLoginTime: now},
				{PrimaryEmail: "c@example.com", OrgUnitPath: "/Eng/Backend", LastLoginTime: now},
			},
			orgUnits: []googleworkspace.OrgUnit{
				{Path: "/Eng", ParentPath: "/", Description: "Engineering"},
				{Path: "/Eng/Backend", ParentPath: "/Eng", BlockInheritance: true},
			},
		}
	}

	collectAt := func(level componentsdk.Level) *OrgUnits {
		c := NewWithClient(Config{AdminEmail: "admin@example.com", Now: func() time.Time { return now }}, newClient())
		posture, err := c.Collect(context.Background(), level)
		if err != nil {
			t.Fatalf("Collect(%s) error = %v", level, err)
		}
		if posture.OrgUnits == nil {
			t.Fatalf("OrgUnits nil at %s", level)
		}
		return posture.OrgUnits
	}

	t.Run("trust omits the surface", func(t *testing.T) {
		c := NewWithClient(Config{AdminEmail: "admin@example.com", Now: func() time.Time { return now }}, newClient())
		posture, err := c.Collect(context.Background(), componentsdk.LevelTrust)
		if err != nil {
			t.Fatalf("Collect error = %v", err)
		}
		if posture.OrgUnits != nil {
			t.Fatalf("OrgUnits must be omitted at trust, got %+v", posture.OrgUnits)
		}
	})

	t.Run("audit adds count, max depth, and inventory with user counts and override flag", func(t *testing.T) {
		ou := collectAt(componentsdk.LevelAudit)
		if ou.Total != 2 {
			t.Fatalf("Total = %d, want 2", ou.Total)
		}
		if ou.MaxDepth != 2 {
			t.Fatalf("MaxDepth = %d, want 2 (/Eng/Backend)", ou.MaxDepth)
		}
		byPath := map[string]OrgUnit{}
		for _, row := range ou.Inventory {
			byPath[row.Path] = row
		}
		if byPath["/Eng"].UserCount != 1 {
			t.Fatalf("/Eng UserCount = %d, want 1", byPath["/Eng"].UserCount)
		}
		if byPath["/Eng/Backend"].UserCount != 2 {
			t.Fatalf("/Eng/Backend UserCount = %d, want 2", byPath["/Eng/Backend"].UserCount)
		}
		if !byPath["/Eng/Backend"].BlockInheritance {
			t.Fatalf("/Eng/Backend BlockInheritance = false, want true")
		}
	})
}

func TestCollect_EndpointByLevel(t *testing.T) {
	now := time.Date(2026, 4, 8, 12, 0, 0, 0, time.UTC)

	newClient := func() *mockClient {
		return &mockClient{
			customer:    googleworkspace.Customer{ID: "C123", PrimaryDomain: "example.com"},
			usageReport: googleworkspace.CustomerUsageReport{NumUsers: 3},
			users:       []googleworkspace.User{{PrimaryEmail: "u@example.com", LastLoginTime: now}},
			mobileDevices: []googleworkspace.Device{
				{Platform: "MOBILE", OS: "ANDROID", OSVersion: "14", Model: "Pixel", OwnerEmail: "u@example.com", Compliant: true, Encrypted: true, ScreenLockEnforced: true, LastSync: now.AddDate(0, 0, -2)},
				{Platform: "MOBILE", OS: "IOS", Model: "iPhone", OwnerEmail: "v@example.com", Compliant: false, LastSync: now.AddDate(0, 0, -60)},
			},
			chromeDevices: []googleworkspace.Device{
				{Platform: "CHROME_OS", OS: "CHROME_OS", OSVersion: "120", Compliant: true, Encrypted: true, LastSync: now.AddDate(0, 0, -1)},
			},
		}
	}

	collectAt := func(level componentsdk.Level) *Endpoint {
		c := NewWithClient(Config{AdminEmail: "admin@example.com", Now: func() time.Time { return now }}, newClient())
		posture, err := c.Collect(context.Background(), level)
		if err != nil {
			t.Fatalf("Collect(%s) error = %v", level, err)
		}
		if posture.Endpoint == nil {
			t.Fatalf("Endpoint nil at %s", level)
		}
		return posture.Endpoint
	}

	t.Run("trust omits the surface", func(t *testing.T) {
		c := NewWithClient(Config{AdminEmail: "admin@example.com", Now: func() time.Time { return now }}, newClient())
		posture, err := c.Collect(context.Background(), componentsdk.LevelTrust)
		if err != nil {
			t.Fatalf("Collect error = %v", err)
		}
		if posture.Endpoint != nil {
			t.Fatalf("Endpoint must be omitted at trust, got %+v", posture.Endpoint)
		}
	})

	t.Run("audit adds counts by OS, not-synced, and compliance breakdown, no rows", func(t *testing.T) {
		e := collectAt(componentsdk.LevelAudit)
		if e.Total != 3 {
			t.Fatalf("Total = %d, want 3", e.Total)
		}
		if e.ManagedByOS["ANDROID"] != 1 || e.ManagedByOS["IOS"] != 1 || e.ManagedByOS["CHROME_OS"] != 1 {
			t.Fatalf("ManagedByOS = %v", e.ManagedByOS)
		}
		if e.NotSynced30d != 1 {
			t.Fatalf("NotSynced30d = %d, want 1 (the 60d-old iPhone)", e.NotSynced30d)
		}
		if e.CompliantByOS["ANDROID"] != 1 || e.NonCompliantByOS["IOS"] != 1 {
			t.Fatalf("compliance breakdown wrong: compliant=%v noncompliant=%v", e.CompliantByOS, e.NonCompliantByOS)
		}
		if e.Inventory != nil {
			t.Fatalf("per-device rows must be omitted at audit")
		}
	})

	t.Run("internal adds per-device rows", func(t *testing.T) {
		e := collectAt(componentsdk.LevelInternal)
		if len(e.Inventory) != 3 {
			t.Fatalf("len(Inventory) = %d, want 3", len(e.Inventory))
		}
		var sawChrome bool
		for _, row := range e.Inventory {
			if row.Platform == "CHROME_OS" {
				sawChrome = true
				if !row.Encrypted {
					t.Fatalf("Chrome OS device should report encrypted")
				}
			}
		}
		if !sawChrome {
			t.Fatalf("internal inventory missing the Chrome OS device")
		}
	})
}

func TestCollect_AuditSurfacesByLevel(t *testing.T) {
	now := time.Date(2026, 4, 8, 12, 0, 0, 0, time.UTC)
	recent := now.AddDate(0, 0, -2)

	newClient := func() *mockClient {
		return &mockClient{
			customer:    googleworkspace.Customer{ID: "C123", PrimaryDomain: "example.com"},
			usageReport: googleworkspace.CustomerUsageReport{NumUsers: 5},
			users:       []googleworkspace.User{{PrimaryEmail: "u@example.com", LastLoginTime: now}},
			activitiesByApp: map[string][]googleworkspace.AuditEvent{
				"admin": {
					{Time: recent, ActorEmail: "admin@example.com", Name: "SUSPEND_USER"},
					{Time: recent, ActorEmail: "admin@example.com", Name: "CHANGE_SSO_SETTINGS"},
				},
				"login": {
					{Time: recent, ActorEmail: "u@example.com", IPAddress: "203.0.113.7", Name: "suspicious_login"},
					{Time: recent, ActorEmail: "u@example.com", IPAddress: "203.0.113.8", Name: "login_failure"},
				},
				"drive": {
					{Time: recent, ActorEmail: "u@example.com", Name: "change_user_access", Parameters: map[string]string{"target_user": "bob@vendor.com", "doc_id": "doc1"}, MultiParameters: map[string][]string{"new_value": {"can_view"}}},
					{Time: recent, ActorEmail: "u@example.com", Name: "change_document_visibility", Parameters: map[string]string{"visibility": "people_with_link", "doc_id": "doc2"}},
				},
				"token": {
					{Time: recent, ActorEmail: "u@example.com", Name: "authorize", Parameters: map[string]string{"client_id": "111.apps", "app_name": "Acme"}, MultiParameters: map[string][]string{"scope": {"https://www.googleapis.com/auth/gmail.modify"}}},
				},
			},
		}
	}

	collectAt := func(level componentsdk.Level) *OrgPosture {
		c := NewWithClient(Config{AdminEmail: "admin@example.com", Now: func() time.Time { return now }}, newClient())
		posture, err := c.Collect(context.Background(), level)
		if err != nil {
			t.Fatalf("Collect(%s) error = %v", level, err)
		}
		return posture
	}

	t.Run("trust omits all audit surfaces", func(t *testing.T) {
		p := collectAt(componentsdk.LevelTrust)
		if p.AdminAuditLog != nil || p.LoginAuditLog != nil || p.DriveExternalSharing != nil || p.OAuthTokens != nil {
			t.Fatalf("audit surfaces must be nil at trust: admin=%v login=%v drive=%v oauth=%v",
				p.AdminAuditLog, p.LoginAuditLog, p.DriveExternalSharing, p.OAuthTokens)
		}
	})

	t.Run("audit emits counts, no event slices; oauth tokens omitted", func(t *testing.T) {
		p := collectAt(componentsdk.LevelAudit)
		if p.AdminAuditLog.CountsByCategory["USER_SETTINGS"] != 1 || p.AdminAuditLog.CountsByCategory["DOMAIN_SETTINGS"] != 1 {
			t.Fatalf("admin counts wrong: %v", p.AdminAuditLog.CountsByCategory)
		}
		if p.AdminAuditLog.Events != nil {
			t.Fatalf("admin event slice must be omitted at audit")
		}
		if p.OAuthTokens != nil {
			t.Fatalf("OAuthTokens must be nil at audit (internal only): %+v", p.OAuthTokens)
		}
		if p.LoginAuditLog.SuspiciousLogins != 1 || p.LoginAuditLog.FailedLogins != 1 {
			t.Fatalf("login counts wrong: %+v", p.LoginAuditLog)
		}
		if p.DriveExternalSharing.ExternalShareEvents != 1 || p.DriveExternalSharing.PublicOnWebEvents != 1 {
			t.Fatalf("drive counts wrong: %+v", p.DriveExternalSharing)
		}
	})

	t.Run("internal emits event slices; drive never emits recipient email", func(t *testing.T) {
		p := collectAt(componentsdk.LevelInternal)
		if len(p.AdminAuditLog.Events) != 2 {
			t.Fatalf("admin events = %d, want 2", len(p.AdminAuditLog.Events))
		}
		if len(p.LoginAuditLog.Events) != 2 || p.LoginAuditLog.Events[0].IPAddress == "" {
			t.Fatalf("login events wrong: %+v", p.LoginAuditLog.Events)
		}
		if len(p.OAuthTokens.Tokens) != 1 || p.OAuthTokens.Tokens[0].ClientID != "111.apps" {
			t.Fatalf("token rows wrong: %+v", p.OAuthTokens.Tokens)
		}
		// Recipient appears as a domain, never the full email address.
		var sawExternal bool
		for _, e := range p.DriveExternalSharing.Events {
			if strings.Contains(e.RecipientDomain, "@") {
				t.Fatalf("recipient domain leaked an email address: %q", e.RecipientDomain)
			}
			if e.RecipientDomain == "vendor.com" {
				sawExternal = true
			}
		}
		if !sawExternal {
			t.Fatalf("expected an external share event with recipient_domain=vendor.com; got %+v", p.DriveExternalSharing.Events)
		}
	})
}

func TestCollect_InventoryTruncationReporting(t *testing.T) {
	now := time.Date(2026, 4, 8, 12, 0, 0, 0, time.UTC)

	t.Run("user inventory over cap reports truncation", func(t *testing.T) {
		users := make([]googleworkspace.User, UsersCap+3)
		for i := range users {
			users[i] = googleworkspace.User{PrimaryEmail: fmt.Sprintf("u%06d@example.com", i), LastLoginTime: now}
		}
		client := &mockClient{
			customer:    googleworkspace.Customer{ID: "C123", PrimaryDomain: "example.com"},
			usageReport: googleworkspace.CustomerUsageReport{NumUsers: int64(len(users))},
			users:       users,
		}
		c := NewWithClient(Config{AdminEmail: "admin@example.com", Now: func() time.Time { return now }}, client)
		posture, err := c.Collect(context.Background(), componentsdk.LevelAudit)
		if err != nil {
			t.Fatalf("Collect error = %v", err)
		}
		if len(posture.Users.Inventory) != UsersCap {
			t.Fatalf("kept = %d, want %d", len(posture.Users.Inventory), UsersCap)
		}
		if !posture.Users.TruncatedInventory || posture.Users.TruncatedInventoryDropped != 3 {
			t.Fatalf("user truncation fields wrong: truncated=%v dropped=%d", posture.Users.TruncatedInventory, posture.Users.TruncatedInventoryDropped)
		}
		raw, _ := json.Marshal(posture.Users)
		if !strings.Contains(string(raw), `"truncated_inventory":true`) || !strings.Contains(string(raw), `"truncated_inventory_dropped":3`) {
			t.Fatalf("truncation keys missing from users JSON: %s", raw)
		}
	})

	t.Run("group inventory over cap reports truncation", func(t *testing.T) {
		groups := make([]googleworkspace.Group, GroupsCap+2)
		for i := range groups {
			groups[i] = googleworkspace.Group{Email: fmt.Sprintf("g%06d@example.com", i), DirectMembersCount: i}
		}
		client := &mockClient{
			customer:    googleworkspace.Customer{ID: "C123", PrimaryDomain: "example.com"},
			usageReport: googleworkspace.CustomerUsageReport{NumUsers: 1},
			users:       []googleworkspace.User{{PrimaryEmail: "u@example.com", LastLoginTime: now}},
			groups:      groups,
		}
		c := NewWithClient(Config{AdminEmail: "admin@example.com", Now: func() time.Time { return now }}, client)
		posture, err := c.Collect(context.Background(), componentsdk.LevelAudit)
		if err != nil {
			t.Fatalf("Collect error = %v", err)
		}
		if len(posture.Groups.Inventory) != GroupsCap {
			t.Fatalf("kept = %d, want %d", len(posture.Groups.Inventory), GroupsCap)
		}
		if !posture.Groups.TruncatedInventory || posture.Groups.TruncatedInventoryDropped != 2 {
			t.Fatalf("group truncation fields wrong: truncated=%v dropped=%d", posture.Groups.TruncatedInventory, posture.Groups.TruncatedInventoryDropped)
		}
	})

	t.Run("under cap omits truncation fields", func(t *testing.T) {
		client := &mockClient{
			customer:    googleworkspace.Customer{ID: "C123", PrimaryDomain: "example.com"},
			usageReport: googleworkspace.CustomerUsageReport{NumUsers: 2},
			users: []googleworkspace.User{
				{PrimaryEmail: "a@example.com", LastLoginTime: now},
				{PrimaryEmail: "b@example.com", LastLoginTime: now},
			},
			groups: []googleworkspace.Group{{Email: "g@example.com"}},
		}
		c := NewWithClient(Config{AdminEmail: "admin@example.com", Now: func() time.Time { return now }}, client)
		posture, err := c.Collect(context.Background(), componentsdk.LevelAudit)
		if err != nil {
			t.Fatalf("Collect error = %v", err)
		}
		if posture.Users.TruncatedInventory || posture.Groups.TruncatedInventory {
			t.Fatalf("truncation flags should be false under cap")
		}
		raw, _ := json.Marshal(posture.Users)
		if strings.Contains(string(raw), "truncated_inventory") {
			t.Fatalf("truncation keys must be omitted under cap: %s", raw)
		}
	})
}

func warningsOf(p *OrgPosture) []string {
	if p.Diagnostics == nil {
		return nil
	}
	return p.Diagnostics.Warnings
}

func hasWarning(p *OrgPosture, substr string) bool {
	for _, w := range warningsOf(p) {
		if strings.Contains(w, substr) {
			return true
		}
	}
	return false
}

func permissionErrorsOf(p *OrgPosture) []string {
	if p.Diagnostics == nil {
		return nil
	}
	return p.Diagnostics.PermissionErrors
}

func hasPermissionError(p *OrgPosture, substr string) bool {
	for _, e := range permissionErrorsOf(p) {
		if strings.Contains(e, substr) {
			return true
		}
	}
	return false
}

func TestCollect_IDPPostureOutput(t *testing.T) {
	now := time.Date(2026, 4, 8, 12, 0, 0, 0, time.UTC)

	client := &mockClient{
		customer: googleworkspace.Customer{
			ID:            "C123",
			PrimaryDomain: "example.com",
		},
		usageReport: googleworkspace.CustomerUsageReport{
			NumUsers:                           100,
			NumSuspendedUsers:                  5,
			NumArchivedUsers:                   3,
			NumUsers2SVEnrolled:                75,
			NumUsers2SVEnforced:                100,
			NumUsers2SVProtected:               70,
			NumUsersWithPasskeysEnrolled:       10,
			NumUsersPasswordStrengthWeak:       8,
			NumUsersPasswordLengthNonCompliant: 4,
			NumAuthorizedApps:                  42,
			NumLockedUsers:                     3,
		},
		users: []googleworkspace.User{
			{PrimaryEmail: "admin@example.com", IsAdmin: true, IsEnrolledIn2Sv: true, IsEnforcedIn2Sv: true, LastLoginTime: now},
			{PrimaryEmail: "delegated@example.com", IsDelegatedAdmin: true, IsEnrolledIn2Sv: false, LastLoginTime: now},
			{PrimaryEmail: "suspended-admin@example.com", IsAdmin: true, Suspended: true},
			{PrimaryEmail: "archived-admin@example.com", IsDelegatedAdmin: true, Archived: true},
			{PrimaryEmail: "active@example.com", LastLoginTime: now},
			{PrimaryEmail: "inactive@example.com", LastLoginTime: now.AddDate(0, 0, -120)},
			{PrimaryEmail: "never@example.com", LastLoginMissing: true},
		},
		contextAwareAccessEvents: []googleworkspace.ContextAwareAccessEvent{
			{UserEmail: "active@example.com", Application: "Drive", DeviceState: "Unmanaged"},
		},
	}

	c := NewWithClient(Config{
		AdminEmail: "admin@example.com",
		Now:        func() time.Time { return now },
	}, client)

	posture, err := c.Collect(context.Background(), componentsdk.LevelTrust)
	if err != nil {
		t.Fatalf("Collect() error = %v", err)
	}

	idp := posture.ToIDPPosture()
	if idp == nil {
		t.Fatal("ToIDPPosture() = nil, want non-nil for report with user data")
	}
	if idp.Provider != "google_workspace" {
		t.Fatalf("Provider = %q, want google_workspace", idp.Provider)
	}
	if idp.OrgDomain != "example.com" {
		t.Fatalf("OrgDomain = %q, want example.com", idp.OrgDomain)
	}
	// MFACoveragePct uses effective strong-auth coverage. For classic 2SV tenants
	// this still maps to 2sv_protected_pct; passkey-first tenants can exceed it.
	// max(70, 10) = 70.0%
	if idp.UserSecurity.MFACoveragePct != 70.0 {
		t.Fatalf("MFACoveragePct = %.2f, want 70.00 (derived from effective strong-auth coverage)", idp.UserSecurity.MFACoveragePct)
	}
	if idp.UserSecurity.MFAPhishingResistantPct != 10.0 {
		t.Fatalf("MFAPhishingResistantPct = %.2f, want 10.00", idp.UserSecurity.MFAPhishingResistantPct)
	}
	// inactive: 2/5 active users = 40.00%
	if idp.UserSecurity.InactivePct != 40.0 {
		t.Fatalf("InactivePct = %.2f, want 40.00", idp.UserSecurity.InactivePct)
	}
	// locked: 3/100 = 3.0%
	if idp.UserSecurity.LockedOutPct != 3.0 {
		t.Fatalf("LockedOutPct = %.2f, want 3.00", idp.UserSecurity.LockedOutPct)
	}
	if idp.UserSecurity.WeakPasswordPct == nil || *idp.UserSecurity.WeakPasswordPct != 8.0 {
		t.Fatalf("WeakPasswordPct = %v, want 8.00", idp.UserSecurity.WeakPasswordPct)
	}
	if idp.UserSecurity.PasswordPolicyNoncompliantPct == nil || *idp.UserSecurity.PasswordPolicyNoncompliantPct != 4.0 {
		t.Fatalf("PasswordPolicyNoncompliantPct = %v, want 4.00", idp.UserSecurity.PasswordPolicyNoncompliantPct)
	}

	if idp.AppSecurity != nil {
		t.Fatalf("AppSecurity must be nil at trust (internal only), got %+v", idp.AppSecurity)
	}
	if idp.PrivilegedAccess == nil {
		t.Fatal("PrivilegedAccess = nil, want admin posture")
	}
	if idp.PrivilegedAccess.PrivilegedUsersCount != 2 {
		t.Fatalf("PrivilegedUsersCount = %d, want 2", idp.PrivilegedAccess.PrivilegedUsersCount)
	}
	if idp.PrivilegedAccess.SuperAdminCount != 1 {
		t.Fatalf("SuperAdminCount = %d, want 1", idp.PrivilegedAccess.SuperAdminCount)
	}
	if idp.PrivilegedAccess.StandingPrivilegedUsersCount == nil || *idp.PrivilegedAccess.StandingPrivilegedUsersCount != 2 {
		t.Fatalf("StandingPrivilegedUsersCount = %v, want 2", idp.PrivilegedAccess.StandingPrivilegedUsersCount)
	}
	if idp.PrivilegedAccess.PrivilegedMFACoveragePct == nil || *idp.PrivilegedAccess.PrivilegedMFACoveragePct != 50.0 {
		t.Fatalf("PrivilegedMFACoveragePct = %v, want 50.00 based on 2SV enrollment", idp.PrivilegedAccess.PrivilegedMFACoveragePct)
	}
	if idp.Lifecycle == nil {
		t.Fatal("Lifecycle = nil, want suspended/archived coverage")
	}
	if idp.Lifecycle.SuspendedPct == nil || *idp.Lifecycle.SuspendedPct != 5.0 {
		t.Fatalf("SuspendedPct = %v, want 5.00", idp.Lifecycle.SuspendedPct)
	}
	if idp.Lifecycle.ArchivedPct == nil || *idp.Lifecycle.ArchivedPct != 3.0 {
		t.Fatalf("ArchivedPct = %v, want 3.00", idp.Lifecycle.ArchivedPct)
	}

	data, err := json.Marshal(idp)
	if err != nil {
		t.Fatalf("Marshal() error = %v", err)
	}

	var decoded map[string]any
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("Unmarshal() error = %v", err)
	}

	if _, ok := decoded["app_security"]; ok {
		t.Fatal("app_security must not appear in trust-level IDP posture (internal only)")
	}

	if idp.Policy == nil {
		t.Fatal("Policy = nil, want non-nil when enforcement coverage is known")
	}
	if idp.Policy.MFARequired {
		t.Fatal("Policy.MFARequired = true, want false when live active-user enforcement is below 100%")
	}
	if idp.Policy.MFARequiredCoveragePct == nil || *idp.Policy.MFARequiredCoveragePct != 20.0 {
		t.Fatalf("Policy.MFARequiredCoveragePct = %v, want 20.00 from live Directory enforcement", idp.Policy.MFARequiredCoveragePct)
	}
	if idp.Policy.LegacyAuthBlocked == nil || !*idp.Policy.LegacyAuthBlocked {
		t.Fatalf("Policy.LegacyAuthBlocked = %v, want true", idp.Policy.LegacyAuthBlocked)
	}
	if idp.DeviceAccess == nil {
		t.Fatal("DeviceAccess = nil, want managed device evidence")
	}
	if idp.DeviceAccess.ManagedDeviceRequired == nil || !*idp.DeviceAccess.ManagedDeviceRequired {
		t.Fatalf("ManagedDeviceRequired = %v, want true", idp.DeviceAccess.ManagedDeviceRequired)
	}
	if idp.DeviceAccess.ManagedDeviceRequiredForAdmins != nil {
		t.Fatalf("ManagedDeviceRequiredForAdmins = %v, want nil (not inferable from current APIs)", idp.DeviceAccess.ManagedDeviceRequiredForAdmins)
	}
}

func TestToIDPPosture_PartialEnforcementKeepsCoverage(t *testing.T) {
	posture := &OrgPosture{
		CollectedAt: "2026-04-08T12:00:00Z",
		Users:       UserMetrics{Total: 100},
		Authentication: AuthMetrics{
			TwoSVEnforcedPct:  80, // Not 100%
			TwoSVProtectedPct: 70,
		},
	}

	idp := posture.ToIDPPosture()
	if idp.Policy == nil {
		t.Fatal("Policy = nil, want non-nil when enforcement coverage is known")
	}
	if idp.Policy.MFARequired {
		t.Fatal("Policy.MFARequired = true, want false when enforcement < 100%")
	}
	if idp.Policy.MFARequiredCoveragePct == nil || *idp.Policy.MFARequiredCoveragePct != 80.0 {
		t.Fatalf("Policy.MFARequiredCoveragePct = %v, want 80.00", idp.Policy.MFARequiredCoveragePct)
	}
	if idp.Policy.LegacyAuthBlocked == nil || !*idp.Policy.LegacyAuthBlocked {
		t.Fatalf("Policy.LegacyAuthBlocked = %v, want true", idp.Policy.LegacyAuthBlocked)
	}
}

func TestToIDPPosture_UsesPasskeyCoverageForPasswordlessTenants(t *testing.T) {
	posture := &OrgPosture{
		CollectedAt: "2026-04-22T17:41:13Z",
		Users:       UserMetrics{Total: 6},
		Authentication: AuthMetrics{
			TwoSVEnrolledPct:  0,
			TwoSVEnforcedPct:  0,
			TwoSVProtectedPct: 0,
			PasskeyUsersPct:   100,
		},
	}

	idp := posture.ToIDPPosture()
	if idp == nil {
		t.Fatal("ToIDPPosture() = nil, want non-nil")
	}
	if idp.UserSecurity.MFACoveragePct != 100.0 {
		t.Fatalf("MFACoveragePct = %.2f, want 100.00 from passkey-first coverage", idp.UserSecurity.MFACoveragePct)
	}
	if idp.Policy == nil || idp.Policy.MFARequiredCoveragePct == nil || *idp.Policy.MFARequiredCoveragePct != 0.0 {
		t.Fatalf("Policy.MFARequiredCoveragePct = %v, want 0.00 when classic 2SV enforcement is not configured", idp.Policy.MFARequiredCoveragePct)
	}
}

func TestCollect_UsesLiveDirectoryEnforcementForTenantCoverage(t *testing.T) {
	now := time.Date(2026, 4, 22, 17, 41, 13, 0, time.UTC)

	client := &mockClient{
		customer: googleworkspace.Customer{
			ID:            "C123",
			PrimaryDomain: "example.com",
		},
		usageReport: googleworkspace.CustomerUsageReport{
			Date:                         "2026-04-20",
			NumUsers:                     6,
			NumUsers2SVEnforced:          0,
			NumUsers2SVProtected:         0,
			NumUsersWithPasskeysEnrolled: 100,
		},
		users: []googleworkspace.User{
			{PrimaryEmail: "admin1@example.com", IsAdmin: true, IsEnforcedIn2Sv: true, LastLoginTime: now},
			{PrimaryEmail: "admin2@example.com", IsAdmin: true, IsEnforcedIn2Sv: true, LastLoginTime: now},
			{PrimaryEmail: "user1@example.com", IsEnforcedIn2Sv: true, LastLoginTime: now},
			{PrimaryEmail: "user2@example.com", IsEnforcedIn2Sv: true, LastLoginTime: now},
			{PrimaryEmail: "user3@example.com", IsEnforcedIn2Sv: true, LastLoginTime: now},
			{PrimaryEmail: "user4@example.com", IsEnforcedIn2Sv: true, LastLoginTime: now},
		},
	}

	c := NewWithClient(Config{
		AdminEmail: "admin@example.com",
		Now:        func() time.Time { return now },
	}, client)

	posture, err := c.Collect(context.Background(), componentsdk.LevelTrust)
	if err != nil {
		t.Fatalf("Collect() error = %v", err)
	}

	if posture.Authentication.TwoSVEnforcedPct != 100.0 {
		t.Fatalf("Authentication.TwoSVEnforcedPct = %.2f, want 100.00 from live Directory enforcement", posture.Authentication.TwoSVEnforcedPct)
	}

	idp := posture.ToIDPPosture()
	if idp == nil || idp.Policy == nil || idp.Policy.MFARequiredCoveragePct == nil {
		t.Fatal("ToIDPPosture() should include policy enforcement coverage")
	}
	if !idp.Policy.MFARequired {
		t.Fatal("Policy.MFARequired = false, want true when live active-user enforcement is 100%")
	}
	if *idp.Policy.MFARequiredCoveragePct != 100.0 {
		t.Fatalf("Policy.MFARequiredCoveragePct = %.2f, want 100.00", *idp.Policy.MFARequiredCoveragePct)
	}
	if posture.Diagnostics == nil || len(posture.Diagnostics.Warnings) == 0 {
		t.Fatal("Diagnostics = nil, want live-vs-report mismatch warning")
	}
}

func TestToIDPPosture_UsesUniquePrivilegedCount(t *testing.T) {
	posture := &OrgPosture{
		CollectedAt: "2026-04-08T12:00:00Z",
		Users:       UserMetrics{Total: 10},
		Admins: AdminMetrics{
			PrivilegedUsersCount:          4,
			SuperAdminCount:               3,
			DelegatedAdminCount:           2,
			PrivilegedUsers2SVEnrolledPct: 50.0,
			PrivilegedUsers2SVEnforcedPct: 75.0,
		},
	}

	idp := posture.ToIDPPosture()
	if idp == nil || idp.PrivilegedAccess == nil {
		t.Fatal("ToIDPPosture() should include privileged access when user data exists")
	}
	if idp.PrivilegedAccess.PrivilegedUsersCount != 4 {
		t.Fatalf("PrivilegedUsersCount = %d, want 4 unique privileged users", idp.PrivilegedAccess.PrivilegedUsersCount)
	}
	if idp.PrivilegedAccess.PrivilegedMFACoveragePct == nil || *idp.PrivilegedAccess.PrivilegedMFACoveragePct != 50.0 {
		t.Fatalf("PrivilegedMFACoveragePct = %v, want 50.0 from enrolled privileged users", idp.PrivilegedAccess.PrivilegedMFACoveragePct)
	}
	if idp.PrivilegedAccess.StandingPrivilegedUsersCount == nil || *idp.PrivilegedAccess.StandingPrivilegedUsersCount != 4 {
		t.Fatalf("StandingPrivilegedUsersCount = %v, want 4", idp.PrivilegedAccess.StandingPrivilegedUsersCount)
	}
}

func TestToIDPPosture_OmitsDeviceAccessWithoutPositiveEvidence(t *testing.T) {
	posture := &OrgPosture{
		CollectedAt: "2026-04-08T12:00:00Z",
		Users:       UserMetrics{Total: 10},
		DeviceAccess: &DeviceAccessMetrics{
			LookbackDays:                      DefaultContextAwareAccessLookbackDays,
			ContextAwareAccessDeniedEvents:    3,
			DeviceStateDeniedEvents:           0,
			ManagedDeviceRequirementEvidenced: false,
		},
	}

	idp := posture.ToIDPPosture()
	if idp == nil {
		t.Fatal("ToIDPPosture() = nil, want non-nil")
	}
	if idp.DeviceAccess != nil {
		t.Fatalf("DeviceAccess = %+v, want nil without device-state evidence", idp.DeviceAccess)
	}
}

func TestCollect_WarnsWhenUsageReportEmpty(t *testing.T) {
	now := time.Date(2026, 4, 8, 12, 0, 0, 0, time.UTC)

	client := &mockClient{
		customer: googleworkspace.Customer{
			ID:            "C123",
			PrimaryDomain: "example.com",
		},
		usageReport: googleworkspace.CustomerUsageReport{NumUsers: 0},
	}

	c := NewWithClient(Config{
		AdminEmail: "admin@example.com",
		Now:        func() time.Time { return now },
	}, client)

	posture, err := c.Collect(context.Background(), componentsdk.LevelTrust)
	if err != nil {
		t.Fatalf("Collect() error = %v", err)
	}

	if posture.Diagnostics == nil {
		t.Fatal("Diagnostics = nil, want empty-report warning")
	}

	found := false
	for _, w := range posture.Diagnostics.Warnings {
		if len(w) > 0 {
			found = true
		}
	}
	if !found {
		t.Fatal("expected at least one non-empty warning")
	}

	// Normalized artifact must be nil when report has no user data,
	// to avoid emitting zero percentages that look like real posture.
	if idp := posture.ToIDPPosture(); idp != nil {
		t.Fatal("ToIDPPosture() should return nil when usage report is empty")
	}
}

func TestCollect_ContextAwareAccessErrorDoesNotFailCollection(t *testing.T) {
	now := time.Date(2026, 4, 8, 12, 0, 0, 0, time.UTC)

	client := &mockClient{
		customer: googleworkspace.Customer{
			ID:            "C123",
			PrimaryDomain: "example.com",
		},
		usageReport: googleworkspace.CustomerUsageReport{NumUsers: 10},
		users: []googleworkspace.User{
			{PrimaryEmail: "user@example.com", LastLoginTime: now},
		},
		contextAwareAccessErr: errors.New("audit scope missing"),
	}

	c := NewWithClient(Config{
		AdminEmail: "admin@example.com",
		Now:        func() time.Time { return now },
	}, client)

	posture, err := c.Collect(context.Background(), componentsdk.LevelTrust)
	if err != nil {
		t.Fatalf("Collect() error = %v", err)
	}
	if posture.DeviceAccess != nil {
		t.Fatalf("DeviceAccess = %+v, want nil when audit scan fails", posture.DeviceAccess)
	}
	if posture.Diagnostics == nil {
		t.Fatal("Diagnostics = nil, want warning about omitted device access posture")
	}

	found := false
	for _, warning := range posture.Diagnostics.Warnings {
		if warning == "surface device_access: scan failed: audit scope missing" {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("warnings = %#v, want device_access scan-failed warning", posture.Diagnostics.Warnings)
	}

	idp := posture.ToIDPPosture()
	if idp == nil {
		t.Fatal("ToIDPPosture() = nil, want non-nil")
	}
	if idp.DeviceAccess != nil {
		t.Fatalf("DeviceAccess = %+v, want nil when managed-device evidence is unavailable", idp.DeviceAccess)
	}
}

func TestCollect_AccessContextManagerEnrichment(t *testing.T) {
	now := time.Date(2026, 4, 8, 12, 0, 0, 0, time.UTC)

	client := &mockClient{
		customer: googleworkspace.Customer{
			ID:            "C123",
			PrimaryDomain: "example.com",
		},
		usageReport: googleworkspace.CustomerUsageReport{NumUsers: 10},
		users: []googleworkspace.User{
			{PrimaryEmail: "user@example.com", LastLoginTime: now},
		},
		contextAwareAccessEvents: []googleworkspace.ContextAwareAccessEvent{
			{UserEmail: "user@example.com", Application: "Drive", DeviceState: "Unmanaged"},
		},
		accessLevels: []googleworkspace.AccessLevel{
			{
				Name:                          "accessPolicies/111/accessLevels/device_trust",
				Title:                         "Device Trust",
				HasDevicePolicy:               true,
				AllowedDeviceManagementLevels: []string{"BASIC", "COMPLETE"},
				RequiresScreenlock:            true,
			},
			{
				Name:   "accessPolicies/111/accessLevels/custom_expr",
				Title:  "Custom Expr",
				Custom: true,
			},
		},
	}

	c := NewWithClient(Config{
		AdminEmail:   "admin@example.com",
		AccessPolicy: "111",
		Now:          func() time.Time { return now },
	}, client)

	posture, err := c.Collect(context.Background(), componentsdk.LevelTrust)
	if err != nil {
		t.Fatalf("Collect() error = %v", err)
	}

	if client.lastAccessLevelsPolicy != "accessPolicies/111" {
		t.Fatalf("lastAccessLevelsPolicy = %q, want accessPolicies/111", client.lastAccessLevelsPolicy)
	}
	if posture.DeviceAccess == nil || posture.DeviceAccess.AccessContextManager == nil {
		t.Fatal("DeviceAccess.AccessContextManager = nil, want ACM summary")
	}
	acm := posture.DeviceAccess.AccessContextManager
	if acm.AccessPolicyName != "accessPolicies/111" {
		t.Fatalf("AccessPolicyName = %q, want accessPolicies/111", acm.AccessPolicyName)
	}
	if acm.BasicAccessLevelsCount != 1 {
		t.Fatalf("BasicAccessLevelsCount = %d, want 1", acm.BasicAccessLevelsCount)
	}
	if acm.CustomAccessLevelsCount != 1 {
		t.Fatalf("CustomAccessLevelsCount = %d, want 1", acm.CustomAccessLevelsCount)
	}
	if acm.BasicDevicePolicyAccessLevelsCount != 1 {
		t.Fatalf("BasicDevicePolicyAccessLevelsCount = %d, want 1", acm.BasicDevicePolicyAccessLevelsCount)
	}
	if acm.BasicManagedDeviceAccessLevelsCount != 1 {
		t.Fatalf("BasicManagedDeviceAccessLevelsCount = %d, want 1", acm.BasicManagedDeviceAccessLevelsCount)
	}
	if len(acm.BasicDevicePolicyAccessLevelTitles) != 1 || acm.BasicDevicePolicyAccessLevelTitles[0] != "Device Trust" {
		t.Fatalf("BasicDevicePolicyAccessLevelTitles = %#v, want [\"Device Trust\"]", acm.BasicDevicePolicyAccessLevelTitles)
	}

	foundCustomWarning := false
	for _, warning := range posture.Diagnostics.Warnings {
		if warning == "access context manager includes 1 custom access levels; device-policy summary only analyzes basic access levels" {
			foundCustomWarning = true
			break
		}
	}
	if !foundCustomWarning {
		t.Fatalf("warnings = %#v, want custom-level ACM warning", posture.Diagnostics.Warnings)
	}
}

func TestCollect_ResolvesAccessPolicyFromOrganizationID(t *testing.T) {
	now := time.Date(2026, 4, 8, 12, 0, 0, 0, time.UTC)

	client := &mockClient{
		customer: googleworkspace.Customer{
			ID:            "C123",
			PrimaryDomain: "example.com",
		},
		usageReport: googleworkspace.CustomerUsageReport{NumUsers: 10},
		users: []googleworkspace.User{
			{PrimaryEmail: "user@example.com", LastLoginTime: now},
		},
		accessPolicies: []googleworkspace.AccessPolicy{
			{Name: "accessPolicies/222", Parent: "organizations/999999", Title: "Corp policy"},
		},
	}

	c := NewWithClient(Config{
		AdminEmail:     "admin@example.com",
		OrganizationID: "999999",
		Now:            func() time.Time { return now },
	}, client)

	posture, err := c.Collect(context.Background(), componentsdk.LevelTrust)
	if err != nil {
		t.Fatalf("Collect() error = %v", err)
	}

	if client.lastAccessPolicyParent != "organizations/999999" {
		t.Fatalf("lastAccessPolicyParent = %q, want organizations/999999", client.lastAccessPolicyParent)
	}
	if client.lastAccessLevelsPolicy != "accessPolicies/222" {
		t.Fatalf("lastAccessLevelsPolicy = %q, want accessPolicies/222", client.lastAccessLevelsPolicy)
	}
	if posture.DeviceAccess == nil || posture.DeviceAccess.AccessContextManager == nil {
		t.Fatal("DeviceAccess.AccessContextManager = nil, want resolved ACM summary")
	}
	if posture.DeviceAccess.AccessContextManager.AccessPolicyName != "accessPolicies/222" {
		t.Fatalf("AccessPolicyName = %q, want accessPolicies/222", posture.DeviceAccess.AccessContextManager.AccessPolicyName)
	}
}

func TestCollect_UsesConfiguredCustomerKey(t *testing.T) {
	client := &mockClient{
		customer: googleworkspace.Customer{
			ID:            "C123",
			PrimaryDomain: "example.com",
		},
	}

	c := NewWithClient(Config{
		Customer:   "customers/C999",
		AdminEmail: "admin@example.com",
		Now:        func() time.Time { return time.Date(2026, 4, 8, 12, 0, 0, 0, time.UTC) },
	}, client)

	if _, err := c.Collect(context.Background(), componentsdk.LevelTrust); err != nil {
		t.Fatalf("Collect() error = %v", err)
	}

	if client.lastCustomerKey != "customers/C999" {
		t.Fatalf("customer key = %q, want customers/C999", client.lastCustomerKey)
	}
}

func TestCollect_AdminDenominatorExcludesSuspendedArchived(t *testing.T) {
	now := time.Date(2026, 4, 8, 12, 0, 0, 0, time.UTC)

	client := &mockClient{
		customer: googleworkspace.Customer{
			ID:            "C123",
			PrimaryDomain: "example.com",
		},
		usageReport: googleworkspace.CustomerUsageReport{NumUsers: 10},
		users: []googleworkspace.User{
			{PrimaryEmail: "active-admin@example.com", IsAdmin: true, IsEnrolledIn2Sv: true, IsEnforcedIn2Sv: true},
			{PrimaryEmail: "suspended-admin@example.com", IsAdmin: true, Suspended: true, IsEnrolledIn2Sv: true, IsEnforcedIn2Sv: true},
			{PrimaryEmail: "archived-deleg@example.com", IsDelegatedAdmin: true, Archived: true},
		},
	}

	c := NewWithClient(Config{
		AdminEmail: "admin@example.com",
		Now:        func() time.Time { return now },
	}, client)

	posture, err := c.Collect(context.Background(), componentsdk.LevelTrust)
	if err != nil {
		t.Fatalf("Collect() error = %v", err)
	}

	if posture.Admins.SuperAdminCount != 1 {
		t.Fatalf("SuperAdminCount = %d, want 1 (suspended excluded)", posture.Admins.SuperAdminCount)
	}
	if posture.Admins.DelegatedAdminCount != 0 {
		t.Fatalf("DelegatedAdminCount = %d, want 0 (archived excluded)", posture.Admins.DelegatedAdminCount)
	}
	if posture.Admins.PrivilegedUsersCount != 1 {
		t.Fatalf("PrivilegedUsersCount = %d, want 1 (only active admin remains)", posture.Admins.PrivilegedUsersCount)
	}
	if posture.Admins.PrivilegedUsers2SVEnrolledPct != 100.0 {
		t.Fatalf("PrivilegedUsers2SVEnrolledPct = %.2f, want 100.00", posture.Admins.PrivilegedUsers2SVEnrolledPct)
	}
	if posture.Admins.PrivilegedUsers2SVEnforcedPct != 100.0 {
		t.Fatalf("PrivilegedUsers2SVEnforcedPct = %.2f, want 100.00", posture.Admins.PrivilegedUsers2SVEnforcedPct)
	}
}

func TestCollect_ReturnsCustomerErrors(t *testing.T) {
	c := NewWithClient(Config{AdminEmail: "admin@example.com"}, &mockClient{
		customerErr: errors.New("boom"),
	})

	_, err := c.Collect(context.Background(), componentsdk.LevelTrust)
	if err == nil {
		t.Fatal("Collect() error = nil, want error")
	}
}

func TestCollect_DegradesOnUsageReportError(t *testing.T) {
	c := NewWithClient(Config{AdminEmail: "admin@example.com"}, &mockClient{
		customer: googleworkspace.Customer{
			ID:            "C123",
			PrimaryDomain: "example.com",
		},
		usageReportErr: errors.New("reports api down"),
	})

	posture, err := c.Collect(context.Background(), componentsdk.LevelTrust)
	if err != nil {
		t.Fatalf("Collect() error = %v, want nil (usage-report failure should degrade)", err)
	}
	if posture.Users.Total != 0 || posture.Authentication.TwoSVEnrolledPct != 0 {
		t.Fatalf("report-derived metrics should be zeroed on degradation; got users=%+v auth=%+v", posture.Users, posture.Authentication)
	}
	if !hasWarning(posture, "usage_report") {
		t.Fatalf("expected usage_report degradation warning; warnings = %v", warningsOf(posture))
	}
}

func TestCollect_DegradesOnListUsersError(t *testing.T) {
	c := NewWithClient(Config{AdminEmail: "admin@example.com"}, &mockClient{
		customer: googleworkspace.Customer{
			ID:            "C123",
			PrimaryDomain: "example.com",
		},
		usersErr: errors.New("directory api down"),
	})

	posture, err := c.Collect(context.Background(), componentsdk.LevelTrust)
	if err != nil {
		t.Fatalf("Collect() error = %v, want nil (user-scan failure should degrade)", err)
	}
	if posture.Admins.PrivilegedUsersCount != 0 {
		t.Fatalf("admin counts should be zeroed on degradation; got %d", posture.Admins.PrivilegedUsersCount)
	}
	if !hasWarning(posture, "surface users: scan failed") {
		t.Fatalf("expected users degradation warning; warnings = %v", warningsOf(posture))
	}
}

func TestCollect_UsageReportScopeDeniedRecordsPermissionError(t *testing.T) {
	c := NewWithClient(Config{AdminEmail: "admin@example.com"}, &mockClient{
		customer: googleworkspace.Customer{
			ID:            "C123",
			PrimaryDomain: "example.com",
		},
		usageReportErr: &googleapi.Error{Code: 403, Errors: []googleapi.ErrorItem{{Reason: "ACCESS_TOKEN_SCOPE_INSUFFICIENT"}}},
	})

	posture, err := c.Collect(context.Background(), componentsdk.LevelTrust)
	if err != nil {
		t.Fatalf("Collect() error = %v, want nil (scope denial should degrade)", err)
	}
	if !hasPermissionError(posture, "usage_report") {
		t.Fatalf("expected usage_report permission error; permission_errors = %v", permissionErrorsOf(posture))
	}
}

func TestCollect_RetriesOlderDateWhenReportNotYetAvailable(t *testing.T) {
	// 2026-04-08 12:00 UTC → Pacific = 2026-04-08 05:00 PDT
	// First attempt: 2026-04-07 (not yet available)
	// Second attempt: 2026-04-06 (available)
	now := time.Date(2026, 4, 8, 12, 0, 0, 0, time.UTC)

	notYetAvailable := &googleapi.Error{
		Code:    400,
		Message: "Data for dates later than 2026-04-05 is not yet available. Please check back later",
	}

	client := &mockClient{
		customer: googleworkspace.Customer{
			ID:            "C123",
			PrimaryDomain: "example.com",
		},
		usageReportByDate: map[string]mockReportResult{
			"2026-04-07": {err: notYetAvailable},
			"2026-04-06": {report: googleworkspace.CustomerUsageReport{
				Date:     "2026-04-06",
				NumUsers: 50,
			}},
		},
		users: []googleworkspace.User{
			{PrimaryEmail: "user@example.com", LastLoginTime: now},
		},
	}

	c := NewWithClient(Config{
		AdminEmail: "admin@example.com",
		Now:        func() time.Time { return now },
	}, client)

	posture, err := c.Collect(context.Background(), componentsdk.LevelTrust)
	if err != nil {
		t.Fatalf("Collect() error = %v", err)
	}

	if posture.UsageReportDate != "2026-04-06" {
		t.Fatalf("UsageReportDate = %q, want 2026-04-06 (should have fallen back)", posture.UsageReportDate)
	}
	if posture.Users.Total != 50 {
		t.Fatalf("Users.Total = %d, want 50", posture.Users.Total)
	}
	if client.lastReportDate != "2026-04-06" {
		t.Fatalf("lastReportDate = %q, want 2026-04-06", client.lastReportDate)
	}
}

func TestCollect_DegradesWhenAllReportDatesUnavailable(t *testing.T) {
	now := time.Date(2026, 4, 8, 12, 0, 0, 0, time.UTC)

	notYetAvailable := &googleapi.Error{
		Code:    400,
		Message: "Data for dates later than 2026-04-01 is not yet available. Please check back later",
	}

	client := &mockClient{
		customer: googleworkspace.Customer{
			ID:            "C123",
			PrimaryDomain: "example.com",
		},
		usageReportErr: notYetAvailable,
	}

	c := NewWithClient(Config{
		AdminEmail: "admin@example.com",
		Now:        func() time.Time { return now },
	}, client)

	posture, err := c.Collect(context.Background(), componentsdk.LevelTrust)
	if err != nil {
		t.Fatalf("Collect() error = %v, want nil (exhausted report dates should degrade)", err)
	}
	if !hasWarning(posture, "usage_report") {
		t.Fatalf("expected usage_report degradation warning; warnings = %v", warningsOf(posture))
	}
}

func TestCollect_RetriesWhenResponseHasDataNotAvailableWarning(t *testing.T) {
	now := time.Date(2026, 4, 8, 12, 0, 0, 0, time.UTC)

	client := &mockClient{
		customer: googleworkspace.Customer{
			ID:            "C123",
			PrimaryDomain: "example.com",
		},
		usageReportByDate: map[string]mockReportResult{
			"2026-04-07": {report: googleworkspace.CustomerUsageReport{
				Date: "2026-04-07",
				Warnings: []googleworkspace.ReportWarning{
					{Code: "200", Message: "Data is not available for date 2026-04-07 for application accounts."},
				},
			}},
			"2026-04-06": {report: googleworkspace.CustomerUsageReport{
				Date:     "2026-04-06",
				NumUsers: 25,
			}},
		},
		users: []googleworkspace.User{
			{PrimaryEmail: "user@example.com", LastLoginTime: now},
		},
	}

	c := NewWithClient(Config{
		AdminEmail: "admin@example.com",
		Now:        func() time.Time { return now },
	}, client)

	posture, err := c.Collect(context.Background(), componentsdk.LevelTrust)
	if err != nil {
		t.Fatalf("Collect() error = %v", err)
	}

	if posture.UsageReportDate != "2026-04-06" {
		t.Fatalf("UsageReportDate = %q, want 2026-04-06 (should skip date with warning)", posture.UsageReportDate)
	}
	if posture.Users.Total != 25 {
		t.Fatalf("Users.Total = %d, want 25", posture.Users.Total)
	}
}

func TestDiagnosticsReturnsNilWithoutWarnings(t *testing.T) {
	c := &Collector{}

	if diagnostics := c.diagnostics(); diagnostics != nil {
		t.Fatalf("diagnostics = %+v, want nil", diagnostics)
	}
}

func TestPercentFloatRoundsToTwoDecimals(t *testing.T) {
	if got := percentFloat(2, 3); got != 66.67 {
		t.Fatalf("percentFloat(2, 3) = %.2f, want 66.67", got)
	}
	if got := percentFloat(0, 0); got != 0 {
		t.Fatalf("percentFloat(0, 0) = %.2f, want 0", got)
	}
}

func TestReportDateFor(t *testing.T) {
	tests := []struct {
		name string
		now  time.Time
		want string
	}{
		{
			name: "midday UTC",
			now:  time.Date(2026, 4, 8, 12, 0, 0, 0, time.UTC),
			want: "2026-04-07",
		},
		{
			name: "early UTC still previous Pacific day",
			// 2026-04-08 02:00 UTC = 2026-04-07 19:00 PDT
			// Yesterday in Pacific = 2026-04-06
			now:  time.Date(2026, 4, 8, 2, 0, 0, 0, time.UTC),
			want: "2026-04-06",
		},
		{
			name: "late UTC same Pacific day as midday",
			// 2026-04-08 23:00 UTC = 2026-04-08 16:00 PDT
			// Yesterday in Pacific = 2026-04-07
			now:  time.Date(2026, 4, 8, 23, 0, 0, 0, time.UTC),
			want: "2026-04-07",
		},
		{
			name: "midnight UTC is still previous Pacific day",
			// 2026-04-08 00:00 UTC = 2026-04-07 17:00 PDT
			// Yesterday in Pacific = 2026-04-06
			now:  time.Date(2026, 4, 8, 0, 0, 0, 0, time.UTC),
			want: "2026-04-06",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := reportDateFor(tt.now, 1); got != tt.want {
				t.Fatalf("reportDateFor(%v, 1) = %q, want %q", tt.now, got, tt.want)
			}
		})
	}
}
