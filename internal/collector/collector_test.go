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
	signInErr error

	customer    googleworkspace.Customer
	customerErr error

	usageReport    googleworkspace.CustomerUsageReport
	usageReportErr error

	// usageReportByDate overrides usageReport/usageReportErr when set.
	// Keys are date strings ("2026-04-07"). Return error to simulate failures.
	usageReportByDate map[string]mockReportResult

	users    []googleworkspace.User
	usersErr error

	passwordPolicies    []googleworkspace.PasswordPolicy
	passwordPoliciesErr error

	sessionPolicies          []googleworkspace.SessionPolicy
	sessionPoliciesErr       error
	lessSecureAppPolicies    []googleworkspace.LessSecureAppsPolicy
	lessSecureAppPoliciesErr error

	roles              []googleworkspace.Role
	rolesErr           error
	roleAssignments    []googleworkspace.RoleAssignment
	roleAssignmentsErr error
	// userRoleAssignments answers ListUserRoleAssignments by user ID. When
	// it is nil, each user holds their roleAssignments.
	userRoleAssignments    map[string][]googleworkspace.RoleAssignment
	userRoleAssignmentsErr error

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
	ssoAssignments  []googleworkspace.SSOAssignment
	ssoErr          error
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

func (m *mockClient) SignIn(ctx context.Context) error {
	return m.signInErr
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

func (m *mockClient) ListUserRoleAssignments(ctx context.Context, customerID, userKey string, callback func([]googleworkspace.RoleAssignment) error) error {
	if m.userRoleAssignmentsErr != nil {
		return m.userRoleAssignmentsErr
	}
	held := m.userRoleAssignments[userKey]
	if m.userRoleAssignments == nil {
		for _, a := range m.roleAssignments {
			if a.AssignedTo == userKey {
				held = append(held, a)
			}
		}
	}
	if len(held) == 0 {
		return nil
	}
	return callback(held)
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

func (m *mockClient) ListPasswordPolicies(ctx context.Context, customerID string, callback func([]googleworkspace.PasswordPolicy) error) error {
	if m.passwordPoliciesErr != nil {
		return m.passwordPoliciesErr
	}
	if len(m.passwordPolicies) == 0 {
		return nil
	}
	return callback(m.passwordPolicies)
}

func (m *mockClient) ListSessionPolicies(ctx context.Context, customerID string, callback func([]googleworkspace.SessionPolicy) error) error {
	if m.sessionPoliciesErr != nil {
		return m.sessionPoliciesErr
	}
	if len(m.sessionPolicies) == 0 {
		return nil
	}
	return callback(m.sessionPolicies)
}

func (m *mockClient) ListLessSecureAppsPolicies(ctx context.Context, customerID string, callback func([]googleworkspace.LessSecureAppsPolicy) error) error {
	if m.lessSecureAppPoliciesErr != nil {
		return m.lessSecureAppPoliciesErr
	}
	if len(m.lessSecureAppPolicies) == 0 {
		return nil
	}
	return callback(m.lessSecureAppPolicies)
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

func (m *mockClient) ListSSOAssignments(ctx context.Context, callback func([]googleworkspace.SSOAssignment) error) error {
	if m.ssoErr != nil {
		return m.ssoErr
	}
	if len(m.ssoAssignments) == 0 {
		return nil
	}
	return callback(m.ssoAssignments)
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
	wantStr(t, "OrgDomain", posture.OrgDomain, "example.com")
	if posture.CustomerID.Write || posture.CustomerID.Value != nil {
		t.Fatalf("CustomerID = %+v at trust, want it left out", posture.CustomerID)
	}
	wantStr(t, "UsageReportDate", posture.UsageReportDate, "2026-04-07")
	if posture.CollectedAt != now.Format(time.RFC3339) {
		t.Fatalf("CollectedAt = %q, want %q", posture.CollectedAt, now.Format(time.RFC3339))
	}

	// Users (from Reports API).
	wantInt(t, "Users.Total", posture.Users.Total, 100)
	wantInt(t, "Users.Suspended", posture.Users.Suspended, 5)
	wantInt(t, "Users.Archived", posture.Users.Archived, 3)

	// Activity must not appear at trust (audit+ only).
	if posture.Activity != nil {
		t.Fatalf("Activity must be nil at trust, got %+v", posture.Activity)
	}

	// Authentication.
	wantPct(t, "Authentication.TwoSVEnrolledPct", posture.Authentication.TwoSVEnrolledPct, 42.86)
	wantPct(t, "Authentication.TwoSVEnforcedPct", posture.Authentication.TwoSVEnforcedPct, 42.86)
	wantPct(t, "Authentication.TwoSVProtectedPct", posture.Authentication.TwoSVProtectedPct, 70.0)
	wantPct(t, "Authentication.PasskeyUsersPct", posture.Authentication.PasskeyUsersPct, 10.0)
	wantInt(t, "Authentication.SecurityKeysTotal", posture.Authentication.SecurityKeysTotal, 25)

	// Passwords.
	wantPct(t, "Passwords.WeakPasswordPct", posture.Passwords.WeakPasswordPct, 8.0)
	wantPct(t, "Passwords.PasswordLengthNonCompliantPct", posture.Passwords.PasswordLengthNonCompliantPct, 4.0)

	// Apps must not appear at trust (internal only).
	if posture.Apps != nil {
		t.Fatalf("Apps must be nil at trust, got %+v", posture.Apps)
	}

	// Admins (from Directory API, active only).
	// super admins: admin1, admin2, both (suspended-admin excluded)
	wantInt(t, "Admins.SuperAdminCount", posture.Admins.SuperAdminCount, 3)
	// delegated admins: deleg, both (archived-admin excluded)
	wantInt(t, "Admins.DelegatedAdminCount", posture.Admins.DelegatedAdminCount, 2)
	// privileged total: admin1, admin2, deleg, both = 4
	// privileged with 2SV enforced: admin1, deleg, both = 3
	// 3/4 = 75.0
	wantInt(t, "Admins.PrivilegedUsersCount", posture.Admins.PrivilegedUsersCount, 4)
	wantPct(t, "Admins.PrivilegedUsers2SVEnrolledPct", posture.Admins.PrivilegedUsers2SVEnrolledPct, 75.0)
	wantPct(t, "Admins.PrivilegedUsers2SVEnforcedPct", posture.Admins.PrivilegedUsers2SVEnforcedPct, 75.0)

	// Locked (from Reports API): 2/100 = 2.0%
	wantPct(t, "Users.LockedPct", posture.Users.LockedPct, 2.0)

	// Inactive (from Directory API): 7 active users, 2 inactive (inactive-user + never-logged-in)
	// 2/7 = 28.57%
	wantPct(t, "Users.InactivePct", posture.Users.InactivePct, 28.57)
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
		wantInt(t, "g.ExternalMembersAllowed", g.ExternalMembersAllowed, 1)
		// Inventory sorts by member count desc: eng (3) before social (1).
		if g.Inventory[0].Email != "eng@example.com" {
			t.Fatalf("inventory[0] = %q, want eng (highest member count first)", g.Inventory[0].Email)
		}
		if g.Inventory[1].WhoCanJoin != "ALL_IN_DOMAIN_CAN_JOIN" || g.Inventory[1].AllowExternalMembers == nil || !*g.Inventory[1].AllowExternalMembers {
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
		wantInt(t, "byPath[\"/Eng\"].UserCount", byPath["/Eng"].UserCount, 1)
		wantInt(t, "byPath[\"/Eng/Backend\"].UserCount", byPath["/Eng/Backend"].UserCount, 2)
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
				{Platform: "MOBILE", OS: "ANDROID", OSVersion: "14", Model: "Pixel", OwnerEmail: "u@example.com", Compliant: boolPtr(true), Encrypted: true, ScreenLockEnforced: true, LastSync: now.AddDate(0, 0, -2)},
				{Platform: "MOBILE", OS: "IOS", Model: "iPhone", OwnerEmail: "v@example.com", Compliant: boolPtr(false), LastSync: now.AddDate(0, 0, -60)},
			},
			chromeDevices: []googleworkspace.Device{
				{Platform: "CHROME_OS", OS: "CHROME_OS", OSVersion: "120", Compliant: boolPtr(true), Encrypted: true, LastSync: now.AddDate(0, 0, -1)},
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

// A mobile device Google reports no compromise status for counts as neither
// compliant nor non-compliant. The breakdowns get a partial gap, and the
// device's row leaves compliant out.
func TestCollect_EndpointLeavesOutADeviceWithNoCompromiseStatus(t *testing.T) {
	now := time.Date(2026, 4, 8, 12, 0, 0, 0, time.UTC)
	rec := &componentsdk.Recorder{}
	c := NewWithClient(Config{AdminEmail: "admin@example.com", Recorder: rec, Now: func() time.Time { return now }}, &mockClient{
		customer:    googleworkspace.Customer{ID: "C123", PrimaryDomain: "example.com"},
		usageReport: googleworkspace.CustomerUsageReport{NumUsers: 2},
		users:       []googleworkspace.User{{PrimaryEmail: "u@example.com", LastLoginTime: now}},
		mobileDevices: []googleworkspace.Device{
			{Platform: "MOBILE", OS: "ANDROID", Compliant: boolPtr(true), LastSync: now},
			{Platform: "MOBILE", OS: "IOS", LastSync: now},
		},
	})
	posture, err := c.Collect(context.Background(), componentsdk.LevelInternal)
	if err != nil {
		t.Fatalf("Collect() error = %v", err)
	}
	e := posture.Endpoint
	if len(e.CompliantByOS) != 1 || e.CompliantByOS["ANDROID"] != 1 || len(e.NonCompliantByOS) != 0 {
		t.Fatalf("compliant = %v, non-compliant = %v; want only the Android device, as compliant", e.CompliantByOS, e.NonCompliantByOS)
	}
	if e.Inventory[1].Compliant != nil {
		t.Fatalf("iPhone row compliant = %t, want it left out", *e.Inventory[1].Compliant)
	}
	gaps := map[string]componentsdk.Gap{}
	for _, g := range rec.Gaps() {
		gaps[g.Pointer] = g
	}
	for _, pointer := range []string{"/endpoint/compliant_by_os", "/endpoint/non_compliant_by_os"} {
		if g := gaps[pointer]; g.Status != componentsdk.GapPartial || g.Unmeasured != 1 || g.Code != componentsdk.CodeInvalidResponse {
			t.Errorf("gap at %s = %+v, want a partial invalid_response gap with 1 unmeasured", pointer, g)
		}
	}
	if g := gaps["/endpoint/inventory/1/compliant"]; g.Status != componentsdk.GapNotCollected || g.Code != componentsdk.CodeInvalidResponse {
		t.Errorf("gap at /endpoint/inventory/1/compliant = %+v, want an invalid_response gap", g)
	}
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
		if p.DriveExternalSharing.ExternalShareEvents == nil || *p.DriveExternalSharing.ExternalShareEvents != 1 || p.DriveExternalSharing.PublicOnWebEvents != 1 {
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
			{ID: "u-delegated", PrimaryEmail: "delegated@example.com", IsDelegatedAdmin: true, IsEnrolledIn2Sv: false, LastLoginTime: now},
			{PrimaryEmail: "suspended-admin@example.com", IsAdmin: true, Suspended: true},
			{PrimaryEmail: "archived-admin@example.com", IsDelegatedAdmin: true, Archived: true},
			{PrimaryEmail: "active@example.com", LastLoginTime: now},
			{PrimaryEmail: "inactive@example.com", LastLoginTime: now.AddDate(0, 0, -120)},
			{PrimaryEmail: "never@example.com", LastLoginMissing: true},
		},
		contextAwareAccessEvents: []googleworkspace.ContextAwareAccessEvent{
			{UserEmail: "active@example.com", Application: "Drive", DeviceState: "Unmanaged"},
		},
		roles:           []googleworkspace.Role{{ID: "r1", Name: "User Management Admin", Privileges: []string{"USERS_ALL"}}},
		roleAssignments: []googleworkspace.RoleAssignment{{AssignedTo: "u-delegated", RoleID: "r1", ScopeType: "CUSTOMER"}},
	}

	c := NewWithClient(Config{
		AdminEmail: "admin@example.com",
		Now:        func() time.Time { return now },
	}, client)

	posture, err := c.Collect(context.Background(), componentsdk.LevelAudit)
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
	// MFACoveragePct is the larger of the live 2SV share and the report's
	// passkey share. 1 of the 5 active users is enrolled, which gives 20%.
	// 10 of the 100 report users have a passkey, which gives 10%. The report's
	// 75 enrolled and 70 protected users are not used.
	wantPercentage(t, "UserSecurity.MFACoveragePct", idp.UserSecurity.MFACoveragePct, 20)
	wantPercentage(t, "UserSecurity.MFAPhishingResistantPct", idp.UserSecurity.MFAPhishingResistantPct, 10)
	// inactive: 2 of 5 active users = 40%
	wantPercentage(t, "UserSecurity.InactivePct", idp.UserSecurity.InactivePct, 40)
	wantInt(t, "UserSecurity.UserCount", idp.UserSecurity.UserCount, 5)
	wantInt(t, "UserSecurity.InactiveUserCount", idp.UserSecurity.InactiveUserCount, 2)
	// locked: 3 of 100 = 3%
	wantPercentage(t, "UserSecurity.LockedOutPct", idp.UserSecurity.LockedOutPct, 3)
	wantPercentage(t, "UserSecurity.WeakPasswordPct", idp.UserSecurity.WeakPasswordPct, 8)
	wantPercentage(t, "UserSecurity.PasswordPolicyNoncompliantPct", idp.UserSecurity.PasswordPolicyNoncompliantPct, 4)

	if idp.AppSecurity != nil {
		t.Fatalf("AppSecurity must be nil below internal, got %+v", idp.AppSecurity)
	}
	if idp.PrivilegedAccess == nil {
		t.Fatal("PrivilegedAccess = nil, want admin posture")
	}
	wantInt(t, "PrivilegedAccess.PrivilegedUsersCount", idp.PrivilegedAccess.PrivilegedUsersCount, 2)
	wantInt(t, "PrivilegedAccess.SuperAdminCount", idp.PrivilegedAccess.SuperAdminCount, 1)
	if idp.PrivilegedAccess.StandingPrivilegedUsersCount != nil {
		t.Errorf("PrivilegedAccess.StandingPrivilegedUsersCount = %d, want it left out for a tenant with admins", *idp.PrivilegedAccess.StandingPrivilegedUsersCount)
	}
	wantInt(t, "PrivilegedAccess.PrivilegedMFAUserCount", idp.PrivilegedAccess.PrivilegedMFAUserCount, 1)
	wantPercentage(t, "PrivilegedAccess.PrivilegedMFACoveragePct", idp.PrivilegedAccess.PrivilegedMFACoveragePct, 50)
	if idp.Lifecycle == nil {
		t.Fatal("Lifecycle = nil, want suspended/archived coverage")
	}
	wantInt(t, "Lifecycle.AccountCount", idp.Lifecycle.AccountCount, 100)
	wantPercentage(t, "Lifecycle.SuspendedPct", idp.Lifecycle.SuspendedPct, 5)
	wantPercentage(t, "Lifecycle.ArchivedPct", idp.Lifecycle.ArchivedPct, 3)

	data, err := json.Marshal(idp)
	if err != nil {
		t.Fatalf("Marshal() error = %v", err)
	}

	var decoded map[string]any
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("Unmarshal() error = %v", err)
	}

	if _, ok := decoded["app_security"]; ok {
		t.Fatal("app_security must not appear below the internal level")
	}

	if idp.Policy == nil {
		t.Fatal("Policy = nil, want non-nil when enforcement coverage is known")
	}
	if idp.Policy.MFARequired == nil || *idp.Policy.MFARequired {
		t.Fatalf("Policy.MFARequired = %s, want false when live active-user enforcement is below 100%%", showPtr(idp.Policy.MFARequired))
	}
	wantPercentage(t, "Policy.MFARequiredCoveragePct", idp.Policy.MFARequiredCoveragePct, 20)
	if _, ok := decoded["policy"].(map[string]any)["legacy_auth_blocked"]; ok {
		t.Fatal("policy.legacy_auth_blocked is emitted, want it left out: no API reports it for the tenant")
	}
	if idp.DeviceAccess == nil {
		t.Fatal("DeviceAccess = nil, want managed device evidence")
	}
	if idp.DeviceAccess.ManagedDeviceRequired == nil || !*idp.DeviceAccess.ManagedDeviceRequired {
		t.Fatalf("ManagedDeviceRequired = %v, want true", idp.DeviceAccess.ManagedDeviceRequired)
	}
}

func TestToIDPPosture_PartialEnforcementKeepsCoverage(t *testing.T) {
	posture := &OrgPosture{
		CollectedAt: "2026-04-08T12:00:00Z",
		OrgDomain:   strPtr("example.com"),
		Users:       UserMetrics{Total: intPtr(100), Active: intPtr(100)},
		Authentication: AuthMetrics{
			TwoSVEnforcedPct:  pctPtr(80), // Not 100%
			TwoSVProtectedPct: pctPtr(70),
		},
		counts: postureCounts{enforced2SVUsers: intPtr(80)},
	}

	idp := posture.ToIDPPosture()
	if idp.Policy == nil {
		t.Fatal("Policy = nil, want non-nil when enforcement coverage is known")
	}
	if idp.Policy.MFARequired == nil || *idp.Policy.MFARequired {
		t.Fatalf("Policy.MFARequired = %s, want false when enforcement < 100%%", showPtr(idp.Policy.MFARequired))
	}
	wantPercentage(t, "Policy.MFARequiredCoveragePct", idp.Policy.MFARequiredCoveragePct, 80)
}

func TestToIDPPosture_UsesPasskeyCoverageForPasswordlessTenants(t *testing.T) {
	posture := &OrgPosture{
		CollectedAt: "2026-04-22T17:41:13Z",
		OrgDomain:   strPtr("example.com"),
		Users:       UserMetrics{Total: intPtr(6), Active: intPtr(6)},
		Authentication: AuthMetrics{
			TwoSVEnrolledPct:  pctPtr(0),
			TwoSVEnforcedPct:  pctPtr(0),
			TwoSVProtectedPct: pctPtr(0),
			PasskeyUsersPct:   pctPtr(100),
		},
		counts: postureCounts{enrolled2SVUsers: intPtr(0), passkeyUsers: intPtr(6), enforced2SVUsers: intPtr(0)},
	}

	idp := posture.ToIDPPosture()
	if idp == nil {
		t.Fatal("ToIDPPosture() = nil, want non-nil")
	}
	wantPercentage(t, "UserSecurity.MFACoveragePct", idp.UserSecurity.MFACoveragePct, 100)
	if idp.Policy == nil {
		t.Fatal("Policy = nil, want the enforcement coverage")
	}
	wantPercentage(t, "Policy.MFARequiredCoveragePct", idp.Policy.MFARequiredCoveragePct, 0)
}

// A user in a 2-step verification enrollment grace period is counted as
// protected in the Accounts report, though the user has no second factor yet.
func TestCollect_MFACoverageCountsUsersEnrolledIn2SV(t *testing.T) {
	tests := []struct {
		name      string
		enforced  bool
		report    googleworkspace.CustomerUsageReport
		wantPct   float64
		wantUsers int
	}{
		{
			name:     "half the users in the enrollment grace period",
			enforced: true,
			report:   googleworkspace.CustomerUsageReport{NumUsers: 10, NumUsers2SVEnrolled: 5, NumUsers2SVEnforced: 10, NumUsers2SVProtected: 10},
			wantPct:  50,
		},
		{
			name:    "protected equals enrolled",
			report:  googleworkspace.CustomerUsageReport{NumUsers: 10, NumUsers2SVEnrolled: 5, NumUsers2SVProtected: 5},
			wantPct: 50,
		},
		{
			name:    "more passkey users than 2SV users",
			report:  googleworkspace.CustomerUsageReport{NumUsers: 10, NumUsers2SVEnrolled: 2, NumUsers2SVProtected: 2, NumUsersWithPasskeysEnrolled: 6},
			wantPct: 60,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			now := time.Date(2026, 4, 8, 12, 0, 0, 0, time.UTC)
			var users []googleworkspace.User
			for i := range 10 {
				users = append(users, googleworkspace.User{
					ID:              fmt.Sprintf("u%d", i),
					PrimaryEmail:    fmt.Sprintf("user%d@example.com", i),
					IsEnrolledIn2Sv: i < int(tt.report.NumUsers2SVEnrolled),
					IsEnforcedIn2Sv: tt.enforced,
					LastLoginTime:   now,
				})
			}
			client := &mockClient{
				customer:    googleworkspace.Customer{ID: "C123", PrimaryDomain: "example.com"},
				usageReport: tt.report,
				users:       users,
			}
			c := NewWithClient(Config{AdminEmail: "admin@example.com", Now: func() time.Time { return now }}, client)
			posture, err := c.Collect(context.Background(), componentsdk.LevelAudit)
			if err != nil {
				t.Fatalf("Collect() error = %v", err)
			}
			idp := posture.ToIDPPosture()
			if idp == nil || idp.UserSecurity == nil {
				t.Fatalf("ToIDPPosture() = %+v, want user security", idp)
			}
			wantPercentage(t, "UserSecurity.MFACoveragePct", idp.UserSecurity.MFACoveragePct, tt.wantPct)
		})
	}
}

// The 2-step verification share comes from the live Directory scan, so the
// report's enrolled count is not needed.
func TestCollect_MFACoverageWithoutTheReportsEnrolledCount(t *testing.T) {
	now := time.Date(2026, 4, 8, 12, 0, 0, 0, time.UTC)
	client := &mockClient{
		customer: googleworkspace.Customer{ID: "C123", PrimaryDomain: "example.com"},
		usageReport: googleworkspace.CustomerUsageReport{
			NumUsers:             10,
			NumUsers2SVProtected: 7,
			Missing:              []string{"accounts:num_users_2sv_enrolled"},
		},
		users: []googleworkspace.User{{PrimaryEmail: "user@example.com", IsEnrolledIn2Sv: true, LastLoginTime: now}},
	}
	c := NewWithClient(Config{AdminEmail: "admin@example.com", Now: func() time.Time { return now }}, client)

	posture, err := c.Collect(context.Background(), componentsdk.LevelTrust)
	if err != nil {
		t.Fatalf("Collect() error = %v", err)
	}
	idp := posture.ToIDPPosture()
	if idp == nil || idp.UserSecurity == nil {
		t.Fatalf("ToIDPPosture() = %+v, want user security", idp)
	}
	wantPercentage(t, "UserSecurity.MFACoveragePct", idp.UserSecurity.MFACoveragePct, 100)
}

// Suspended and archived users cannot sign in. The usage report counts them
// in its total, so a suspended user who never enrolled in 2-step
// verification would lower the share there.
func TestCollect_MFACoverageLeavesOutSuspendedAndArchivedUsers(t *testing.T) {
	now := time.Date(2026, 4, 8, 12, 0, 0, 0, time.UTC)
	var users []googleworkspace.User
	for i := range 10 {
		users = append(users, googleworkspace.User{
			ID:              fmt.Sprintf("u%d", i),
			PrimaryEmail:    fmt.Sprintf("user%d@example.com", i),
			IsEnrolledIn2Sv: i < 7,
			Suspended:       i == 7 || i == 8,
			Archived:        i == 9,
			LastLoginTime:   now,
		})
	}
	client := &mockClient{
		customer: googleworkspace.Customer{ID: "C123", PrimaryDomain: "example.com"},
		usageReport: googleworkspace.CustomerUsageReport{
			NumUsers: 10, NumSuspendedUsers: 2, NumArchivedUsers: 1, NumUsers2SVEnrolled: 7, NumUsers2SVProtected: 7,
		},
		users: users,
	}
	c := NewWithClient(Config{AdminEmail: "admin@example.com", Now: func() time.Time { return now }}, client)

	posture, err := c.Collect(context.Background(), componentsdk.LevelTrust)
	if err != nil {
		t.Fatalf("Collect() error = %v", err)
	}
	idp := posture.ToIDPPosture()
	if idp == nil || idp.UserSecurity == nil {
		t.Fatalf("ToIDPPosture() = %+v, want user security", idp)
	}
	wantPercentage(t, "UserSecurity.MFACoveragePct", idp.UserSecurity.MFACoveragePct, 100)
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

	wantPct(t, "Authentication.TwoSVEnforcedPct", posture.Authentication.TwoSVEnforcedPct, 100.0)

	idp := posture.ToIDPPosture()
	if idp == nil || idp.Policy == nil {
		t.Fatal("ToIDPPosture() should include policy enforcement coverage")
	}
	if idp.Policy.MFARequired == nil || !*idp.Policy.MFARequired {
		t.Fatalf("Policy.MFARequired = %s, want true when live active-user enforcement is 100%%", showPtr(idp.Policy.MFARequired))
	}
	wantPercentage(t, "Policy.MFARequiredCoveragePct", idp.Policy.MFARequiredCoveragePct, 100)
	if posture.Diagnostics == nil || len(posture.Diagnostics.Warnings) == 0 {
		t.Fatal("Diagnostics = nil, want live-vs-report mismatch warning")
	}
}

// A user who enrolls inside the usage report's 2-3 day publishing lag must not
// be counted as uncovered: the tenant rollup has to agree with the per-user
// inventory flags collected from the same Directory snapshot.
func TestCollect_UsesLiveDirectoryEnrollmentForTenantCoverage(t *testing.T) {
	now := time.Date(2026, 8, 20, 12, 0, 0, 0, time.UTC)

	client := &mockClient{
		customer: googleworkspace.Customer{
			ID:            "C123",
			PrimaryDomain: "example.com",
		},
		usageReport: googleworkspace.CustomerUsageReport{
			Date:                 "2026-08-18",
			NumUsers:             7,
			NumUsers2SVEnrolled:  6,
			NumUsers2SVEnforced:  6,
			NumUsers2SVProtected: 6,
		},
		users: []googleworkspace.User{
			{PrimaryEmail: "admin@example.com", IsAdmin: true, IsEnrolledIn2Sv: true, IsEnforcedIn2Sv: true, LastLoginTime: now},
			{PrimaryEmail: "user1@example.com", IsEnrolledIn2Sv: true, IsEnforcedIn2Sv: true, LastLoginTime: now},
			{PrimaryEmail: "user2@example.com", IsEnrolledIn2Sv: true, IsEnforcedIn2Sv: true, LastLoginTime: now},
			{PrimaryEmail: "user3@example.com", IsEnrolledIn2Sv: true, IsEnforcedIn2Sv: true, LastLoginTime: now},
			{PrimaryEmail: "user4@example.com", IsEnrolledIn2Sv: true, IsEnforcedIn2Sv: true, LastLoginTime: now},
			{PrimaryEmail: "user5@example.com", IsEnrolledIn2Sv: true, IsEnforcedIn2Sv: true, LastLoginTime: now},
			{PrimaryEmail: "user6@example.com", IsEnrolledIn2Sv: true, IsEnforcedIn2Sv: true, LastLoginTime: now},
		},
	}

	c := NewWithClient(Config{
		AdminEmail: "admin@example.com",
		Now:        func() time.Time { return now },
	}, client)

	posture, err := c.Collect(context.Background(), componentsdk.LevelAudit)
	if err != nil {
		t.Fatalf("Collect() error = %v", err)
	}

	wantPct(t, "Authentication.TwoSVEnrolledPct", posture.Authentication.TwoSVEnrolledPct, 100.0)
	wantPct(t, "Authentication.TwoSVEnforcedPct", posture.Authentication.TwoSVEnforcedPct, 100.0)
	if len(posture.Users.Inventory) != 7 {
		t.Fatalf("len(Users.Inventory) = %d, want 7", len(posture.Users.Inventory))
	}
	for _, row := range posture.Users.Inventory {
		if !row.TwoSVEnrolled || !row.TwoSVEnforced {
			t.Fatalf("inventory row %s disagrees with the tenant rollup: %+v", row.PrimaryEmail, row)
		}
	}
	if !hasWarning(posture, "2SV enrollment coverage differs") {
		t.Fatalf("expected enrollment live-vs-report divergence warning; warnings = %v", warningsOf(posture))
	}
}

// A user who logs in inside the usage report's publishing lag must not be
// counted as inactive in the activity rollup while their inventory row shows
// active_7d true from the same Directory snapshot.
func TestCollect_UsesLiveDirectoryActivityForTenantCoverage(t *testing.T) {
	now := time.Date(2026, 8, 20, 12, 0, 0, 0, time.UTC)

	client := &mockClient{
		customer: googleworkspace.Customer{
			ID:            "C123",
			PrimaryDomain: "example.com",
		},
		usageReport: googleworkspace.CustomerUsageReport{
			Date:           "2026-08-18",
			NumUsers:       3,
			Num7DayLogins:  1,
			Num30DayLogins: 2,
		},
		users: []googleworkspace.User{
			{PrimaryEmail: "admin@example.com", IsAdmin: true, LastLoginTime: now},
			{PrimaryEmail: "user1@example.com", LastLoginTime: now.AddDate(0, 0, -2)},
			{PrimaryEmail: "user2@example.com", LastLoginTime: now.AddDate(0, 0, -6)},
		},
	}

	c := NewWithClient(Config{
		AdminEmail: "admin@example.com",
		Now:        func() time.Time { return now },
	}, client)

	posture, err := c.Collect(context.Background(), componentsdk.LevelAudit)
	if err != nil {
		t.Fatalf("Collect() error = %v", err)
	}

	if posture.Activity == nil {
		t.Fatal("Activity = nil, want activity metrics at audit")
	}
	wantPct(t, "Activity.Active7dPct", posture.Activity.Active7dPct, 100.0)
	wantPct(t, "Activity.Active30dPct", posture.Activity.Active30dPct, 100.0)
	for _, row := range posture.Users.Inventory {
		if !row.Active7d || !row.Active30d {
			t.Fatalf("inventory row %s disagrees with the activity rollup: %+v", row.PrimaryEmail, row)
		}
	}
	if !hasWarning(posture, "7-day login activity differs") {
		t.Fatalf("expected 7-day activity divergence warning; warnings = %v", warningsOf(posture))
	}
	if !hasWarning(posture, "30-day login activity differs") {
		t.Fatalf("expected 30-day activity divergence warning; warnings = %v", warningsOf(posture))
	}
}

func TestToIDPPosture_UsesUniquePrivilegedCount(t *testing.T) {
	posture := &OrgPosture{
		CollectedAt:      "2026-04-08T12:00:00Z",
		CollectedAtLevel: string(componentsdk.LevelAudit),
		OrgDomain:        strPtr("example.com"),
		Users:            UserMetrics{Total: intPtr(10)},
		Admins: AdminMetrics{
			PrivilegedUsersCount:          intPtr(4),
			SuperAdminCount:               intPtr(3),
			DelegatedAdminCount:           intPtr(2),
			PrivilegedUsers2SVEnrolledPct: pctPtr(50.0),
			PrivilegedUsers2SVEnforcedPct: pctPtr(75.0),
		},
		counts: postureCounts{privileged: intPtr(4), privileged2SVEnrolled: intPtr(2)},
	}

	idp := posture.ToIDPPosture()
	if idp == nil || idp.PrivilegedAccess == nil {
		t.Fatal("ToIDPPosture() should include privileged access when user data exists")
	}
	wantInt(t, "PrivilegedAccess.PrivilegedUsersCount", idp.PrivilegedAccess.PrivilegedUsersCount, 4)
	wantPercentage(t, "PrivilegedAccess.PrivilegedMFACoveragePct", idp.PrivilegedAccess.PrivilegedMFACoveragePct, 50)
}

func TestToIDPPosture_OmitsDeviceAccessWithoutPositiveEvidence(t *testing.T) {
	posture := &OrgPosture{
		CollectedAt: "2026-04-08T12:00:00Z",
		OrgDomain:   strPtr("example.com"),
		Users:       UserMetrics{Total: intPtr(10)},
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

	// A report with no user data gives no percentages: zero percentages
	// would look like real posture.
	if posture.Users.LockedPct != nil || posture.Authentication.TwoSVProtectedPct != nil {
		t.Fatalf("report percentages over no users = %v, %v; want them left out", posture.Users.LockedPct, posture.Authentication.TwoSVProtectedPct)
	}
	// With no active users either, the normalized percentages are null.
	idp := posture.ToIDPPosture()
	if idp == nil || idp.UserSecurity == nil {
		t.Fatal("ToIDPPosture() has no user security, want users_present false")
	}
	us := idp.UserSecurity
	if us.UsersPresent == nil || *us.UsersPresent {
		t.Fatalf("UsersPresent = %s, want false", showPtr(us.UsersPresent))
	}
	for name, pct := range map[string]Percentage{
		"MFACoveragePct": us.MFACoveragePct, "InactivePct": us.InactivePct, "LockedOutPct": us.LockedOutPct,
		"WeakPasswordPct": us.WeakPasswordPct, "PasswordPolicyNoncompliantPct": us.PasswordPolicyNoncompliantPct,
	} {
		if !pct.Read || pct.Value != nil {
			t.Errorf("UserSecurity.%s = %+v, want null", name, pct)
		}
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

	// At trust the warning gives the error's code, not its message.
	found := false
	for _, warning := range posture.Diagnostics.Warnings {
		if warning == "surface device_access: scan failed: internal" {
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
	if acm.AccessPolicyName != "" {
		t.Fatalf("AccessPolicyName = %q at trust, want it left out", acm.AccessPolicyName)
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

	posture, err = c.Collect(context.Background(), componentsdk.LevelAudit)
	if err != nil {
		t.Fatalf("Collect() error = %v", err)
	}
	if name := posture.DeviceAccess.AccessContextManager.AccessPolicyName; name != "accessPolicies/111" {
		t.Fatalf("AccessPolicyName = %q at audit, want accessPolicies/111", name)
	}
}

// A basic access level joins its conditions with AND, the default, or OR,
// where a request has to meet only one of them. A negated (Don't meet)
// condition is met by a request that fails any of its settings.
func TestCollect_AccessLevelRequirementsComeFromConditionsEveryRequestMeets(t *testing.T) {
	const network = `{"ipSubnetworks":["203.0.113.0/24"]}`
	const device = `{"devicePolicy":{"allowedDeviceManagementLevels":["COMPLETE"],"requireCorpOwned":true,"requireScreenlock":true}}`
	tests := []struct {
		name             string
		basic            string
		wantManaged      int
		wantCorpOwned    bool
		wantScreenlock   bool
		wantDevicePolicy bool
	}{
		{name: "AND", basic: `{"combiningFunction":"AND","conditions":[` + network + `,` + device + `]}`, wantManaged: 1, wantCorpOwned: true, wantScreenlock: true, wantDevicePolicy: true},
		{name: "OR", basic: `{"combiningFunction":"OR","conditions":[` + network + `,` + device + `]}`, wantDevicePolicy: true},
		{name: "OR with one condition", basic: `{"combiningFunction":"OR","conditions":[` + device + `]}`, wantManaged: 1, wantCorpOwned: true, wantScreenlock: true, wantDevicePolicy: true},
		{name: "met", basic: `{"conditions":[{"devicePolicy":{"requireScreenlock":true}}]}`, wantScreenlock: true, wantDevicePolicy: true},
		{name: "negated", basic: `{"conditions":[{"negate":true,"devicePolicy":{"requireScreenlock":true}}]}`, wantDevicePolicy: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tenant := cleanTenant()
			tenant.accessLevels = `{"accessLevels":[{"name":"accessPolicies/111/accessLevels/level","title":"Level","basic":` + tt.basic + `}]}`
			posture := runKitTenant(t, tenant)
			if posture.DeviceAccess == nil || posture.DeviceAccess.AccessContextManager == nil || len(posture.DeviceAccess.AccessContextManager.Levels) != 1 {
				t.Fatalf("device_access = %+v, want one access level", posture.DeviceAccess)
			}
			acm := posture.DeviceAccess.AccessContextManager
			level := acm.Levels[0]
			if acm.BasicManagedDeviceAccessLevelsCount != tt.wantManaged {
				t.Errorf("basic_managed_device_access_levels_count = %d, want %d", acm.BasicManagedDeviceAccessLevelsCount, tt.wantManaged)
			}
			if level.RequiresCorpOwned != tt.wantCorpOwned || level.RequiresScreenlock != tt.wantScreenlock || level.HasDevicePolicy != tt.wantDevicePolicy {
				t.Errorf("level = %+v, want requires_corp_owned %v, requires_screenlock %v, has_device_policy %v", level, tt.wantCorpOwned, tt.wantScreenlock, tt.wantDevicePolicy)
			}
			if !tt.wantCorpOwned && len(level.AllowedDeviceManagementLevels) != 0 {
				t.Errorf("allowed_device_management_levels = %v, want none from a condition a request need not meet", level.AllowedDeviceManagementLevels)
			}
		})
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
	if acm := posture.DeviceAccess.AccessContextManager; acm.AccessPolicyName != "" || acm.AccessPolicyParent != "" {
		t.Fatalf("access policy = %q in %q at trust, want both left out", acm.AccessPolicyName, acm.AccessPolicyParent)
	}

	posture, err = c.Collect(context.Background(), componentsdk.LevelAudit)
	if err != nil {
		t.Fatalf("Collect() error = %v", err)
	}
	if acm := posture.DeviceAccess.AccessContextManager; acm.AccessPolicyName != "accessPolicies/222" || acm.AccessPolicyParent != "organizations/999999" {
		t.Fatalf("access policy = %q in %q at audit, want accessPolicies/222 in organizations/999999", acm.AccessPolicyName, acm.AccessPolicyParent)
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

	wantInt(t, "Admins.SuperAdminCount", posture.Admins.SuperAdminCount, 1)
	wantInt(t, "Admins.DelegatedAdminCount", posture.Admins.DelegatedAdminCount, 0)
	wantInt(t, "Admins.PrivilegedUsersCount", posture.Admins.PrivilegedUsersCount, 1)
	wantPct(t, "Admins.PrivilegedUsers2SVEnrolledPct", posture.Admins.PrivilegedUsers2SVEnrolledPct, 100.0)
	wantPct(t, "Admins.PrivilegedUsers2SVEnforcedPct", posture.Admins.PrivilegedUsers2SVEnforcedPct, 100.0)
}

func TestCollect_SignInFailureFailsTheRun(t *testing.T) {
	rejected := errors.New("token endpoint rejected the assertion")
	c := NewWithClient(Config{AdminEmail: "admin@example.com"}, &mockClient{signInErr: rejected})

	if _, err := c.Collect(context.Background(), componentsdk.LevelTrust); !errors.Is(err, rejected) {
		t.Fatalf("Collect() error = %v, want the sign-in failure", err)
	}
}

// Only a Super Admin can read the tenant record. Without it the run goes on
// under the customer key, and leaves out only what needs the record. The
// customer ID is written from the audit level, as null with a gap when the
// record can't be read, and below it the run records no gap for it.
func TestCollect_CustomerErrorLeavesOutOnlyTheTenantRecord(t *testing.T) {
	for _, level := range []componentsdk.Level{componentsdk.LevelTrust, componentsdk.LevelAudit} {
		t.Run(string(level), func(t *testing.T) {
			testCustomerErrorAt(t, level)
		})
	}
}

func testCustomerErrorAt(t *testing.T, level componentsdk.Level) {
	now := time.Date(2026, 4, 8, 12, 0, 0, 0, time.UTC)
	rec := &componentsdk.Recorder{}
	client := &mockClient{
		customerErr: &googleapi.Error{Code: 403, Errors: []googleapi.ErrorItem{{Reason: "forbidden"}}},
		usageReport: googleworkspace.CustomerUsageReport{NumUsers: 2, NumUsers2SVProtected: 1},
		users:       []googleworkspace.User{{PrimaryEmail: "helpdesk@example.com", IsDelegatedAdmin: true, LastLoginTime: now}},
	}
	c := NewWithClient(Config{AdminEmail: "helpdesk@example.com", Recorder: rec, Now: func() time.Time { return now }}, client)

	posture, err := c.Collect(context.Background(), level)
	if err != nil {
		t.Fatalf("Collect() error = %v, want the run to go on without the tenant record", err)
	}
	audit := level.AtLeast(componentsdk.LevelAudit)
	if posture.CustomerID.Value != nil || posture.CustomerID.Write != audit || posture.OrgDomain != nil {
		t.Fatalf("customer_id = %+v, org_domain = %v; want both left out", posture.CustomerID, posture.OrgDomain)
	}
	if !hasGap(rec, "/org_domain") {
		t.Errorf("no gap at /org_domain; gaps = %+v", rec.Gaps())
	}
	if hasGap(rec, "/customer_id") != audit {
		t.Errorf("gap at /customer_id is %v, want %v; gaps = %+v", !audit, audit, rec.Gaps())
	}
	if client.lastCustomerID != googleworkspace.DefaultCustomerKey {
		t.Fatalf("usage report customer = %q, want the customer key", client.lastCustomerID)
	}
	wantPct(t, "Authentication.TwoSVProtectedPct", posture.Authentication.TwoSVProtectedPct, 50)
	wantInt(t, "Admins.DelegatedAdminCount", posture.Admins.DelegatedAdminCount, 1)
	if !hasPermissionError(posture, "surface customer: impersonation user lacks required admin role: Super Admin") {
		t.Fatalf("permission_errors = %v, want the Super Admin guidance", permissionErrorsOf(posture))
	}
	if idp := posture.ToIDPPosture(); idp != nil {
		t.Fatalf("ToIDPPosture() = %+v, want nil: the normalized shape requires the primary domain", idp)
	}
}

func TestCollect_CustomerScopeDeniedNamesScope(t *testing.T) {
	c := NewWithClient(Config{AdminEmail: "admin@example.com"}, &mockClient{
		customerErr: &googleapi.Error{Code: 403, Errors: []googleapi.ErrorItem{{Reason: "ACCESS_TOKEN_SCOPE_INSUFFICIENT"}}},
	})

	posture, err := c.Collect(context.Background(), componentsdk.LevelTrust)
	if err != nil {
		t.Fatalf("Collect() error = %v, want the run to go on", err)
	}
	if !hasPermissionError(posture, "admin.directory.customer.readonly") {
		t.Errorf("permission_errors = %v, want scope guidance", permissionErrorsOf(posture))
	}
}

func TestCollect_DegradesOnUsageReportError(t *testing.T) {
	rec := &componentsdk.Recorder{}
	c := NewWithClient(Config{AdminEmail: "admin@example.com", Recorder: rec}, &mockClient{
		customer: googleworkspace.Customer{
			ID:            "C123",
			PrimaryDomain: "example.com",
		},
		usageReportErr: errors.New("reports api down"),
		users:          []googleworkspace.User{{PrimaryEmail: "admin@example.com", IsAdmin: true, IsEnrolledIn2Sv: true}},
	})

	posture, err := c.Collect(context.Background(), componentsdk.LevelTrust)
	if err != nil {
		t.Fatalf("Collect() error = %v, want nil (usage-report failure should degrade)", err)
	}
	if posture.Users.Total != nil || posture.Authentication.TwoSVProtectedPct != nil || posture.UsageReportDate != nil {
		t.Fatalf("report-derived metrics should be left out, not zeroed; got users=%+v auth=%+v", posture.Users, posture.Authentication)
	}
	wantPct(t, "Authentication.TwoSVEnrolledPct", posture.Authentication.TwoSVEnrolledPct, 100)
	for _, pointer := range []string{"/usage_report_date", "/users/total", "/authentication/2sv_protected_pct"} {
		if !hasGap(rec, pointer) {
			t.Errorf("no gap at %s; gaps = %+v", pointer, rec.Gaps())
		}
	}
	if !hasWarning(posture, "usage_report") {
		t.Fatalf("expected usage_report degradation warning; warnings = %v", warningsOf(posture))
	}
}

func TestCollect_DegradesOnListUsersError(t *testing.T) {
	rec := &componentsdk.Recorder{}
	c := NewWithClient(Config{AdminEmail: "admin@example.com", Recorder: rec}, &mockClient{
		customer: googleworkspace.Customer{
			ID:            "C123",
			PrimaryDomain: "example.com",
		},
		usageReport: googleworkspace.CustomerUsageReport{NumUsers: 10, NumUsers2SVEnrolled: 9},
		usersErr:    errors.New("directory api down"),
	})

	posture, err := c.Collect(context.Background(), componentsdk.LevelTrust)
	if err != nil {
		t.Fatalf("Collect() error = %v, want nil (user-scan failure should degrade)", err)
	}
	if posture.Admins.PrivilegedUsersCount != nil || posture.Users.InactivePct != nil {
		t.Fatalf("user-scan metrics should be left out, not zeroed; got admins=%+v users=%+v", posture.Admins, posture.Users)
	}
	if posture.Authentication.TwoSVEnrolledPct != nil {
		t.Fatalf("2SV enrollment = %v, want it left out rather than taken from the lagged report", *posture.Authentication.TwoSVEnrolledPct)
	}
	for _, pointer := range []string{"/admins/privileged_users_count", "/users/inactive_pct", "/authentication/2sv_enrolled_pct"} {
		if !hasGap(rec, pointer) {
			t.Errorf("no gap at %s; gaps = %+v", pointer, rec.Gaps())
		}
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

	wantStr(t, "UsageReportDate", posture.UsageReportDate, "2026-04-06")
	wantInt(t, "Users.Total", posture.Users.Total, 50)
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

// The no-data message in the Reports API reference starts "Sorry, data for
// date". The kit fixtures start it "Data is not available".
func TestCollect_RetriesWhenResponseHasDataNotAvailableWarning(t *testing.T) {
	for _, message := range []string{
		`Sorry, data for date 2026-04-07 for application "accounts" is not available.`,
		"Data is not available for date 2026-04-07 for application accounts.",
	} {
		t.Run(message, func(t *testing.T) {
			now := time.Date(2026, 4, 8, 12, 0, 0, 0, time.UTC)

			client := &mockClient{
				customer: googleworkspace.Customer{
					ID:            "C123",
					PrimaryDomain: "example.com",
				},
				usageReportByDate: map[string]mockReportResult{
					"2026-04-07": {report: googleworkspace.CustomerUsageReport{
						Date:     "2026-04-07",
						Warnings: []googleworkspace.ReportWarning{{Code: "200", Message: message}},
						Missing:  reportParameters(),
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

			wantStr(t, "UsageReportDate", posture.UsageReportDate, "2026-04-06")
			wantInt(t, "Users.Total", posture.Users.Total, 25)
		})
	}
}

// The partial-data message in the Reports API reference says the data "is not
// available right now". Messages that start "Partial data" are matched too.
func TestCollect_SkipsPartialReport(t *testing.T) {
	for _, message := range []string{
		`Data for date 2026-04-07 for application "accounts" is not available right now, please try again after a few hours.`,
		"Partial data is available for date 2026-04-07 for application accounts.",
	} {
		t.Run(message, func(t *testing.T) {
			now := time.Date(2026, 4, 8, 12, 0, 0, 0, time.UTC)
			client := &mockClient{
				customer: googleworkspace.Customer{ID: "C123", PrimaryDomain: "example.com"},
				usageReportByDate: map[string]mockReportResult{
					"2026-04-07": {report: googleworkspace.CustomerUsageReport{
						Date:     "2026-04-07",
						NumUsers: 7,
						Warnings: []googleworkspace.ReportWarning{{Code: "200", Message: message}},
					}},
					"2026-04-06": {report: googleworkspace.CustomerUsageReport{
						Date:                         "2026-04-06",
						NumUsers:                     7,
						NumUsersWithPasskeysEnrolled: 7,
						NumSecurityKeys:              10,
					}},
				},
				users: []googleworkspace.User{{PrimaryEmail: "user@example.com", LastLoginTime: now}},
			}
			c := NewWithClient(Config{AdminEmail: "admin@example.com", Now: func() time.Time { return now }}, client)

			posture, err := c.Collect(context.Background(), componentsdk.LevelTrust)
			if err != nil {
				t.Fatalf("Collect() error = %v", err)
			}
			wantStr(t, "UsageReportDate", posture.UsageReportDate, "2026-04-06")
			wantInt(t, "Authentication.SecurityKeysTotal", posture.Authentication.SecurityKeysTotal, 10)
			wantPct(t, "Authentication.PasskeyUsersPct", posture.Authentication.PasskeyUsersPct, 100)
			if !hasWarning(posture, "usage report for 2026-04-07 is partial") {
				t.Fatalf("warnings = %v, want the partial report named", warningsOf(posture))
			}
		})
	}
}

func TestCollect_LeavesOutReportWhenNoDateIsComplete(t *testing.T) {
	now := time.Date(2026, 4, 8, 12, 0, 0, 0, time.UTC)
	partial := func(date string) mockReportResult {
		return mockReportResult{report: googleworkspace.CustomerUsageReport{
			Date:     date,
			NumUsers: 7,
			Warnings: []googleworkspace.ReportWarning{{Code: "200", Message: "Data for date " + date + " for application accounts is not available right now, please try again after a few hours."}},
		}}
	}
	client := &mockClient{
		customer: googleworkspace.Customer{ID: "C123", PrimaryDomain: "example.com"},
		usageReportByDate: map[string]mockReportResult{
			"2026-04-07": partial("2026-04-07"),
			"2026-04-04": partial("2026-04-04"),
			"2026-03-29": partial("2026-03-29"),
		},
		// Every other date is not out yet.
		usageReportErr: &googleapi.Error{Code: 400, Message: "Data for dates later than 2026-03-01 is not yet available. Please check back later"},
		users:          []googleworkspace.User{{PrimaryEmail: "user@example.com", LastLoginTime: now}},
	}
	c := NewWithClient(Config{AdminEmail: "admin@example.com", Now: func() time.Time { return now }}, client)

	posture, err := c.Collect(context.Background(), componentsdk.LevelTrust)
	if err != nil {
		t.Fatalf("Collect() error = %v, want nil", err)
	}
	if posture.UsageReportDate != nil {
		t.Fatalf("UsageReportDate = %q, want nil", *posture.UsageReportDate)
	}
	if posture.Users.Total != nil {
		t.Fatalf("Users.Total = %d, want nil", *posture.Users.Total)
	}
	if posture.Authentication.PasskeyUsersPct != nil {
		t.Fatalf("Authentication.PasskeyUsersPct = %v, want nil", *posture.Authentication.PasskeyUsersPct)
	}
	if !hasWarning(posture, "usage report for 2026-03-29 is partial") || !hasWarning(posture, "usage_report") {
		t.Fatalf("warnings = %v, want the last partial date and the usage_report warning", warningsOf(posture))
	}
}

// reportParameters lists every parameter the client asks the usage report
// for. A report with no data leaves out all of them.
func reportParameters() []string {
	return strings.Split(reportParameterList, ",")
}

func kitTenantWithNewestReport(body string) kitTenant {
	tenant := cleanTenant()
	tenant.reports[0] = kitReport{date: "2026-04-07", body: body}
	return tenant
}

func TestCollect_UsageReportWarningsOverTheReportsAPI(t *testing.T) {
	warning := func(message string) string {
		return `{"kind":"admin#reports#usageReports","warnings":[{"code":"200","message":"` + message + `"}]}`
	}
	// The partial report has 0 passkey users and 0 security keys. The complete
	// report for the day before has both.
	partial := func(message string) string {
		return strings.Replace(usageReport(map[string]int{
			"accounts:num_users": 8, "accounts:num_suspended_users": 1, "accounts:num_archived_users": 1,
			"accounts:num_users_2sv_protected": 4, "accounts:num_users_with_passkeys_enrolled": 0,
			"accounts:num_security_keys": 0, "accounts:num_authorized_apps": 5,
		}), `{"kind":"admin#reports#usageReports",`,
			`{"kind":"admin#reports#usageReports","warnings":[{"code":"200","message":"`+message+`"}],`, 1)
	}

	for _, message := range []string{
		`Sorry, data for date 2026-04-07 for application \"accounts\" is not available.`,
		"Data is not available for date 2026-04-07 for application accounts.",
	} {
		t.Run("no data: "+message, func(t *testing.T) {
			posture := runKitTenant(t, kitTenantWithNewestReport(warning(message)))
			wantStr(t, "UsageReportDate", posture.UsageReportDate, "2026-04-06")
			wantInt(t, "Authentication.SecurityKeysTotal", posture.Authentication.SecurityKeysTotal, 2)
			wantPct(t, "Authentication.TwoSVProtectedPct", posture.Authentication.TwoSVProtectedPct, 50)
			wantPct(t, "Authentication.PasskeyUsersPct", posture.Authentication.PasskeyUsersPct, 12.5)
			if posture.Apps == nil {
				t.Fatal("Apps is nil, want the authorized app count")
			}
			wantInt(t, "Apps.AuthorizedAppsCount", posture.Apps.AuthorizedAppsCount, 5)
		})
	}

	for _, message := range []string{
		`Data for date 2026-04-07 for application \"accounts\" is not available right now, please try again after a few hours.`,
		"Partial data is available for date 2026-04-07.",
	} {
		t.Run("partial data: "+message, func(t *testing.T) {
			posture := runKitTenant(t, kitTenantWithNewestReport(partial(message)))
			wantStr(t, "UsageReportDate", posture.UsageReportDate, "2026-04-06")
			wantInt(t, "Authentication.SecurityKeysTotal", posture.Authentication.SecurityKeysTotal, 2)
			wantPct(t, "Authentication.PasskeyUsersPct", posture.Authentication.PasskeyUsersPct, 12.5)
			if !hasWarning(&posture, "usage report for 2026-04-07 is partial") {
				t.Fatalf("warnings = %v, want the partial report named", warningsOf(&posture))
			}
		})
	}
}

func TestDiagnosticsReturnsNilWithoutWarnings(t *testing.T) {
	c := &Collector{}

	if diagnostics := c.diagnostics(); diagnostics != nil {
		t.Fatalf("diagnostics = %+v, want nil", diagnostics)
	}
}

func TestPercentFloatRoundsToTwoDecimals(t *testing.T) {
	wantPct(t, "percentFloat(2, 3)", percentFloat(2, 3), 66.67)
	if got := percentFloat(0, 0); got != nil {
		t.Fatalf("percentFloat(0, 0) = %v, want nil over no population", *got)
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

// The password policy surface is optional and must never be able to fail the
// run or disturb another surface.
func TestCollect_PasswordPolicyFailureLeavesEverySurfaceIntact(t *testing.T) {
	now := time.Date(2026, 4, 8, 12, 0, 0, 0, time.UTC)

	newClient := func() *mockClient {
		return &mockClient{
			customer: googleworkspace.Customer{ID: "C123", PrimaryDomain: "example.com"},
			usageReport: googleworkspace.CustomerUsageReport{
				NumUsers:                           100,
				NumUsers2SVEnrolled:                90,
				NumUsers2SVEnforced:                100,
				NumUsersPasswordStrengthWeak:       8,
				NumUsersPasswordLengthNonCompliant: 4,
				NumLockedUsers:                     3,
			},
			users: []googleworkspace.User{
				{PrimaryEmail: "admin@example.com", IsAdmin: true, IsEnrolledIn2Sv: true, IsEnforcedIn2Sv: true, LastLoginTime: now},
				{PrimaryEmail: "active@example.com", LastLoginTime: now},
			},
			passwordPolicies: []googleworkspace.PasswordPolicy{
				{MinimumLength: 12, AllowedStrength: "STRONG", EnforceRequirementsAtLogin: true},
			},
		}
	}

	collect := func(t *testing.T, client *mockClient) *OrgPosture {
		t.Helper()
		c := NewWithClient(Config{AdminEmail: "admin@example.com", Now: func() time.Time { return now }}, client)
		posture, err := c.Collect(context.Background(), componentsdk.LevelTrust)
		if err != nil {
			t.Fatalf("Collect() error = %v", err)
		}
		return posture
	}

	healthy := collect(t, newClient())

	broken := newClient()
	broken.passwordPoliciesErr = &googleapi.Error{Code: 403, Errors: []googleapi.ErrorItem{{Reason: "ACCESS_TOKEN_SCOPE_INSUFFICIENT"}}}
	degraded := collect(t, broken)

	if healthy.Passwords.Policy == nil {
		t.Fatal("healthy run Passwords.Policy = nil, want the policy present")
	}
	if degraded.Passwords.Policy != nil {
		t.Fatalf("degraded run Passwords.Policy = %+v, want nil", degraded.Passwords.Policy)
	}

	// Everything outside the password policy must be byte-identical between the
	// two runs. Clearing the one field that is meant to differ, plus the
	// diagnostics that record why, should leave the artifacts equal.
	healthy.Passwords.Policy = nil
	healthy.Diagnostics = nil
	degraded.Diagnostics = nil

	wantJSON, err := json.Marshal(healthy)
	if err != nil {
		t.Fatalf("marshalling healthy posture: %v", err)
	}
	gotJSON, err := json.Marshal(degraded)
	if err != nil {
		t.Fatalf("marshalling degraded posture: %v", err)
	}
	if string(wantJSON) != string(gotJSON) {
		t.Fatalf("a password policy failure changed another surface:\nhealthy  = %s\ndegraded = %s", wantJSON, gotJSON)
	}
}

func wantInt(t *testing.T, name string, got *int, want int) {
	t.Helper()
	if got == nil || *got != want {
		t.Fatalf("%s = %s, want %d", name, showPtr(got), want)
	}
}

func wantPercentage(t *testing.T, name string, got Percentage, want float64) {
	t.Helper()
	if !got.Read || got.Value == nil || *got.Value != want {
		t.Fatalf("%s = %s (read %t), want %v", name, showPtr(got.Value), got.Read, want)
	}
}

func wantPct(t *testing.T, name string, got *float64, want float64) {
	t.Helper()
	if got == nil || *got != want {
		t.Fatalf("%s = %s, want %.2f", name, showPtr(got), want)
	}
}

func wantStr(t *testing.T, name string, got *string, want string) {
	t.Helper()
	if got == nil || *got != want {
		t.Fatalf("%s = %s, want %q", name, showPtr(got), want)
	}
}

func showPtr[T any](p *T) string {
	if p == nil {
		return "null"
	}
	return fmt.Sprint(*p)
}

func pctPtr(v float64) *float64 { return &v }

func strPtr(v string) *string { return &v }

func hasGap(rec *componentsdk.Recorder, pointer string) bool {
	for _, g := range rec.Gaps() {
		if g.Pointer == pointer {
			return true
		}
	}
	return false
}

// A parameter the usage report leaves out is not a zero.
func TestCollect_LeavesOutAUsageReportParameterTheReportOmits(t *testing.T) {
	rec := &componentsdk.Recorder{}
	c := NewWithClient(Config{AdminEmail: "admin@example.com", Recorder: rec, Now: func() time.Time { return time.Date(2026, 4, 8, 12, 0, 0, 0, time.UTC) }}, &mockClient{
		customer: googleworkspace.Customer{ID: "C123", PrimaryDomain: "example.com"},
		usageReport: googleworkspace.CustomerUsageReport{
			NumUsers:             10,
			NumUsers2SVProtected: 7,
			Missing:              []string{"accounts:num_locked_users"},
		},
		sessionPolicies:       []googleworkspace.SessionPolicy{{WebSessionSeconds: 43200}},
		lessSecureAppPolicies: []googleworkspace.LessSecureAppsPolicy{{}},
		passwordPolicies:      []googleworkspace.PasswordPolicy{{MinimumLength: 12, AllowedStrength: "STRONG"}},
	})

	posture, err := c.Collect(context.Background(), componentsdk.LevelTrust)
	if err != nil {
		t.Fatalf("Collect() error = %v", err)
	}
	if posture.Users.LockedPct != nil {
		t.Fatalf("Users.LockedPct = %v, want it left out", *posture.Users.LockedPct)
	}
	wantPct(t, "Authentication.TwoSVProtectedPct", posture.Authentication.TwoSVProtectedPct, 70)
	gaps := rec.Gaps()
	if len(gaps) != 1 || gaps[0].Pointer != "/users/locked_pct" || gaps[0].Code != componentsdk.CodeInvalidResponse {
		t.Fatalf("gaps = %+v, want one invalid_response gap at /users/locked_pct", gaps)
	}
}
