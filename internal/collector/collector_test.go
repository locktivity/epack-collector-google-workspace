package collector

import (
	"context"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"google.golang.org/api/googleapi"

	"github.com/locktivity/epack-collector-google-workspace/internal/googleworkspace"
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

	posture, err := c.Collect(context.Background())
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

	// Activity.
	if posture.Activity.Active7dPct != 80.0 {
		t.Fatalf("Activity.Active7dPct = %.2f, want 80.00", posture.Activity.Active7dPct)
	}
	if posture.Activity.Active30dPct != 90.0 {
		t.Fatalf("Activity.Active30dPct = %.2f, want 90.00", posture.Activity.Active30dPct)
	}

	// Authentication.
	if posture.Authentication.TwoSVEnrolledPct != 75.0 {
		t.Fatalf("Authentication.TwoSVEnrolledPct = %.2f, want 75.00", posture.Authentication.TwoSVEnrolledPct)
	}
	if posture.Authentication.TwoSVEnforcedPct != 60.0 {
		t.Fatalf("Authentication.TwoSVEnforcedPct = %.2f, want 60.00", posture.Authentication.TwoSVEnforcedPct)
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

	// Apps.
	if posture.Apps.AuthorizedAppsCount != 42 {
		t.Fatalf("Apps.AuthorizedAppsCount = %d, want 42", posture.Apps.AuthorizedAppsCount)
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

	posture, err := c.Collect(context.Background())
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
	// MFACoveragePct maps from 2sv_protected_pct (effective coverage), not enrolled.
	// 70/100 = 70.0%
	if idp.UserSecurity.MFACoveragePct != 70.0 {
		t.Fatalf("MFACoveragePct = %.2f, want 70.00 (derived from 2sv_protected_pct)", idp.UserSecurity.MFACoveragePct)
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

	if idp.AppSecurity == nil {
		t.Fatal("AppSecurity = nil, want authorized app count")
	}
	if idp.AppSecurity.AuthorizedThirdPartyAppsCount == nil || *idp.AppSecurity.AuthorizedThirdPartyAppsCount != 42 {
		t.Fatalf("AuthorizedThirdPartyAppsCount = %v, want 42", idp.AppSecurity.AuthorizedThirdPartyAppsCount)
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

	if _, ok := decoded["app_security"]; !ok {
		t.Fatal("idp-posture JSON should include app_security when authorized app count is available")
	}

	if idp.Policy == nil {
		t.Fatal("Policy = nil, want non-nil when enforcement coverage is known")
	}
	if !idp.Policy.MFARequired {
		t.Fatal("Policy.MFARequired = false, want true when 2sv_enforced_pct == 100")
	}
	if idp.Policy.MFARequiredCoveragePct == nil || *idp.Policy.MFARequiredCoveragePct != 100.0 {
		t.Fatalf("Policy.MFARequiredCoveragePct = %v, want 100.00", idp.Policy.MFARequiredCoveragePct)
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

	posture, err := c.Collect(context.Background())
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

	posture, err := c.Collect(context.Background())
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
		if warning == "context-aware access audit scan failed; device access posture omitted: audit scope missing" {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("warnings = %#v, want context-aware access warning", posture.Diagnostics.Warnings)
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

	posture, err := c.Collect(context.Background())
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

	posture, err := c.Collect(context.Background())
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

	if _, err := c.Collect(context.Background()); err != nil {
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

	posture, err := c.Collect(context.Background())
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

	_, err := c.Collect(context.Background())
	if err == nil {
		t.Fatal("Collect() error = nil, want error")
	}
}

func TestCollect_ReturnsUsageReportErrors(t *testing.T) {
	c := NewWithClient(Config{AdminEmail: "admin@example.com"}, &mockClient{
		customer: googleworkspace.Customer{
			ID:            "C123",
			PrimaryDomain: "example.com",
		},
		usageReportErr: errors.New("reports api down"),
	})

	_, err := c.Collect(context.Background())
	if err == nil {
		t.Fatal("Collect() error = nil, want error")
	}
}

func TestCollect_ReturnsListUsersErrors(t *testing.T) {
	c := NewWithClient(Config{AdminEmail: "admin@example.com"}, &mockClient{
		customer: googleworkspace.Customer{
			ID:            "C123",
			PrimaryDomain: "example.com",
		},
		usersErr: errors.New("directory api down"),
	})

	_, err := c.Collect(context.Background())
	if err == nil {
		t.Fatal("Collect() error = nil, want error")
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

	posture, err := c.Collect(context.Background())
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

func TestCollect_FailsWhenAllReportDatesUnavailable(t *testing.T) {
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

	_, err := c.Collect(context.Background())
	if err == nil {
		t.Fatal("Collect() error = nil, want error when all dates unavailable")
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

	posture, err := c.Collect(context.Background())
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
			if got := reportDateFor(tt.now); got != tt.want {
				t.Fatalf("reportDateFor(%v) = %q, want %q", tt.now, got, tt.want)
			}
		})
	}
}
