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

	lastCustomerKey string
	lastCustomerID  string
	lastReportDate  string
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
			{PrimaryEmail: "admin1@example.com", IsAdmin: true, IsEnforcedIn2Sv: true, LastLoginTime: now},
			{PrimaryEmail: "admin2@example.com", IsAdmin: true, IsEnforcedIn2Sv: false, LastLoginTime: now},
			{PrimaryEmail: "deleg@example.com", IsDelegatedAdmin: true, IsEnforcedIn2Sv: true, LastLoginTime: now},
			{PrimaryEmail: "both@example.com", IsAdmin: true, IsDelegatedAdmin: true, IsEnforcedIn2Sv: true, LastLoginTime: now},
			{PrimaryEmail: "suspended-admin@example.com", IsAdmin: true, Suspended: true},
			{PrimaryEmail: "archived-admin@example.com", IsDelegatedAdmin: true, Archived: true},
			{PrimaryEmail: "active-user@example.com", LastLoginTime: now},
			{PrimaryEmail: "inactive-user@example.com", LastLoginTime: now.AddDate(0, 0, -120)},
			{PrimaryEmail: "never-logged-in@example.com", LastLoginMissing: true},
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
			NumUsers:                     100,
			NumUsers2SVEnrolled:          75,
			NumUsers2SVEnforced:          100,
			NumUsers2SVProtected:         70,
			NumUsersWithPasskeysEnrolled: 10,
			NumLockedUsers:               3,
		},
		users: []googleworkspace.User{
			{PrimaryEmail: "active@example.com", LastLoginTime: now},
			{PrimaryEmail: "inactive@example.com", LastLoginTime: now.AddDate(0, 0, -120)},
			{PrimaryEmail: "never@example.com", LastLoginMissing: true},
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
	// inactive: 2/3 active users = 66.67%
	if idp.UserSecurity.InactivePct != 66.67 {
		t.Fatalf("InactivePct = %.2f, want 66.67", idp.UserSecurity.InactivePct)
	}
	// locked: 3/100 = 3.0%
	if idp.UserSecurity.LockedOutPct != 3.0 {
		t.Fatalf("LockedOutPct = %.2f, want 3.00", idp.UserSecurity.LockedOutPct)
	}

	// Unsupported sections should be omitted, not faked as zero.
	data, err := json.Marshal(idp)
	if err != nil {
		t.Fatalf("Marshal() error = %v", err)
	}

	var decoded map[string]any
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("Unmarshal() error = %v", err)
	}

	if _, ok := decoded["app_security"]; ok {
		t.Fatal("idp-posture JSON should omit app_security (not available from Google Workspace APIs)")
	}

	// Policy should be present when 2SV is enforced at 100%.
	if idp.Policy == nil {
		t.Fatal("Policy = nil, want non-nil when 2sv_enforced_pct == 100")
	}
	if !idp.Policy.MFARequired {
		t.Fatal("Policy.MFARequired = false, want true when 2sv_enforced_pct == 100")
	}
}

func TestToIDPPosture_OmitsPolicyWhenEnforcementPartial(t *testing.T) {
	posture := &OrgPosture{
		CollectedAt: "2026-04-08T12:00:00Z",
		Users:       UserMetrics{Total: 100},
		Authentication: AuthMetrics{
			TwoSVEnforcedPct:  80, // Not 100%
			TwoSVProtectedPct: 70,
		},
	}

	idp := posture.ToIDPPosture()
	if idp.Policy != nil {
		t.Fatalf("Policy = %+v, want nil when enforcement < 100%%", idp.Policy)
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
			{PrimaryEmail: "active-admin@example.com", IsAdmin: true, IsEnforcedIn2Sv: true},
			{PrimaryEmail: "suspended-admin@example.com", IsAdmin: true, Suspended: true, IsEnforcedIn2Sv: true},
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
