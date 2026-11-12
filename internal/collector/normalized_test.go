package collector

import (
	"encoding/json"
	"errors"
	"slices"
	"strings"
	"testing"

	"github.com/locktivity/epack-collector-google-workspace/internal/googleworkspace"
	"github.com/locktivity/epack/componentsdk"
)

func postureWithCounts(level componentsdk.Level) *OrgPosture {
	return &OrgPosture{
		CollectedAtLevel: string(level),
		OrgDomain:        strPtr("example.com"),
		Users:            UserMetrics{Total: intPtr(3000), Suspended: intPtr(1), Archived: intPtr(0), Active: intPtr(2999)},
		Admins:           AdminMetrics{PrivilegedUsersCount: intPtr(3), SuperAdminCount: intPtr(1)},
		Passwords: PasswordMetrics{Policy: &PasswordPolicyConfig{
			MinimumLength: 12, AllowedStrength: strengthStrong, EnforceRequirementsAtLogin: true,
		}},
		counts: postureCounts{
			inactiveUsers: intPtr(1), enforced2SVUsers: intPtr(2998), privileged: intPtr(3), privileged2SVEnrolled: intPtr(3),
			enrolled2SVUsers: intPtr(2998), passkeyUsers: intPtr(0), lockedUsers: intPtr(1),
			weakPasswordUsers: intPtr(0), shortPasswordUsers: intPtr(0),
		},
	}
}

// Each percentage is rounded down where more is better and up where more is
// worse. A shortfall then never shows as 100, and an exposure never shows as
// 0.
func TestToIDPPostureRoundsPercentagesToWholeNumbers(t *testing.T) {
	idp := postureWithCounts(componentsdk.LevelTrust).ToIDPPosture()

	wantPercentage(t, "MFACoveragePct", idp.UserSecurity.MFACoveragePct, 99)
	wantPercentage(t, "MFARequiredCoveragePct", idp.Policy.MFARequiredCoveragePct, 99)
	wantPercentage(t, "InactivePct", idp.UserSecurity.InactivePct, 1)
	wantPercentage(t, "LockedOutPct", idp.UserSecurity.LockedOutPct, 1)
	wantPercentage(t, "SuspendedPct", idp.Lifecycle.SuspendedPct, 1)
	wantPercentage(t, "ArchivedPct", idp.Lifecycle.ArchivedPct, 0)
	if idp.Policy.MFARequired == nil || *idp.Policy.MFARequired {
		t.Fatalf("MFARequired = %s, want false with one active user not enforced", showPtr(idp.Policy.MFARequired))
	}
}

func TestToIDPPostureWritesCountsFromTheAuditLevel(t *testing.T) {
	trust := postureWithCounts(componentsdk.LevelTrust).ToIDPPosture()
	if trust.UserSecurity.UserCount != nil || trust.PrivilegedAccess.PrivilegedUsersCount != nil || trust.Lifecycle.AccountCount != nil {
		t.Fatalf("trust posture has counts: %+v %+v %+v", trust.UserSecurity, trust.PrivilegedAccess, trust.Lifecycle)
	}
	for name, flag := range map[string]*bool{
		"UsersPresent":           trust.UserSecurity.UsersPresent,
		"PrivilegedUsersPresent": trust.PrivilegedAccess.PrivilegedUsersPresent,
		"AccountsPresent":        trust.Lifecycle.AccountsPresent,
	} {
		if flag == nil || !*flag {
			t.Errorf("trust %s = %s, want true", name, showPtr(flag))
		}
	}

	audit := postureWithCounts(componentsdk.LevelAudit).ToIDPPosture()
	wantInt(t, "UserCount", audit.UserSecurity.UserCount, 2999)
	wantInt(t, "InactiveUserCount", audit.UserSecurity.InactiveUserCount, 1)
	wantInt(t, "MFARequiredUserCount", audit.Policy.MFARequiredUserCount, 2998)
	wantInt(t, "PrivilegedMFAUserCount", audit.PrivilegedAccess.PrivilegedMFAUserCount, 3)
	wantInt(t, "AccountCount", audit.Lifecycle.AccountCount, 3000)
	wantInt(t, "SuspendedAccountCount", audit.Lifecycle.SuspendedAccountCount, 1)
}

// For a tenant with no privileged users, the privileged percentage is null.
// A percentage the collector could not read is left out.
func TestToIDPPostureWritesNullOverNoPrivilegedUsers(t *testing.T) {
	posture := postureWithCounts(componentsdk.LevelTrust)
	posture.Admins.PrivilegedUsersCount = intPtr(0)
	posture.counts.privileged, posture.counts.privileged2SVEnrolled = intPtr(0), intPtr(0)

	raw, err := json.Marshal(posture.ToIDPPosture().PrivilegedAccess)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{`"privileged_users_present":false`, `"privileged_mfa_coverage_pct":null`} {
		if !strings.Contains(string(raw), want) {
			t.Fatalf("privileged access = %s, want it to contain %s", raw, want)
		}
	}
}

// An admin role can be assigned until a set time, and the collector does not
// read those times. For a tenant with admins, the standing values are left
// out with a not_read gap, and the count gets its gap only at audit. A tenant
// with no admins has no standing admins either.
func TestToIDPPostureStandingAdminValues(t *testing.T) {
	standing := []string{"/privileged_access/standing_privileged_users_present", "/privileged_access/standing_privileged_users_count"}
	for _, level := range []componentsdk.Level{componentsdk.LevelTrust, componentsdk.LevelAudit} {
		for _, admins := range []int{3, 0} {
			posture := postureWithCounts(level)
			posture.Admins.PrivilegedUsersCount = intPtr(admins)
			posture.counts.privileged = intPtr(admins)
			rec := &componentsdk.Recorder{}
			c := NewWithClient(Config{AdminEmail: "admin@example.com", Recorder: rec}, &mockClient{})
			pa := posture.ToIDPPosture().PrivilegedAccess
			c.recordIDPPostureGaps(posture, level)
			gaps := map[string]componentsdk.Code{}
			for _, g := range rec.Gaps() {
				if g.Path == idpPosturePath {
					gaps[g.Pointer] = g.Code
				}
			}
			if admins > 0 {
				if pa.StandingPrivilegedUsersPresent != nil || pa.StandingPrivilegedUsersCount != nil {
					t.Errorf("%s, %d admins: standing = %s and %s, want both left out", level, admins, showPtr(pa.StandingPrivilegedUsersPresent), showPtr(pa.StandingPrivilegedUsersCount))
				}
				want := map[string]componentsdk.Code{standing[0]: componentsdk.CodeNotRead}
				if level == componentsdk.LevelAudit {
					want[standing[1]] = componentsdk.CodeNotRead
				}
				for _, pointer := range standing {
					if gaps[pointer] != want[pointer] {
						t.Errorf("%s, %d admins: %s gap = %q, want %q", level, admins, pointer, gaps[pointer], want[pointer])
					}
				}
				continue
			}
			if pa.StandingPrivilegedUsersPresent == nil || *pa.StandingPrivilegedUsersPresent {
				t.Errorf("%s, no admins: standing_privileged_users_present = %s, want false", level, showPtr(pa.StandingPrivilegedUsersPresent))
			}
			if level == componentsdk.LevelAudit {
				wantInt(t, "StandingPrivilegedUsersCount", pa.StandingPrivilegedUsersCount, 0)
			}
			for _, pointer := range standing {
				if code, ok := gaps[pointer]; ok {
					t.Errorf("%s, no admins: %s has a %s gap, want none", level, pointer, code)
				}
			}
		}
	}
}

// The usage report percentages are over the report's users, and
// users_present comes from the live scan. When the scan fails, those
// percentages are left out.
func TestToIDPPostureLeavesOutReportPercentagesWithoutTheScan(t *testing.T) {
	posture := postureWithCounts(componentsdk.LevelTrust)
	posture.Users.Active = nil
	posture.counts.inactiveUsers = nil

	us := posture.ToIDPPosture().UserSecurity
	if us != nil {
		t.Fatalf("user security = %+v, want it left out", us)
	}
}

// The password policy stays in the detailed artifact. The idp-posture schema
// has no password policy fields.
func TestToIDPPostureLeavesOutThePasswordPolicy(t *testing.T) {
	raw, err := json.Marshal(postureWithCounts(componentsdk.LevelAudit).ToIDPPosture())
	if err != nil {
		t.Fatal(err)
	}
	for _, key := range []string{"minimum_password_length", "password_strength_required", "password_policy_enforced_for_existing_users"} {
		if strings.Contains(string(raw), key) {
			t.Fatalf("normalized posture = %s, want no %q", raw, key)
		}
	}
}

func TestArtifactPathsAreTheSDKPaths(t *testing.T) {
	if want := componentsdk.ArtifactPath(collectorName, ""); detailedPath != want {
		t.Errorf("detailedPath = %q, want %q", detailedPath, want)
	}
	if want := componentsdk.ArtifactPath(collectorName, idpSchema); idpPosturePath != want {
		t.Errorf("idpPosturePath = %q, want %q", idpPosturePath, want)
	}
}

// A delegated admin's role makes them privileged only with a privilege that
// can change users, groups, org units, security, or settings.
func TestWritePrivilege(t *testing.T) {
	for name, want := range map[string]bool{
		"SUPER_ADMIN":                  true,
		"USERS_ALL":                    true,
		"USERS_UPDATE":                 true,
		"USERS_RESET_PASSWORD":         true,
		"GROUPS_ALL":                   true,
		"CHANGE_USER_GROUP_MEMBERSHIP": true,
		"ORGANIZATION_UNITS_UPDATE":    true,
		"USER_SECURITY_ALL":            true,
		"MANAGE_USER_SETTINGS":         true,
		"USERS_RETRIEVE":               false,
		"GROUPS_RETRIEVE":              false,
		"ORGANIZATION_UNITS_RETRIEVE":  false,
		"REPORTS_ACCESS":               false,
	} {
		if got := writePrivilege(name); got != want {
			t.Errorf("writePrivilege(%s) = %v, want %v", name, got, want)
		}
	}
}

// A super admin is privileged. A delegated admin is privileged when a role
// assigned to them holds a write privilege. Without the role assignments,
// whether a delegated admin is privileged is unknown.
func TestCountPrivileged(t *testing.T) {
	admins := []adminUser{
		{id: "super", super: true, enrolled: true},
		{id: "editor", enrolled: true},
		{id: "reader"},
	}
	roles := adminRoles{
		byID: map[string]googleworkspace.Role{
			"edit": {ID: "edit", Privileges: []string{"USERS_RETRIEVE", "GROUPS_ALL"}},
			"read": {ID: "read", Privileges: []string{"USERS_RETRIEVE", "GROUPS_RETRIEVE"}},
		},
		assignments: map[string][]googleworkspace.RoleAssignment{
			"editor": {{RoleID: "edit"}},
			"reader": {{RoleID: "read"}},
		},
	}
	privileged, enrolled, unread := countPrivileged(admins, roles)
	if privileged == nil || *privileged != 2 || enrolled == nil || *enrolled != 2 || unread != 0 {
		t.Errorf("countPrivileged = %s, %s, %d; want 2, 2, 0", showPtr(privileged), showPtr(enrolled), unread)
	}
	privileged, enrolled, unread = countPrivileged(admins, adminRoles{assignmentsErr: errors.New("refused")})
	if privileged != nil || enrolled != nil || unread != 2 {
		t.Errorf("without assignments: countPrivileged = %s, %s, %d; want nil, nil, 2", showPtr(privileged), showPtr(enrolled), unread)
	}
	privileged, _, _ = countPrivileged(admins[:1], adminRoles{})
	if privileged == nil || *privileged != 1 {
		t.Errorf("super admin alone: countPrivileged = %s, want 1", showPtr(privileged))
	}
}

// The identity providers named are those a SAML_SSO assignment sends users
// to, by the profile's display name and entity ID, and the domain-wide
// profile. An assignment with SSO off names none.
func TestSAMLProviders(t *testing.T) {
	profiles := []googleworkspace.SAMLProfile{{Name: "inboundSamlSsoProfiles/abc", DisplayName: "Okta", IdpEntityID: "https://idp.example.com/entity"}}
	got := samlProviders(profiles, []googleworkspace.SSOAssignment{
		{SSOMode: "SSO_OFF", TargetOrgUnit: "orgUnits/root"},
		{SSOMode: "SAML_SSO", Profile: "inboundSamlSsoProfiles/abc", TargetOrgUnit: "orgUnits/1"},
		{SSOMode: "SAML_SSO", Profile: "inboundSamlSsoProfiles/abc", TargetGroup: "groups/2"},
		{SSOMode: "DOMAIN_WIDE_SAML_IF_ENABLED", TargetOrgUnit: "orgUnits/3"},
	})
	want := []string{"Okta (https://idp.example.com/entity)", "the domain-wide SSO profile"}
	if !slices.Equal(got, want) {
		t.Errorf("samlProviders = %q, want %q", got, want)
	}
	if got := samlProviders(profiles, []googleworkspace.SSOAssignment{{SSOMode: "SSO_OFF"}}); len(got) != 0 {
		t.Errorf("samlProviders with SSO off = %q, want none", got)
	}
}

// When the roles can't be read and no delegated admin needs them, the
// privileged values are written from the super admins, with no gap.
func TestRolesUnreadWithoutDelegatedAdmins(t *testing.T) {
	client := &mockClient{
		users:    []googleworkspace.User{{ID: "u1", PrimaryEmail: "admin@example.com", IsAdmin: true, IsEnrolledIn2Sv: true}},
		rolesErr: errors.New("refused"),
	}
	rec := &componentsdk.Recorder{}
	c := NewWithClient(Config{AdminEmail: "admin@example.com", Recorder: rec}, client)
	posture, err := c.Collect(t.Context(), componentsdk.LevelAudit)
	if err != nil {
		t.Fatal(err)
	}
	posture.OrgDomain = strPtr("example.com")
	pa := posture.ToIDPPosture().PrivilegedAccess
	c.recordIDPPostureGaps(posture, componentsdk.LevelAudit)
	wantInt(t, "PrivilegedUsersCount", pa.PrivilegedUsersCount, 1)
	for _, g := range rec.Gaps() {
		if g.Path == idpPosturePath && (strings.HasPrefix(g.Pointer, "/privileged_access/privileged_users") || strings.HasPrefix(g.Pointer, "/privileged_access/privileged_mfa")) {
			t.Errorf("gap %+v on a privileged value that is written", g)
		}
	}
}
