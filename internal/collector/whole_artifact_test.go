package collector

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/locktivity/epack-collector-google-workspace/internal/googleworkspace"
	"github.com/locktivity/epack/componentsdk"
)

// These are whole-artifact contract tests: they drive a single Collect against
// a fully-populated mock client and assert properties of the assembled artifact
// that no per-surface test can (the per-level field boundary and the
// never-emit-forbidden-data guarantees across every surface at once). They stop
// at the googleworkspace.Client seam, so they are not end-to-end; the real
// against-Google tests live in e2e_test.go behind the `e2e` build tag.

// fullyPopulatedClient returns a mock with data on every surface, so the
// per-level boundary can be asserted across the whole artifact.
func fullyPopulatedClient(now time.Time) *mockClient {
	recent := now.AddDate(0, 0, -2)
	return &mockClient{
		customer:    googleworkspace.Customer{ID: "C123", PrimaryDomain: "example.com"},
		usageReport: googleworkspace.CustomerUsageReport{NumUsers: 3, NumAuthorizedApps: 5},
		users: []googleworkspace.User{
			{ID: "u1", PrimaryEmail: "super@example.com", OrgUnitPath: "/Eng", IsAdmin: true, IsEnrolledIn2Sv: true, IsEnforcedIn2Sv: true, LastLoginTime: now},
			{ID: "u2", PrimaryEmail: "user@example.com", OrgUnitPath: "/Eng", LastLoginTime: now},
		},
		roles:           []googleworkspace.Role{{ID: "1", Name: "_SEED_ADMIN_ROLE", IsSystem: true}, {ID: "2", Name: "Custom", PrivilegeCount: 2}},
		roleAssignments: []googleworkspace.RoleAssignment{{AssignedTo: "u1", RoleID: "1", ScopeType: "CUSTOMER"}},
		orgUnits:        []googleworkspace.OrgUnit{{Path: "/Eng", ParentPath: "/", BlockInheritance: true}},
		groups:          []googleworkspace.Group{{Email: "g@example.com", Name: "G", DirectMembersCount: 2, AdminCreated: true}},
		groupSettings:   map[string]googleworkspace.GroupSettings{"g@example.com": {AllowExternalMembers: true, WhoCanJoin: "INVITED_CAN_JOIN"}},
		groupMembers:    map[string][]googleworkspace.GroupMember{"g@example.com": {{Email: "user@example.com", Role: "MEMBER"}}},
		mobileDevices:   []googleworkspace.Device{{Platform: "MOBILE", OS: "ANDROID", OwnerEmail: "user@example.com", Compliant: true, Encrypted: true, LastSync: now}},
		samlProfiles:    []googleworkspace.SAMLProfile{{DisplayName: "Okta", IdpEntityID: "https://idp", SSOServiceURI: "https://idp.example.com/sso?x=1"}},
		domains:         []googleworkspace.Domain{{DomainName: "example.com", Verified: true, IsPrimary: true}},
		passwordPolicies: []googleworkspace.PasswordPolicy{
			{MinimumLength: 12, MaximumLength: 100, AllowedStrength: "STRONG", EnforceRequirementsAtLogin: true, ExpirationDays: 90},
			{MinimumLength: 8, MaximumLength: 64, AllowedStrength: "WEAK", AllowReuse: true},
		},
		vaultMatters: []googleworkspace.VaultMatter{{MatterID: "m1", Name: "Case", State: "OPEN"}},
		vaultHolds:   map[string][]googleworkspace.VaultHold{"m1": {{HoldID: "h1", MatterID: "m1", Corpus: "MAIL", AccountCount: 1}}},
		accessLevels: []googleworkspace.AccessLevel{
			{Name: "p/accessLevels/corp", Title: "Corp", HasDevicePolicy: true, IPSubnetworks: []string{"203.0.113.0/24"}},
		},
		contextAwareAccessEvents: []googleworkspace.ContextAwareAccessEvent{{UserEmail: "user@example.com", DeviceState: "Unmanaged"}},
		activitiesByApp: map[string][]googleworkspace.AuditEvent{
			"admin": {{Time: recent, ActorEmail: "super@example.com", Name: "SUSPEND_USER"}},
			"login": {{Time: recent, ActorEmail: "user@example.com", IPAddress: "203.0.113.9", Name: "suspicious_login"}},
			"drive": {{Time: recent, ActorEmail: "user@example.com", Name: "change_user_access", Parameters: map[string]string{"target_user": "x@vendor.com", "doc_id": "d1"}}},
			"token": {{Time: recent, ActorEmail: "user@example.com", Name: "authorize", Parameters: map[string]string{"client_id": "c", "app_name": "App"}, MultiParameters: map[string][]string{"scope": {"https://www.googleapis.com/auth/gmail.modify"}}}},
		},
	}
}

func collectJSON(t *testing.T, level componentsdk.Level) (*OrgPosture, string) {
	t.Helper()
	now := time.Date(2026, 4, 8, 12, 0, 0, 0, time.UTC)
	c := NewWithClient(Config{AdminEmail: "admin@example.com", AccessPolicy: "p", Now: func() time.Time { return now }}, fullyPopulatedClient(now))
	posture, err := c.Collect(context.Background(), level)
	if err != nil {
		t.Fatalf("Collect(%s) error = %v", level, err)
	}
	raw, err := json.Marshal(posture)
	if err != nil {
		t.Fatalf("marshal error = %v", err)
	}
	return posture, string(raw)
}

func TestWholeArtifact_ThreeLevelBoundary(t *testing.T) {
	// Keys that must never appear in trust output (audit / internal only).
	auditInternalKeys := []string{
		`"inventory"`, `"custom_roles"`, `"levels"`, `"admin_audit_log"`,
		`"login_audit_log"`, `"drive_external_sharing"`, `"compliant_by_os"`,
		`"saml_profiles"`, `"events"`, `"holds"`, `"matters"`, `"tokens"`,
		`"counts_by_app"`, `"counts_by_category"`,
		`"active_7d_pct"`, `"active_30d_pct"`,
		`"authorized_apps_count"`, `"oauth_tokens"`,
	}

	_, trustJSON := collectJSON(t, componentsdk.LevelTrust)
	if !strings.Contains(trustJSON, `"collected_at_level":"trust"`) {
		t.Fatalf("trust output missing collected_at_level stamp")
	}
	for _, key := range auditInternalKeys {
		if strings.Contains(trustJSON, key) {
			t.Fatalf("trust output leaked audit/internal key %s", key)
		}
	}

	auditPosture, _ := collectJSON(t, componentsdk.LevelAudit)
	if auditPosture.Users.Inventory == nil {
		t.Fatalf("audit output missing user inventory")
	}
	if auditPosture.AdminAuditLog == nil || auditPosture.AdminAuditLog.Events != nil {
		t.Fatalf("audit: admin audit-log present without event slice expected; got %+v", auditPosture.AdminAuditLog)
	}

	internalPosture, internalJSON := collectJSON(t, componentsdk.LevelInternal)
	if !strings.Contains(internalJSON, `"collected_at_level":"internal"`) {
		t.Fatalf("internal output missing collected_at_level stamp")
	}
	if internalPosture.AdminAuditLog.Events == nil {
		t.Fatalf("internal output missing admin audit-log event slice")
	}
	if internalPosture.Vault == nil || len(internalPosture.Vault.Holds) != 1 {
		t.Fatalf("internal output missing vault holds")
	}
	if len(internalPosture.DomainSettings.SAMLProfiles) != 1 || internalPosture.DomainSettings.SAMLProfiles[0].SSOServiceHost != "idp.example.com" {
		t.Fatalf("internal SSO host wrong: %+v", internalPosture.DomainSettings.SAMLProfiles)
	}
	// SSO host must never include the full URL or query string.
	if strings.Contains(internalJSON, "sso?x=1") || strings.Contains(internalJSON, "/sso") {
		t.Fatalf("internal output leaked full SSO URL")
	}
}

func TestWholeArtifact_NeverEmitsForbiddenData(t *testing.T) {
	_, internalJSON := collectJSON(t, componentsdk.LevelInternal)
	// The mock seeds an external Drive share to x@vendor.com; only the domain
	// may appear, never the full recipient address.
	if strings.Contains(internalJSON, "x@vendor.com") {
		t.Fatalf("internal output leaked a recipient email address")
	}
	if !strings.Contains(internalJSON, "vendor.com") {
		t.Fatalf("expected recipient domain vendor.com in the drive external-sharing slice")
	}
}
