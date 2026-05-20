//go:build e2e
// +build e2e

// End-to-end tests that make real requests to the Google Workspace APIs.
//
// Run with:
//
//	go test -tags=e2e -v ./internal/collector/...
//
// Required environment variables:
//
//	GOOGLE_SERVICE_ACCOUNT_JSON    full JSON of a service-account key with
//	                               domain-wide delegation configured
//	GOOGLE_WORKSPACE_E2E_ADMIN_EMAIL  a Workspace admin the service account
//	                                  impersonates
//
// Optional environment variables:
//
//	GOOGLE_WORKSPACE_E2E_LEVEL            trust | audit | internal (default trust)
//	GOOGLE_WORKSPACE_E2E_CUSTOMER         customer key (default my_customer)
//	GOOGLE_WORKSPACE_E2E_ORGANIZATION_ID  GCP org ID for Access Context Manager
//	GOOGLE_WORKSPACE_E2E_ACCESS_POLICY    Access Context Manager policy
//
// The collection level only controls how much is gathered; surfaces whose
// scopes (or Cloud-project APIs) are ungranted degrade with diagnostics rather
// than failing the run, so these tests pass against a tenant with any scope set.

package collector

import (
	"context"
	"encoding/json"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/locktivity/epack/componentsdk"
)

// e2eLevel selects which collection level the suite runs at. Defaults to
// LevelTrust; override with GOOGLE_WORKSPACE_E2E_LEVEL=audit|internal to
// exercise the gated surfaces against a sandbox tenant.
func e2eLevel() componentsdk.Level {
	switch strings.ToLower(strings.TrimSpace(os.Getenv("GOOGLE_WORKSPACE_E2E_LEVEL"))) {
	case "audit":
		return componentsdk.LevelAudit
	case "internal":
		return componentsdk.LevelInternal
	default:
		return componentsdk.LevelTrust
	}
}

func getE2EConfig(t *testing.T) Config {
	t.Helper()

	creds := os.Getenv("GOOGLE_SERVICE_ACCOUNT_JSON")
	adminEmail := strings.TrimSpace(os.Getenv("GOOGLE_WORKSPACE_E2E_ADMIN_EMAIL"))
	if creds == "" || adminEmail == "" {
		t.Skip("Skipping e2e: GOOGLE_SERVICE_ACCOUNT_JSON and GOOGLE_WORKSPACE_E2E_ADMIN_EMAIL required")
	}

	return Config{
		AdminEmail:      adminEmail,
		CredentialsJSON: creds,
		Customer:        strings.TrimSpace(os.Getenv("GOOGLE_WORKSPACE_E2E_CUSTOMER")),
		OrganizationID:  strings.TrimSpace(os.Getenv("GOOGLE_WORKSPACE_E2E_ORGANIZATION_ID")),
		AccessPolicy:    strings.TrimSpace(os.Getenv("GOOGLE_WORKSPACE_E2E_ACCESS_POLICY")),
	}
}

func collectE2E(t *testing.T, level componentsdk.Level) *OrgPosture {
	t.Helper()
	config := getE2EConfig(t)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	c, err := New(ctx, config)
	if err != nil {
		t.Fatalf("New() error: %v", err)
	}

	posture, err := c.Collect(ctx, level)
	if err != nil {
		t.Fatalf("Collect(%s) error: %v", level, err)
	}
	return posture
}

func TestE2E_RealGoogleWorkspaceCollection(t *testing.T) {
	level := e2eLevel()
	posture := collectE2E(t, level)

	if posture.SchemaVersion != SchemaVersion {
		t.Errorf("schema_version = %q, want %q", posture.SchemaVersion, SchemaVersion)
	}
	if posture.Provider != "google-workspace" {
		t.Errorf("provider = %q, want google-workspace", posture.Provider)
	}
	if posture.CollectedAtLevel != string(level) {
		t.Errorf("collected_at_level = %q, want %q", posture.CollectedAtLevel, level)
	}
	if _, err := time.Parse(time.RFC3339, posture.CollectedAt); err != nil {
		t.Errorf("collected_at %q is not RFC3339: %v", posture.CollectedAt, err)
	}
	if posture.OrgDomain == "" {
		t.Error("org_domain should not be empty")
	}
	if posture.CustomerID == "" {
		t.Error("customer_id should not be empty")
	}

	assertPercentFloat(t, "users.locked_pct", posture.Users.LockedPct)
	assertPercentFloat(t, "users.inactive_pct", posture.Users.InactivePct)
	assertPercentFloat(t, "activity.active_7d_pct", posture.Activity.Active7dPct)
	assertPercentFloat(t, "activity.active_30d_pct", posture.Activity.Active30dPct)
	assertPercentFloat(t, "authentication.2sv_enrolled_pct", posture.Authentication.TwoSVEnrolledPct)
	assertPercentFloat(t, "authentication.2sv_enforced_pct", posture.Authentication.TwoSVEnforcedPct)
	assertPercentFloat(t, "authentication.2sv_protected_pct", posture.Authentication.TwoSVProtectedPct)
	assertPercentFloat(t, "authentication.passkey_users_pct", posture.Authentication.PasskeyUsersPct)
	assertPercentFloat(t, "passwords.weak_password_pct", posture.Passwords.WeakPasswordPct)
	assertPercentFloat(t, "admins.privileged_users_2sv_enforced_pct", posture.Admins.PrivilegedUsers2SVEnforcedPct)

	data, _ := json.MarshalIndent(posture, "", "  ")
	t.Logf("collection complete at level=%s org=%s\n%s", level, posture.OrgDomain, string(data))
}

func TestE2E_OutputValidJSON(t *testing.T) {
	posture := collectE2E(t, e2eLevel())

	data, err := json.Marshal(posture)
	if err != nil {
		t.Fatalf("marshal error: %v", err)
	}
	var decoded map[string]any
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("output is not valid JSON: %v", err)
	}

	for _, field := range []string{
		"schema_version", "collected_at", "collected_at_level", "provider",
		"org_domain", "customer_id", "users", "activity", "authentication",
		"admins", "passwords", "apps",
	} {
		if _, ok := decoded[field]; !ok {
			t.Errorf("missing required top-level field: %s", field)
		}
	}
}

// TestE2E_NeverEmitsForbiddenData runs at internal (the deepest level) and
// verifies on real data that the privacy invariants hold: Drive external-share
// recipients appear as a domain only, and no device serial / IMEI, Vault search
// query, or full SSO URL ever lands in the artifact.
func TestE2E_NeverEmitsForbiddenData(t *testing.T) {
	posture := collectE2E(t, componentsdk.LevelInternal)

	if posture.DriveExternalSharing != nil {
		for _, ev := range posture.DriveExternalSharing.Events {
			if strings.Contains(ev.RecipientDomain, "@") {
				t.Errorf("drive external-sharing recipient_domain leaked an email address: %q", ev.RecipientDomain)
			}
		}
	}
	if posture.DomainSettings != nil {
		for _, p := range posture.DomainSettings.SAMLProfiles {
			if strings.Contains(p.SSOServiceHost, "://") || strings.Contains(p.SSOServiceHost, "?") {
				t.Errorf("sso_service_host should be host-only, got %q", p.SSOServiceHost)
			}
		}
	}

	data, _ := json.Marshal(posture)
	raw := strings.ToLower(string(data))
	for _, forbidden := range []string{`"serial"`, `"imei"`, `"meid"`, `"query"`, `"search_query"`, `"hold_content"`} {
		if strings.Contains(raw, forbidden) {
			t.Errorf("artifact contains forbidden key %s", forbidden)
		}
	}
}

func assertPercentFloat(t *testing.T, name string, v float64) {
	t.Helper()
	if v < 0 || v > 100 {
		t.Errorf("%s should be in [0,100], got %v", name, v)
	}
}
