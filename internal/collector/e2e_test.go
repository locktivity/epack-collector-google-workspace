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
// scopes (or Cloud-project APIs) are ungranted are left out with a gap rather
// than failing the run, so these tests pass against a tenant with any scope set.

package collector

import (
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

// collectE2E runs the collector the way a runner does, against the real
// APIs, and returns the detailed artifact as JSON.
func collectE2E(t *testing.T, level componentsdk.Level) []byte {
	t.Helper()

	creds := os.Getenv("GOOGLE_SERVICE_ACCOUNT_JSON")
	adminEmail := strings.TrimSpace(os.Getenv("GOOGLE_WORKSPACE_E2E_ADMIN_EMAIL"))
	if creds == "" || adminEmail == "" {
		t.Skip("Skipping e2e: GOOGLE_SERVICE_ACCOUNT_JSON and GOOGLE_WORKSPACE_E2E_ADMIN_EMAIL required")
	}

	config := map[string]any{"admin_email": adminEmail, "level": string(level)}
	for key, env := range map[string]string{
		"customer":        "GOOGLE_WORKSPACE_E2E_CUSTOMER",
		"organization_id": "GOOGLE_WORKSPACE_E2E_ORGANIZATION_ID",
		"access_policy":   "GOOGLE_WORKSPACE_E2E_ACCESS_POLICY",
	} {
		if v := strings.TrimSpace(os.Getenv(env)); v != "" {
			config[key] = v
		}
	}

	res := componentsdk.RunInProcess(Spec("e2e", "e2e"), Run, componentsdk.InProcessOptions{
		Config:  config,
		Secrets: map[string]string{"GOOGLE_SERVICE_ACCOUNT_JSON": creds},
	})
	if res.ExitCode != 0 {
		t.Fatalf("run failed with exit %d: %s", res.ExitCode, res.Stderr)
	}
	if res.Result != nil {
		for _, gap := range res.Result.Gaps {
			t.Logf("gap: %s %s %s (%s)", gap.Path, gap.Pointer, gap.Code, gap.VendorCode)
		}
		for _, check := range res.Result.Checks {
			t.Errorf("output check %s at %s %s: %s", check.Check, check.Path, check.Pointer, check.Message)
		}
	}
	for _, artifact := range res.Artifacts {
		if artifact.Path == detailedPath {
			return artifact.Data
		}
	}
	t.Fatalf("no %s in the output", detailedPath)
	return nil
}

func TestE2E_RealGoogleWorkspaceCollection(t *testing.T) {
	level := e2eLevel()
	raw := collectE2E(t, level)

	var posture OrgPosture
	if err := json.Unmarshal(raw, &posture); err != nil {
		t.Fatalf("decoding artifact: %v", err)
	}
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
	if posture.OrgDomain == nil || *posture.OrgDomain == "" {
		t.Error("org_domain should be read for a Super Admin")
	}

	assertPercentFloat(t, "users.locked_pct", posture.Users.LockedPct)
	assertPercentFloat(t, "users.inactive_pct", posture.Users.InactivePct)
	if posture.Activity != nil {
		assertPercentFloat(t, "activity.active_7d_pct", posture.Activity.Active7dPct)
		assertPercentFloat(t, "activity.active_30d_pct", posture.Activity.Active30dPct)
	}
	assertPercentFloat(t, "authentication.2sv_enrolled_pct", posture.Authentication.TwoSVEnrolledPct)
	assertPercentFloat(t, "authentication.2sv_enforced_pct", posture.Authentication.TwoSVEnforcedPct)
	assertPercentFloat(t, "authentication.2sv_protected_pct", posture.Authentication.TwoSVProtectedPct)
	assertPercentFloat(t, "authentication.passkey_users_pct", posture.Authentication.PasskeyUsersPct)
	assertPercentFloat(t, "passwords.weak_password_pct", posture.Passwords.WeakPasswordPct)
	assertPercentFloat(t, "admins.privileged_users_2sv_enforced_pct", posture.Admins.PrivilegedUsers2SVEnforcedPct)

	t.Logf("collection complete at level=%s\n%s", level, raw)
}

func TestE2E_OutputValidJSON(t *testing.T) {
	level := e2eLevel()
	raw := collectE2E(t, level)

	var decoded map[string]any
	if err := json.Unmarshal(raw, &decoded); err != nil {
		t.Fatalf("output is not valid JSON: %v", err)
	}

	for _, field := range []string{
		"schema_version", "collected_at", "collected_at_level", "usage_report_date",
		"provider", "org_domain", "users", "authentication",
		"admins", "passwords",
	} {
		if _, ok := decoded[field]; !ok {
			t.Errorf("missing required top-level field: %s", field)
		}
	}
	if _, ok := decoded["customer_id"]; ok != level.AtLeast(componentsdk.LevelAudit) {
		t.Errorf("customer_id written = %v at %s, want it from the audit level only", ok, level)
	}
}

// TestE2E_NeverEmitsForbiddenData runs at internal (the deepest level) and
// verifies on real data that the privacy invariants hold: Drive external-share
// recipients appear as a domain only, and no device serial / IMEI, Vault search
// query, or full SSO URL ever lands in the artifact.
func TestE2E_NeverEmitsForbiddenData(t *testing.T) {
	raw := collectE2E(t, componentsdk.LevelInternal)

	var posture OrgPosture
	if err := json.Unmarshal(raw, &posture); err != nil {
		t.Fatalf("decoding artifact: %v", err)
	}
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

	lower := strings.ToLower(string(raw))
	for _, forbidden := range []string{`"serial"`, `"imei"`, `"meid"`, `"query"`, `"search_query"`, `"hold_content"`} {
		if strings.Contains(lower, forbidden) {
			t.Errorf("artifact contains forbidden key %s", forbidden)
		}
	}
}

func assertPercentFloat(t *testing.T, name string, v *float64) {
	t.Helper()
	if v != nil && (*v < 0 || *v > 100) {
		t.Errorf("%s should be in [0,100], got %v", name, *v)
	}
}
