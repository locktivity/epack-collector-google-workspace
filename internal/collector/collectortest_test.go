package collector

import (
	"encoding/json"
	"net/http"
	"net/url"
	"testing"
	"time"

	"github.com/locktivity/epack-collector-google-workspace/internal/googleworkspace"
	"github.com/locktivity/epack/componentsdk"
	"github.com/locktivity/epack/componentsdk/collectortest"
)

var kitOperations = []string{
	googleworkspace.OpToken,
	googleworkspace.OpCustomersGet,
	googleworkspace.OpUsageReportGet,
	googleworkspace.OpUsersList,
	googleworkspace.OpRolesList,
	googleworkspace.OpRoleAssignmentsList,
	googleworkspace.OpAccessEventsList,
	googleworkspace.OpAccessPoliciesList,
	googleworkspace.OpAccessLevelsList,
	googleworkspace.OpGroupsList,
	googleworkspace.OpGroupSettingsGet,
	googleworkspace.OpMembersList,
	googleworkspace.OpOrgUnitsList,
	googleworkspace.OpMobileDevicesList,
	googleworkspace.OpChromeOSDevicesList,
	googleworkspace.OpActivitiesList,
	googleworkspace.OpDomainsList,
	googleworkspace.OpSAMLProfilesList,
	googleworkspace.OpPoliciesList,
	googleworkspace.OpVaultMattersList,
	googleworkspace.OpVaultHoldsList,
}

func kitConfig() map[string]any {
	return map[string]any{
		"admin_email":     kitAdminEmail,
		"organization_id": kitOrganizationID,
		"level":           "internal",
	}
}

func kitSecrets() map[string]string {
	return map[string]string{"GOOGLE_SERVICE_ACCOUNT_JSON": kitKeyJSON()}
}

// emptyList declares that a Cloud API's {} is its empty list: Cloud Identity,
// Access Context Manager, and Vault leave an empty list out of the answer.
// positions limits expect to faults at those positions, as Semantic's
// Positions does.
func emptyList(op, meaning string, expect map[string]any, positions ...string) collectortest.Semantic {
	return collectortest.Semantic{
		Operation: op,
		Fault:     "empty-object",
		Meaning:   meaning,
		Expect:    map[string]map[string]any{detailedPath: expect},
		Positions: positions,
	}
}

// runKitTenant runs the collector at the internal level over the tenant's
// canned responses and returns the detailed artifact.
func runKitTenant(t *testing.T, tenant kitTenant) OrgPosture {
	t.Helper()
	replay, err := collectortest.NewReplay(collectortest.Scenario{Name: t.Name(), Responses: tenant.responses()})
	if err != nil {
		t.Fatal(err)
	}
	res := componentsdk.RunInProcess(Spec("test", "collectortest"), Run, componentsdk.InProcessOptions{
		Config:    kitConfig(),
		Secrets:   kitSecrets(),
		Transport: replay,
		Clock:     func() time.Time { return kitNow },
	})
	if res.ExitCode != 0 {
		t.Fatalf("run failed with exit %d: %s", res.ExitCode, res.Stderr)
	}
	for _, artifact := range res.Artifacts {
		if artifact.Path != detailedPath {
			continue
		}
		var posture OrgPosture
		if err := json.Unmarshal(artifact.Data, &posture); err != nil {
			t.Fatal(err)
		}
		return posture
	}
	t.Fatalf("the run wrote no %s", detailedPath)
	return OrgPosture{}
}

func kitSuite() collectortest.Suite {
	return collectortest.Suite{
		Spec:    Spec("test", "collectortest"),
		Run:     Run,
		Config:  kitConfig(),
		Secrets: kitSecrets(),
		Clock:   kitNow,
		Scenarios: []collectortest.Scenario{
			{
				Name:      "clean",
				Responses: cleanTenant().withCustomerKey(),
				// The normalized percentages are whole numbers, rounded down
				// where more is better and up where more is worse.
				Expect: map[string]map[string]any{idpPosturePath: {
					"/user_security/users_present":                true,
					"/user_security/user_count":                   6,
					"/user_security/inactive_pct":                 34,
					"/user_security/weak_password_pct":            13,
					"/policy/mfa_required_coverage_pct":           33,
					"/privileged_access/privileged_users_present": true,
					"/lifecycle/account_count":                    8,
					"/policy/minimum_password_length":             collectortest.Absent,
					"/app_security/sso_coverage_pct":              collectortest.Absent,
					"/policy/session_lifetime_max_min":            20160,
					"/policy/legacy_auth_blocked":                 collectortest.Absent,
				}},
			},
			{
				Name:          "token rejected",
				ExpectFailure: componentsdk.CodeAuthFailed,
				Responses: []collectortest.Response{{
					Method: http.MethodPost,
					URL:    kitTokenURL,
					Status: http.StatusBadRequest,
					Body:   `{"error":"invalid_grant","error_description":"Invalid JWT Signature."}`,
				}},
			},
			{
				Name:      "empty tenant",
				Responses: emptyTenant().responses(),
				Expect: map[string]map[string]any{detailedPath: {
					"/usage_report_date":                    nil,
					"/users/total":                          nil,
					"/users/active":                         1,
					"/groups/total":                         0,
					"/vault/matters_count":                  0,
					"/device_access/access_context_manager": nil,
					"/sign_in":                              nil,
				}},
			},
			{
				Name:      "usage report behind the Directory",
				Responses: reportLagTenant().responses(),
				Expect: map[string]map[string]any{
					detailedPath: {
						"/usage_report_date":                "2026-04-07",
						"/users/active":                     7,
						"/authentication/2sv_enrolled_pct":  100,
						"/authentication/2sv_enforced_pct":  100,
						"/authentication/2sv_protected_pct": 85.71,
						"/activity/active_7d_pct":           100,
					},
					idpPosturePath: {
						"/policy/mfa_required":              true,
						"/policy/mfa_required_coverage_pct": 100,
					},
				},
			},
			{
				Name:      "session controls refused for a token without the scope",
				Responses: sessionScopeDeniedTenant().withCustomerKey(),
				Expect: map[string]map[string]any{
					detailedPath:   {"/sign_in/web_session_duration_max_minutes": collectortest.Absent, "/sign_in/less_secure_apps_allowed": true},
					idpPosturePath: {"/policy/session_lifetime_max_min": collectortest.Absent, "/policy/legacy_auth_blocked": collectortest.Absent},
				},
			},
			{
				Name:      "session controls policy without a length",
				Responses: sessionWithoutLengthTenant().withCustomerKey(),
				Expect: map[string]map[string]any{
					idpPosturePath: {"/policy/session_lifetime_max_min": collectortest.Absent},
				},
			},
			{
				Name:      "less secure apps blocked everywhere",
				Responses: lessSecureAppsBlockedTenant().withCustomerKey(),
				Expect: map[string]map[string]any{
					detailedPath:   {"/sign_in/less_secure_apps_allowed": false},
					idpPosturePath: {"/policy/legacy_auth_blocked": collectortest.Absent, "/policy/session_lifetime_max_min": 20160},
				},
			},
			{
				Name:      "delegated admin cannot read the tenant record",
				Responses: delegatedAdminTenant().responses(),
				Expect: map[string]map[string]any{detailedPath: {
					"/customer_id": nil,
					"/org_domain":  nil,
					"/drive_external_sharing/external_share_events": nil,
					"/users/active":                    6,
					"/authentication/2sv_enrolled_pct": 66.67,
					"/admins/privileged_users_count":   2,
					"/passwords/policy/minimum_length": 12,
				}},
			},
		},
		Required: []string{googleworkspace.OpToken},
		Semantics: []collectortest.Semantic{
			{
				Operation: googleworkspace.OpVaultMattersList,
				Fault:     "404",
				Meaning:   "the tenant's edition does not include Vault",
				Expect: map[string]map[string]any{detailedPath: {
					"/vault/licensed":      false,
					"/vault/matters_count": nil,
					"/vault/holds_count":   nil,
				}},
			},
			{
				Operation: googleworkspace.OpPoliciesList,
				Fault:     "404",
				Meaning:   "the tenant's edition does not include the Policy API",
				Expect:    map[string]map[string]any{detailedPath: {"/passwords/policy": nil, "/sign_in": nil}},
				Positions: []string{collectortest.PositionAll},
			},
			emptyList(googleworkspace.OpSAMLProfilesList, "no SAML profile is configured", map[string]any{
				"/domain_settings/sso_configured": false, "/domain_settings/saml_profile_count": 0,
			}),
			emptyList(googleworkspace.OpPoliciesList, "the Policy API returns no policy of the setting type asked for", map[string]any{
				"/passwords/policy": nil, "/sign_in": nil,
			}, collectortest.PositionAll),
			emptyList(googleworkspace.OpAccessPoliciesList, "the organization has no access policy", map[string]any{
				"/device_access/access_context_manager": nil,
			}),
			emptyList(googleworkspace.OpAccessLevelsList, "the access policy has no access levels", map[string]any{
				"/device_access/access_context_manager/basic_access_levels_count":  0,
				"/device_access/access_context_manager/custom_access_levels_count": 0,
			}),
			emptyList(googleworkspace.OpVaultMattersList, "the tenant has no Vault matters", map[string]any{
				"/vault/matters_count": 0, "/vault/holds_count": 0,
			}),
			emptyList(googleworkspace.OpVaultHoldsList, "the matter has no holds", map[string]any{
				"/vault/holds_count": 0, "/vault/matters/0/hold_count": 0,
			}),
		},
		Ignore: map[string][]string{
			detailedPath: {"/diagnostics"},
		},
		Operations:  kitOperations,
		Insensitive: []string{googleworkspace.OpToken},
		Faults: []collectortest.Fault{
			collectortest.StatusFault("403-rate-limited-once", http.StatusForbidden, nil, kitRateLimited, "", true),
			collectortest.StatusFault("403-rate-limited", http.StatusForbidden, nil, kitRateLimited, componentsdk.CodeRateLimited, false),
		},
	}
}

func TestCollectorKit(t *testing.T) {
	collectortest.Run(t, kitSuite())
}

// The OIDC mode's sign-in: the runner's identity token, its exchange at
// Google's Security Token Service, impersonating the service account, and a
// signed delegation assertion exchanged for each scope's token.
const (
	kitGitHubTokenURL      = "https://pipelines.actions.githubusercontent.test/abc/_apis/idtoken?api-version=2.0"
	kitRunnerRequestToken  = "kit-runner-request-token-0123456789"
	kitIdentityProvider    = "projects/123/locations/global/workloadIdentityPools/epack/providers/github"
	kitServiceAccountsPath = "https://iamcredentials.googleapis.com/v1/projects/-/serviceAccounts/" + kitServiceAccount
)

func oidcTokenResponses() []collectortest.Response {
	audience := "//iam.googleapis.com/" + kitIdentityProvider
	return []collectortest.Response{
		get(kitGitHubTokenURL+"&audience="+url.QueryEscape(audience), `{"value":"kit-runner-identity-token"}`),
		{Method: http.MethodPost, URL: "https://sts.googleapis.com/v1/token", Body: `{"access_token":"kit-federated-token","issued_token_type":"urn:ietf:params:oauth:token-type:access_token","token_type":"Bearer","expires_in":3600}`},
		{Method: http.MethodPost, URL: kitServiceAccountsPath + ":generateAccessToken", Body: `{"accessToken":"kit-service-account-token","expireTime":"2099-01-01T00:00:00Z"}`},
		{Method: http.MethodPost, URL: kitServiceAccountsPath + ":signJwt?alt=json&prettyPrint=false", Body: `{"keyId":"kit-key","signedJwt":"kit-signed-assertion"}`},
	}
}

func oidcSuite() collectortest.Suite {
	s := kitSuite()
	s.Config = map[string]any{
		"admin_email":                kitAdminEmail,
		"auth_mode":                  "oidc",
		"workload_identity_provider": kitIdentityProvider,
		"service_account":            kitServiceAccount,
		"level":                      "trust",
	}
	s.Secrets = map[string]string{"ACTIONS_ID_TOKEN_REQUEST_TOKEN": kitRunnerRequestToken}
	s.Scenarios = []collectortest.Scenario{
		{Name: "clean", Responses: append(oidcTokenResponses(), cleanTenant().withCustomerKey()...)},
		{
			Name:          "runner identity rejected",
			ExpectFailure: componentsdk.CodeAuthFailed,
			Responses: append(oidcTokenResponses()[:1], collectortest.Response{
				Method: http.MethodPost,
				URL:    "https://sts.googleapis.com/v1/token",
				Status: http.StatusBadRequest,
				Body:   `{"error":"invalid_grant","error_description":"The given credential is rejected by the attribute condition."}`,
			}),
		},
	}
	tokenOps := []string{
		googleworkspace.OpGitHubIDToken, googleworkspace.OpSTSToken, googleworkspace.OpImpersonate,
		googleworkspace.OpSignJWT, googleworkspace.OpToken,
	}
	s.Required = tokenOps
	s.Insensitive = tokenOps
	s.Operations = append(append([]string(nil), tokenOps...),
		googleworkspace.OpCustomersGet, googleworkspace.OpUsageReportGet, googleworkspace.OpUsersList,
		googleworkspace.OpAccessEventsList, googleworkspace.OpPoliciesList,
	)
	s.Faults = nil
	return s
}

func TestCollectorKitOIDC(t *testing.T) {
	t.Setenv("ACTIONS_ID_TOKEN_REQUEST_URL", kitGitHubTokenURL)
	t.Setenv("ACTIONS_ID_TOKEN_REQUEST_TOKEN", kitRunnerRequestToken)
	collectortest.Run(t, oidcSuite())
}

func TestRejectedKeyFailsTheRunWithAuthFailed(t *testing.T) {
	replay, err := collectortest.NewReplay(collectortest.Scenario{
		Name: "token rejected",
		Responses: []collectortest.Response{{
			Method: http.MethodPost,
			URL:    kitTokenURL,
			Status: http.StatusBadRequest,
			Body:   `{"error":"invalid_grant","error_description":"Invalid JWT Signature."}`,
		}},
	})
	if err != nil {
		t.Fatal(err)
	}
	res := componentsdk.RunInProcess(Spec("test", "collectortest"), Run, componentsdk.InProcessOptions{
		Config:    kitConfig(),
		Secrets:   kitSecrets(),
		Transport: replay,
	})
	if res.ExitCode != 3 || res.Failure == nil || res.Failure.Code != componentsdk.CodeAuthFailed {
		t.Fatalf("exit %d, failure %+v; want exit 3 with auth_failed", res.ExitCode, res.Failure)
	}
	if len(res.Artifacts) != 0 {
		t.Fatalf("a failed sign-in emitted %d artifacts, want none", len(res.Artifacts))
	}
	if unmatched := replay.Unmatched(); len(unmatched) > 0 {
		t.Fatalf("a failed sign-in went on to call %v", unmatched)
	}
}
