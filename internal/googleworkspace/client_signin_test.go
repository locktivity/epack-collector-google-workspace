package googleworkspace

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"testing"

	"golang.org/x/oauth2"

	"github.com/locktivity/epack/componentsdk"
)

// policyServer answers the Policy API with policies, each of settingType and
// with the value given, and checks the filter names that setting type.
func policyServer(t *testing.T, settingType string, values ...map[string]any) func(http.ResponseWriter, *http.Request) {
	t.Helper()
	return func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/policies" {
			return
		}
		if got, want := r.URL.Query().Get("filter"), "setting.type.matches('^settings/"+settingType+"$') && customer == \"customers/C01abc23d\""; got != want {
			t.Fatalf("filter = %q, want %q", got, want)
		}
		policies := make([]map[string]any, 0, len(values))
		for _, value := range values {
			policies = append(policies, map[string]any{
				"name":        "policies/aaaaaaaa",
				"policyQuery": map[string]any{"orgUnit": "orgUnits/03ph8a2z1x9y7w6"},
				"setting":     map[string]any{"type": "settings/" + settingType, "value": value},
			})
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"policies": policies})
	}
}

func TestAPIClientListSessionPolicies(t *testing.T) {
	client := newTestClient(t, policyServer(t, "security.session_controls",
		map[string]any{"webSessionDuration": "1209600s"}, map[string]any{"webSessionDuration": "43200.5s"}))
	var got []SessionPolicy
	err := client.ListSessionPolicies(context.Background(), "C01abc23d", func(policies []SessionPolicy) error {
		got = append(got, policies...)
		return nil
	})
	if err != nil {
		t.Fatalf("ListSessionPolicies() error = %v", err)
	}
	if len(got) != 2 || got[0].WebSessionSeconds != 1209600 || got[1].WebSessionSeconds != 43200.5 {
		t.Fatalf("policies = %+v, want 1209600 and 43200.5 seconds", got)
	}
}

// A policy whose session length is missing has no length to read, so the
// read fails as an invalid response.
func TestAPIClientListSessionPoliciesRejectsAPolicyWithoutALength(t *testing.T) {
	for _, value := range []map[string]any{{}, {"webSessionDuration": "0s"}, {"webSessionDuration": "a day"}} {
		client := newTestClient(t, policyServer(t, "security.session_controls", value))
		err := client.ListSessionPolicies(context.Background(), "C01abc23d", func([]SessionPolicy) error { return nil })
		if code := componentsdk.Classify(err); code != componentsdk.CodeInvalidResponse {
			t.Errorf("value %v: error %v has code %q, want invalid_response", value, err, code)
		}
	}
}

// The JSON leaves out allowLessSecureApps when it is false.
func TestAPIClientListLessSecureAppsPolicies(t *testing.T) {
	client := newTestClient(t, policyServer(t, "security.less_secure_apps", map[string]any{}, map[string]any{"allowLessSecureApps": true}))
	var got []LessSecureAppsPolicy
	err := client.ListLessSecureAppsPolicies(context.Background(), "C01abc23d", func(policies []LessSecureAppsPolicy) error {
		got = append(got, policies...)
		return nil
	})
	if err != nil {
		t.Fatalf("ListLessSecureAppsPolicies() error = %v", err)
	}
	if len(got) != 2 || got[0].Allowed || !got[1].Allowed {
		t.Fatalf("policies = %+v, want the first to block and the second to allow", got)
	}
}

func TestNamesPermission(t *testing.T) {
	cases := []struct {
		name string
		body string
		want bool
	}{
		{"token without the scope", `{"error":{"code":403,"message":"Request had insufficient authentication scopes.","errors":[{"reason":"insufficientPermissions"}],"details":[{"@type":"type.googleapis.com/google.rpc.ErrorInfo","reason":"ACCESS_TOKEN_SCOPE_INSUFFICIENT"}]}}`, true},
		{"missing IAM permission", `{"error":{"code":403,"status":"PERMISSION_DENIED","details":[{"@type":"type.googleapis.com/google.rpc.ErrorInfo","reason":"IAM_PERMISSION_DENIED"}]}}`, true},
		{"admin role without the privilege", `{"error":{"code":403,"message":"Not Authorized to access this resource/api","errors":[{"reason":"forbidden"}]}}`, false},
		{"API turned off", `{"error":{"code":403,"errors":[{"reason":"accessNotConfigured"}],"details":[{"reason":"SERVICE_DISABLED"}]}}`, false},
		{"no body", ``, false},
	}
	for _, tc := range cases {
		if got := NamesPermission(nil, []byte(tc.body)); got != tc.want {
			t.Errorf("%s: NamesPermission = %t, want %t", tc.name, got, tc.want)
		}
	}
}

func TestEveryWorkspaceCallDeclaresItsPermission(t *testing.T) {
	ops := []string{
		OpCustomersGet, OpUsersList, OpRolesList, OpRoleAssignmentsList, OpUserAssignmentsList, OpGroupsList, OpMembersList,
		OpOrgUnitsList, OpMobileDevicesList, OpChromeOSDevicesList, OpDomainsList, OpUsageReportGet,
		OpActivitiesList, OpAccessEventsList, OpGroupSettingsGet, OpSAMLProfilesList, OpSSOAssignmentsList, OpPoliciesList,
		OpAccessPoliciesList, OpAccessLevelsList, OpVaultMattersList, OpVaultHoldsList, OpSignJWT, OpImpersonate,
	}
	for _, op := range ops {
		permission := Permission(op)
		if permission == "" || strings.ContainsAny(permission, " \t") {
			t.Errorf("%s declares %q, want one permission with no spaces", op, permission)
		}
	}
	if got := Permission(OpPoliciesList); got != "https://www.googleapis.com/auth/cloud-identity.policies.readonly" {
		t.Errorf("%s declares %q, want the Policy API's read-only scope", OpPoliciesList, got)
	}
	for _, op := range []string{OpToken, OpSTSToken, OpGitHubIDToken} {
		if got := Permission(op); got != "" {
			t.Errorf("%s declares %q, want none", op, got)
		}
	}
}

type failingSource struct{ err error }

func (s failingSource) Token() (*oauth2.Token, error) { return nil, s.err }

// A surface whose delegation grant lacks its scope gets unauthorized_client
// from the token endpoint, and the failure names that scope.
func TestTokenFailureNamesTheDeniedScope(t *testing.T) {
	const scope = "https://www.googleapis.com/auth/cloud-identity.policies.readonly"
	denied := &TokenError{Host: "oauth2.googleapis.com", Status: http.StatusUnauthorized, OAuthCode: "unauthorized_client", rejects400: true}
	cases := []struct {
		name   string
		err    error
		scopes []string
		want   string
	}{
		{"grant without the scope", denied, []string{scope}, scope},
		{"rejected key", &TokenError{Host: "oauth2.googleapis.com", Status: http.StatusBadRequest, OAuthCode: "invalid_grant", rejects400: true}, []string{scope}, ""},
		{"token for two scopes", denied, []string{scope, "https://www.googleapis.com/auth/ediscovery.readonly"}, ""},
	}
	for _, tc := range cases {
		_, err := surfaceSource{src: failingSource{err: tc.err}, scopes: tc.scopes}.Token()
		var failure *tokenFailure
		if !errors.As(err, &failure) {
			t.Fatalf("%s: error %v is not a token failure", tc.name, err)
		}
		if got := failure.DeniedPermission(); got != tc.want {
			t.Errorf("%s: DeniedPermission = %q, want %q", tc.name, got, tc.want)
		}
	}
}
