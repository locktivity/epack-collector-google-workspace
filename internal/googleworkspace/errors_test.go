package googleworkspace

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"io"
	"net/http"
	"net/url"
	"reflect"
	"strings"
	"testing"

	"google.golang.org/api/googleapi"

	"github.com/locktivity/epack/componentsdk"
)

func TestAPIErrorCodes(t *testing.T) {
	tests := []struct {
		name       string
		err        *googleapi.Error
		want       componentsdk.Code
		vendorCode string
	}{
		{"a role the admin lacks", &googleapi.Error{Code: 403, Errors: []googleapi.ErrorItem{{Reason: "forbidden"}}}, componentsdk.CodePermissionDenied, "forbidden"},
		{"a throttle sent as 403", &googleapi.Error{Code: 403, Errors: []googleapi.ErrorItem{{Reason: "rateLimitExceeded"}}}, componentsdk.CodeRateLimited, "rateLimitExceeded"},
		{"a disabled API", &googleapi.Error{Code: 403, Details: []any{map[string]any{"reason": "SERVICE_DISABLED"}}}, componentsdk.CodePermissionDenied, "SERVICE_DISABLED"},
		{"a rejected token", &googleapi.Error{Code: 401}, componentsdk.CodeAuthFailed, ""},
		{"a missing resource", &googleapi.Error{Code: 404}, componentsdk.CodeInvalidResponse, ""},
		{"a server error", &googleapi.Error{Code: 503}, componentsdk.CodeVendorError, ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := listError(OpUsersList, "listing users", tt.err)
			if got := componentsdk.Classify(err); got != tt.want {
				t.Errorf("Classify() = %s, want %s", got, tt.want)
			}
			if got := componentsdk.VendorCodeOf(err); got != tt.vendorCode {
				t.Errorf("VendorCodeOf() = %q, want %q", got, tt.vendorCode)
			}
			var gerr *googleapi.Error
			if !errors.As(err, &gerr) {
				t.Error("the googleapi error is no longer reachable with errors.As")
			}
		})
	}
}

func TestClassifyResponseReadsGoogleThrottle(t *testing.T) {
	throttle := `{"error":{"code":403,"errors":[{"reason":"userRateLimitExceeded"}]}}`
	forbidden := `{"error":{"code":403,"errors":[{"reason":"forbidden"}]}}`
	if code, ok := ClassifyResponse(&http.Response{StatusCode: 403}, []byte(throttle)); !ok || code != componentsdk.CodeRateLimited {
		t.Errorf("throttle = %s, %v; want rate_limited", code, ok)
	}
	if _, ok := ClassifyResponse(&http.Response{StatusCode: 403}, []byte(forbidden)); ok {
		t.Error("a denial should keep its status")
	}
	if _, ok := ClassifyResponse(&http.Response{StatusCode: 500}, []byte(throttle)); ok {
		t.Error("only a 403 is read")
	}
}

func tokenResponse(host string, status int) *http.Response {
	return &http.Response{StatusCode: status, Header: http.Header{}, Request: &http.Request{URL: &url.URL{Scheme: "https", Host: host, Path: "/token"}}}
}

func TestTokenErrorCodes(t *testing.T) {
	tests := []struct {
		name       string
		resp       *http.Response
		body       string
		rejects400 bool
		want       componentsdk.Code
	}{
		{"an assertion Google rejects", tokenResponse("oauth2.googleapis.com", 400), `{"error":"invalid_grant","error_description":"Invalid JWT Signature."}`, true, componentsdk.CodeAuthFailed},
		{"a delegation grant without the scope", tokenResponse("oauth2.googleapis.com", 401), `{"error":"unauthorized_client"}`, true, componentsdk.CodePermissionDenied},
		{"a malformed token request", tokenResponse("oauth2.googleapis.com", 400), `{"error":"invalid_request"}`, true, componentsdk.CodeConfigInvalid},
		{"a scope Google refuses", tokenResponse("oauth2.googleapis.com", 400), `{"error":"invalid_scope"}`, true, componentsdk.CodePermissionDenied},
		{"an outage named in a 400", tokenResponse("oauth2.googleapis.com", 400), `{"error":"temporarily_unavailable"}`, true, componentsdk.CodeVendorError},
		{"an exchange whose body x/oauth2 dropped", tokenResponse("sts.googleapis.com", 400), ``, true, componentsdk.CodeAuthFailed},
		{"a runner identity endpoint's 400", tokenResponse("pipelines.actions.githubusercontent.com", 400), `{}`, false, componentsdk.CodeInvalidResponse},
		{"a token endpoint outage", tokenResponse("sts.googleapis.com", 503), ``, true, componentsdk.CodeVendorError},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := newTokenError(tt.resp, []byte(tt.body), tt.rejects400)
			if got := componentsdk.Classify(err); got != tt.want {
				t.Errorf("Classify() = %s, want %s (%v)", got, tt.want, err)
			}
		})
	}
}

type timeoutErr struct{}

func (timeoutErr) Error() string   { return "i/o timeout" }
func (timeoutErr) Timeout() bool   { return true }
func (timeoutErr) Temporary() bool { return true }

// An HTTP client wraps a failed token request in a url.Error, which reads
// only its own cause's Timeout.
func TestCauseErrorKeepsATimeoutVisible(t *testing.T) {
	err := &url.Error{Op: "Get", URL: "https://admin.googleapis.com/admin/directory/v1/users", Err: wrapCause(timeoutErr{}, "requesting a token")}
	if got := componentsdk.Classify(err); got != componentsdk.CodeTimeout {
		t.Fatalf("Classify() = %s, want timeout", got)
	}
}

func TestNameOperationNamesTokenRequests(t *testing.T) {
	tests := []struct {
		method, url string
		want        string
	}{
		{http.MethodPost, "https://oauth2.googleapis.com/token", OpToken},
		{http.MethodPost, "https://sts.googleapis.com/v1/token", OpSTSToken},
		{http.MethodPost, "https://iamcredentials.googleapis.com/v1/projects/-/serviceAccounts/sa@p.iam.gserviceaccount.com:generateAccessToken", OpImpersonate},
		{http.MethodPost, "https://iamcredentials.googleapis.com/v1/projects/-/serviceAccounts/sa@p.iam.gserviceaccount.com:signJwt", ""},
		{http.MethodGet, "https://admin.googleapis.com/admin/directory/v1/users", ""},
	}
	for _, tt := range tests {
		req, _ := http.NewRequest(tt.method, tt.url, nil)
		op, ok := NameOperation(req)
		if ok != (tt.want != "") || op.Name != tt.want {
			t.Errorf("NameOperation(%s %s) = %q, %v; want %q", tt.method, tt.url, op.Name, ok, tt.want)
		}
		if ok && !op.Safe {
			t.Errorf("NameOperation(%s) is not Safe; a token request only mints a token", tt.url)
		}
	}
}

func TestCredentialHosts(t *testing.T) {
	key := []string{"admin.googleapis.com", "www.googleapis.com", "cloudidentity.googleapis.com", "accesscontextmanager.googleapis.com", "vault.googleapis.com", "oauth2.googleapis.com"}
	if got := CredentialHosts(AuthConfig{CredentialsJSON: "{}"}); !reflect.DeepEqual(got, key) {
		t.Fatalf("key mode hosts = %v, want %v", got, key)
	}
	t.Setenv(githubRequestURLEnv, "https://pipelines.actions.githubusercontent.com/abc/_apis/idtoken?api-version=2.0")
	want := append(append([]string(nil), key...), "sts.googleapis.com", "iamcredentials.googleapis.com", "pipelines.actions.githubusercontent.com")
	if got := CredentialHosts(oidcConfig()); !reflect.DeepEqual(got, want) {
		t.Fatalf("oidc hosts = %v, want %v", got, want)
	}
}

func testKeyJSON(t *testing.T) string {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := json.Marshal(map[string]string{
		"type":         "service_account",
		"private_key":  string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})),
		"client_email": "collector@p.iam.gserviceaccount.com",
		"token_uri":    "https://oauth2.googleapis.com/token",
	})
	return string(raw)
}

// x/oauth2's jwt package reports a failed exchange as text. The key source
// gives each failure its code from what the exchange request met.
func TestKeySourceCodesFailedExchanges(t *testing.T) {
	keyJSON := testKeyJSON(t)
	answer := func(status int, body string) http.RoundTripper {
		return roundTripFunc(func(r *http.Request) (*http.Response, error) {
			return &http.Response{StatusCode: status, Header: http.Header{}, Body: io.NopCloser(strings.NewReader(body)), Request: r}, nil
		})
	}
	tests := []struct {
		name      string
		transport http.RoundTripper
		want      componentsdk.Code
	}{
		{"a rejected assertion", answer(400, `{"error":"invalid_grant","error_description":"Invalid JWT Signature."}`), componentsdk.CodeAuthFailed},
		{"a grant without the scope", answer(401, `{"error":"unauthorized_client"}`), componentsdk.CodePermissionDenied},
		{"a body that is not JSON", answer(200, `{not json`), componentsdk.CodeInvalidResponse},
		{"no access token", answer(200, `{}`), componentsdk.CodeInvalidResponse},
		{"a timeout", roundTripFunc(func(*http.Request) (*http.Response, error) { return nil, timeoutErr{} }), componentsdk.CodeTimeout},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			auth, err := newAuthenticator(context.Background(), AuthConfig{CredentialsJSON: keyJSON}, tt.transport)
			if err != nil {
				t.Fatal(err)
			}
			src, err := auth.source("admin@example.com", []string{"https://www.googleapis.com/auth/admin.directory.user.readonly"})
			if err != nil {
				t.Fatal(err)
			}
			_, err = src.Token()
			if got := componentsdk.Classify(err); got != tt.want {
				t.Fatalf("Classify() = %s, want %s (%v)", got, tt.want, err)
			}
		})
	}
}
