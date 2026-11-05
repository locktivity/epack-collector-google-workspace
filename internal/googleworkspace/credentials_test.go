package googleworkspace

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google/externalaccount"
	iamcredentials "google.golang.org/api/iamcredentials/v1"
	"google.golang.org/api/option"
)

const canarySecret = "LEAKCANARY_do_not_echo_me"

// fakeAuthClient serves both round trips a delegated token needs: the signing
// call and the assertion exchange.
func fakeAuthClient(handler http.HandlerFunc) *http.Client {
	return &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
		recorder := &responseRecorder{header: make(http.Header)}
		handler(recorder, r)
		if recorder.statusCode == 0 {
			recorder.statusCode = http.StatusOK
		}
		return &http.Response{
			StatusCode: recorder.statusCode,
			Header:     recorder.header,
			Body:       io.NopCloser(strings.NewReader(recorder.body.String())),
			Request:    r,
		}, nil
	})}
}

// newTestTokenSource wires a delegated source to a fake transport. Returns the
// uncached source so a test can count signing calls precisely, plus a counter.
func newTestTokenSource(t *testing.T, handler http.HandlerFunc) (*delegatedTokenSource, *http.Client) {
	t.Helper()

	client := fakeAuthClient(handler)
	signer, err := iamcredentials.NewService(context.Background(),
		option.WithHTTPClient(client),
		option.WithEndpoint("https://unit.test/"),
	)
	if err != nil {
		t.Fatalf("iamcredentials.NewService() error = %v", err)
	}

	now := time.Date(2026, 8, 18, 12, 0, 0, 0, time.UTC)
	return &delegatedTokenSource{
		ctx:           context.Background(),
		signer:        signer,
		saEmail:       "collector@p.iam.gserviceaccount.com",
		subject:       "admin@example.com",
		scopes:        []string{"https://www.googleapis.com/auth/cloud-identity.policies.readonly"},
		tokenEndpoint: "https://unit.test/token",
		httpClient:    client,
		now:           func() time.Time { return now },
	}, client
}

func TestDelegatedTokenSourceSignsAndExchanges(t *testing.T) {
	var claims delegationClaims
	var sentAssertion, sentGrant string

	source, _ := newTestTokenSource(t, func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.Contains(r.URL.Path, ":signJwt"):
			if !strings.Contains(r.URL.Path, "collector@p.iam.gserviceaccount.com") {
				t.Errorf("signJwt path = %q, want it to name the service account", r.URL.Path)
			}
			var request struct {
				Payload string `json:"payload"`
			}
			_ = json.NewDecoder(r.Body).Decode(&request)
			if err := json.Unmarshal([]byte(request.Payload), &claims); err != nil {
				t.Errorf("assertion payload is not valid JSON: %v", err)
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"signedJwt": "SIGNED_ASSERTION_VALUE"})

		case strings.HasSuffix(r.URL.Path, "/token"):
			body, _ := io.ReadAll(r.Body)
			form, _ := url.ParseQuery(string(body))
			sentGrant = form.Get("grant_type")
			sentAssertion = form.Get("assertion")
			_ = json.NewEncoder(w).Encode(map[string]any{
				"access_token": "ACCESS_TOKEN_VALUE",
				"token_type":   "Bearer",
				"expires_in":   3600,
			})

		default:
			t.Errorf("unexpected request to %s", r.URL.Path)
		}
	})

	token, err := source.Token()
	if err != nil {
		t.Fatalf("Token() error = %v", err)
	}

	if claims.Issuer != "collector@p.iam.gserviceaccount.com" {
		t.Errorf("iss = %q, want the service account", claims.Issuer)
	}
	if claims.Subject != "admin@example.com" {
		t.Errorf("sub = %q, want the impersonated admin", claims.Subject)
	}
	if claims.Scope != "https://www.googleapis.com/auth/cloud-identity.policies.readonly" {
		t.Errorf("scope = %q, want only this surface's scope", claims.Scope)
	}
	if claims.Audience != "https://unit.test/token" {
		t.Errorf("aud = %q, want the token endpoint", claims.Audience)
	}

	// The assertion must not be usable before Google's clock reaches it.
	issued := time.Unix(claims.IssuedAt, 0).UTC()
	if !issued.Before(source.now()) {
		t.Errorf("iat = %s, want it backdated before %s for clock skew", issued, source.now())
	}
	if lifetime := time.Unix(claims.Expiry, 0).Sub(issued); lifetime > time.Hour {
		t.Errorf("assertion lifetime = %s, want at most one hour", lifetime)
	}

	if sentGrant != "urn:ietf:params:oauth:grant-type:jwt-bearer" {
		t.Errorf("grant_type = %q, want the JWT bearer grant", sentGrant)
	}
	if sentAssertion != "SIGNED_ASSERTION_VALUE" {
		t.Errorf("assertion = %q, want the signed assertion from the signing call", sentAssertion)
	}
	if token.AccessToken != "ACCESS_TOKEN_VALUE" {
		t.Errorf("AccessToken = %q, want the exchanged token", token.AccessToken)
	}
	if !token.Expiry.After(source.now()) {
		t.Errorf("Expiry = %s, want it in the future", token.Expiry)
	}
}

// A rejected exchange must report Google's error code, never the assertion:
// the assertion is a bearer credential and errors are logged.
func TestDelegatedTokenSourceRejectionCarriesNoAssertion(t *testing.T) {
	source, _ := newTestTokenSource(t, func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.URL.Path, ":signJwt") {
			_ = json.NewEncoder(w).Encode(map[string]any{"signedJwt": canarySecret})
			return
		}
		w.WriteHeader(http.StatusBadRequest)
		_ = json.NewEncoder(w).Encode(map[string]any{
			"error":             "unauthorized_client",
			"error_description": "Client is unauthorized to retrieve access tokens using this method",
		})
	})

	_, err := source.Token()
	if err == nil {
		t.Fatal("Token() error = nil, want the rejection surfaced")
	}
	if strings.Contains(err.Error(), canarySecret) {
		t.Fatalf("error leaked the signed assertion: %v", err)
	}
	if !strings.Contains(err.Error(), "unauthorized_client") {
		t.Fatalf("error = %v, want it to name the OAuth error code so a scope denial stays recognisable", err)
	}
}

func TestDelegatedTokenSourceCachesUntilExpiry(t *testing.T) {
	tests := []struct {
		name      string
		expiresIn int
		wantSigns int
	}{
		{name: "long-lived token is reused", expiresIn: 3600, wantSigns: 1},
		{name: "expiring token is re-signed", expiresIn: 1, wantSigns: 2},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			signs := 0
			inner, _ := newTestTokenSource(t, func(w http.ResponseWriter, r *http.Request) {
				if strings.Contains(r.URL.Path, ":signJwt") {
					signs++
					_ = json.NewEncoder(w).Encode(map[string]any{"signedJwt": "SIGNED"})
					return
				}
				_ = json.NewEncoder(w).Encode(map[string]any{
					"access_token": "ACCESS_TOKEN_VALUE",
					"expires_in":   tt.expiresIn,
				})
			})
			inner.now = time.Now

			cached := oauth2.ReuseTokenSource(nil, inner)
			for i := 0; i < 2; i++ {
				if _, err := cached.Token(); err != nil {
					t.Fatalf("Token() call %d error = %v", i+1, err)
				}
			}

			if signs != tt.wantSigns {
				t.Fatalf("signing calls = %d, want %d", signs, tt.wantSigns)
			}
		})
	}
}

// The constructor is what Slice C wires in, so it is worth asserting it caches
// and defaults to Google's real token endpoint rather than a test override.
func TestNewDelegatedTokenSourceCachesAndTargetsGoogle(t *testing.T) {
	signs := 0
	client := fakeAuthClient(func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.URL.Path, ":signJwt") {
			signs++
			_ = json.NewEncoder(w).Encode(map[string]any{"signedJwt": "SIGNED"})
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"access_token": "ACCESS_TOKEN_VALUE", "expires_in": 3600})
	})
	signer, err := iamcredentials.NewService(context.Background(),
		option.WithHTTPClient(client), option.WithEndpoint("https://unit.test/"))
	if err != nil {
		t.Fatalf("iamcredentials.NewService() error = %v", err)
	}

	source := newDelegatedTokenSource(context.Background(), signer,
		"collector@p.iam.gserviceaccount.com", "admin@example.com",
		[]string{"https://www.googleapis.com/auth/admin.directory.user.readonly"}, client)

	if source == nil {
		t.Fatal("newDelegatedTokenSource() returned no usable token source")
	}

	// Constructing must not sign: a trust-level run should never mint for a
	// surface it does not touch.
	if signs != 0 {
		t.Fatalf("signing calls after construction = %d, want 0", signs)
	}

	if got := (&delegatedTokenSource{tokenEndpoint: googleTokenEndpoint}).tokenEndpoint; got != "https://oauth2.googleapis.com/token" {
		t.Fatalf("default token endpoint = %q, want Google's", got)
	}
}

const keyFixture = `{"type":"service_account","project_id":"p","private_key_id":"k",` +
	`"private_key":"-----BEGIN PRIVATE KEY-----\n` + canarySecret + `\n-----END PRIVATE KEY-----\n",` +
	`"client_email":"collector@p.iam.gserviceaccount.com","token_uri":"https://oauth2.googleapis.com/token"}`

func oidcConfig() AuthConfig {
	return AuthConfig{
		Mode:                     AuthModeOIDC,
		WorkloadIdentityProvider: "projects/123/locations/global/workloadIdentityPools/epack/providers/github",
		ServiceAccount:           "collector@p.iam.gserviceaccount.com",
	}
}

// Every way of misconfiguring authentication is something the operator fixes in
// a profile key or a workflow permission, so each must say which.
func TestAuthConfigValidate(t *testing.T) {
	withRunnerIdentity := func(t *testing.T) {
		t.Helper()
		t.Setenv("ACTIONS_ID_TOKEN_REQUEST_URL", "https://pipelines.actions.githubusercontent.com/token")
		t.Setenv("ACTIONS_ID_TOKEN_REQUEST_TOKEN", canarySecret)
	}

	tests := []struct {
		name     string
		setup    func(*testing.T)
		config   AuthConfig
		wantErr  bool
		wantSaid string
	}{
		{
			name:   "key mode by default",
			config: AuthConfig{CredentialsJSON: keyFixture},
		},
		{
			name:   "key mode named explicitly",
			config: AuthConfig{Mode: AuthModeServiceAccountKey, CredentialsJSON: keyFixture},
		},
		{
			name:     "key mode with no credential",
			config:   AuthConfig{},
			wantErr:  true,
			wantSaid: "GOOGLE_SERVICE_ACCOUNT_JSON",
		},
		{
			name:   "oidc mode on a runner with an identity",
			setup:  withRunnerIdentity,
			config: oidcConfig(),
		},
		{
			name:  "oidc mode missing the provider",
			setup: withRunnerIdentity,
			config: AuthConfig{
				Mode:           AuthModeOIDC,
				ServiceAccount: "collector@p.iam.gserviceaccount.com",
			},
			wantErr:  true,
			wantSaid: "workload_identity_provider",
		},
		{
			name:  "oidc mode missing the service account",
			setup: withRunnerIdentity,
			config: AuthConfig{
				Mode:                     AuthModeOIDC,
				WorkloadIdentityProvider: "projects/123/locations/global/workloadIdentityPools/epack/providers/github",
			},
			wantErr:  true,
			wantSaid: "service_account",
		},
		{
			name:     "oidc mode with no runner identity",
			config:   oidcConfig(),
			wantErr:  true,
			wantSaid: "id-token: write",
		},
		{
			name:     "unrecognised mode",
			config:   AuthConfig{Mode: "assume_role", CredentialsJSON: keyFixture},
			wantErr:  true,
			wantSaid: "invalid auth_mode",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Setenv("ACTIONS_ID_TOKEN_REQUEST_URL", "")
			t.Setenv("ACTIONS_ID_TOKEN_REQUEST_TOKEN", "")
			if tt.setup != nil {
				tt.setup(t)
			}

			err := tt.config.Validate()
			if tt.wantErr == (err == nil) {
				t.Fatalf("Validate() error = %v, wantErr = %v", err, tt.wantErr)
			}
			if err != nil {
				if !strings.Contains(err.Error(), tt.wantSaid) {
					t.Fatalf("error = %v, want it to mention %q", err, tt.wantSaid)
				}
				if strings.Contains(err.Error(), canarySecret) {
					t.Fatalf("error leaked credential material: %v", err)
				}
			}
		})
	}
}

func TestGitHubOIDCSupplierFetchesForTheRequestedAudience(t *testing.T) {
	var gotAudience, gotAuth string
	requests := 0

	supplier := &githubOIDCSupplier{httpClient: fakeAuthClient(func(w http.ResponseWriter, r *http.Request) {
		requests++
		gotAudience = r.URL.Query().Get("audience")
		gotAuth = r.Header.Get("Authorization")
		_ = json.NewEncoder(w).Encode(map[string]any{"value": "RUNNER_IDENTITY_TOKEN"})
	})}

	t.Setenv("ACTIONS_ID_TOKEN_REQUEST_URL", "https://pipelines.actions.githubusercontent.com/token")
	t.Setenv("ACTIONS_ID_TOKEN_REQUEST_TOKEN", canarySecret)

	const audience = "//iam.googleapis.com/projects/123/locations/global/workloadIdentityPools/epack/providers/github"
	for i := 0; i < 2; i++ {
		token, err := supplier.SubjectToken(context.Background(), externalaccount.SupplierOptions{Audience: audience})
		if err != nil {
			t.Fatalf("SubjectToken() call %d error = %v", i+1, err)
		}
		if token != "RUNNER_IDENTITY_TOKEN" {
			t.Fatalf("token = %q, want the runner's identity token", token)
		}
	}

	if gotAudience != audience {
		t.Errorf("audience = %q, want the workload identity pool", gotAudience)
	}
	if gotAuth != "Bearer "+canarySecret {
		t.Errorf("Authorization header = %q, want the runner's request token", gotAuth)
	}
	// The library does not cache subject tokens, so the supplier must.
	if requests != 1 {
		t.Errorf("identity requests = %d, want 1 across two calls", requests)
	}
}

func TestGitHubOIDCSupplierErrorsCarryNoRequestToken(t *testing.T) {
	supplier := &githubOIDCSupplier{httpClient: fakeAuthClient(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
		// The endpoint echoes the request back, which is exactly how a token
		// reaches an error message if the body is reported.
		_, _ = w.Write([]byte(`{"message":"denied","request":{"headers":{"Authorization":"Bearer ` + canarySecret + `"}}}`))
	})}

	t.Setenv("ACTIONS_ID_TOKEN_REQUEST_URL", "https://pipelines.actions.githubusercontent.com/token")
	t.Setenv("ACTIONS_ID_TOKEN_REQUEST_TOKEN", canarySecret)

	_, err := supplier.SubjectToken(context.Background(), externalaccount.SupplierOptions{Audience: "//iam.googleapis.com/x"})
	if err == nil {
		t.Fatal("SubjectToken() error = nil, want the rejection surfaced")
	}
	if strings.Contains(err.Error(), canarySecret) {
		t.Fatalf("error leaked the runner's request token: %v", err)
	}
	if !strings.Contains(err.Error(), "id-token: write") {
		t.Fatalf("error = %v, want it to name the likely workflow fix", err)
	}
}

// The key path is what every current user runs. It must reach the same delegated
// JWT config it does today, with no signing service involved.
func TestAuthenticatorKeyPathUnchanged(t *testing.T) {
	auth, err := newAuthenticator(context.Background(), AuthConfig{CredentialsJSON: keyFixture}, http.DefaultTransport)
	if err != nil {
		t.Fatalf("newAuthenticator() error = %v", err)
	}
	if auth.config.federated() {
		t.Fatal("an omitted auth_mode must not be treated as federated")
	}
	if auth.signer != nil {
		t.Fatal("the key path must build no signing service")
	}

	scopes := []string{"https://www.googleapis.com/auth/admin.directory.user.readonly"}
	cfg, err := auth.jwtConfig("admin@example.com", scopes)
	if err != nil {
		t.Fatalf("jwtConfig() error = %v", err)
	}
	if cfg.Subject != "admin@example.com" {
		t.Errorf("Subject = %q, want the impersonated admin", cfg.Subject)
	}
	if len(cfg.Scopes) != 1 || cfg.Scopes[0] != scopes[0] {
		t.Errorf("Scopes = %v, want only %v", cfg.Scopes, scopes)
	}

	undelegated, err := auth.jwtConfig("", scopes)
	if err != nil {
		t.Fatalf("jwtConfig() error = %v", err)
	}
	if undelegated.Subject != "" {
		t.Errorf("Subject = %q for an undelegated surface, want empty", undelegated.Subject)
	}
}

func TestAuthenticatorRoutesSubjectsToTheRightTokenSource(t *testing.T) {
	tests := []struct {
		name    string
		config  AuthConfig
		subject string
		want    bool
	}{
		{name: "key with a subject signs locally", config: AuthConfig{CredentialsJSON: keyFixture}, subject: "admin@example.com", want: false},
		{name: "key without a subject signs locally", config: AuthConfig{CredentialsJSON: keyFixture}, subject: "", want: false},
		{name: "oidc with a subject needs an assertion", config: oidcConfig(), subject: "admin@example.com", want: true},
		{name: "oidc without a subject uses the service account identity", config: oidcConfig(), subject: "", want: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			auth := &authenticator{config: tt.config}
			if got := auth.delegates(tt.subject); got != tt.want {
				t.Fatalf("delegates(%q) = %v, want %v", tt.subject, got, tt.want)
			}
		})
	}
}

// Building a client must fetch no identity and sign nothing. A trust-level run
// touches a handful of surfaces, and minting for the rest would be wasted calls.
func TestAuthenticatorMintsLazily(t *testing.T) {
	calls := 0
	fake := fakeAuthClient(func(w http.ResponseWriter, r *http.Request) {
		calls++
		_ = json.NewEncoder(w).Encode(map[string]any{"signedJwt": "SIGNED", "value": "IDENTITY"})
	})
	signer, err := iamcredentials.NewService(context.Background(),
		option.WithHTTPClient(fake), option.WithEndpoint("https://unit.test/"))
	if err != nil {
		t.Fatalf("iamcredentials.NewService() error = %v", err)
	}

	auth := &authenticator{ctx: context.Background(), config: oidcConfig(), signer: signer, transport: fake.Transport}
	for _, scope := range []string{
		"https://www.googleapis.com/auth/admin.directory.user.readonly",
		"https://www.googleapis.com/auth/cloud-identity.policies.readonly",
		"https://www.googleapis.com/auth/ediscovery.readonly",
	} {
		if _, err := auth.source("admin@example.com", []string{scope}); err != nil {
			t.Fatalf("source(%s) error = %v", scope, err)
		}
	}

	if calls != 0 {
		t.Fatalf("auth calls after building three clients = %d, want 0 until a surface is used", calls)
	}
}
