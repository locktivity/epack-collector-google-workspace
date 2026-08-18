package googleworkspace

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"

	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"
	"golang.org/x/oauth2/google/externalaccount"
	"golang.org/x/oauth2/jwt"
	"google.golang.org/api/googleapi"
	iamcredentials "google.golang.org/api/iamcredentials/v1"
	"google.golang.org/api/option"
)

// googleTokenEndpoint is where a signed delegation assertion is exchanged for
// an access token.
const googleTokenEndpoint = "https://oauth2.googleapis.com/token"

// assertionSkew backdates the assertion's issue time. Google rejects an
// assertion issued in the future, and a runner's clock can sit slightly ahead
// of Google's.
const assertionSkew = 10 * time.Second

// assertionLifetime is how long a delegation assertion stays valid. Google
// caps this at one hour.
const assertionLifetime = time.Hour

// delegationClaims is the assertion the service account signs to act as a
// Workspace user. It is the same claim set the service account key path builds
// locally; the difference is only who holds the signing key.
type delegationClaims struct {
	Issuer   string `json:"iss"`
	Subject  string `json:"sub"`
	Scope    string `json:"scope"`
	Audience string `json:"aud"`
	IssuedAt int64  `json:"iat"`
	Expiry   int64  `json:"exp"`
}

// delegatedTokenSource mints access tokens for one subject and scope set
// without a local private key.
//
// Each refresh builds a delegation assertion, has Google sign it with the
// service account's Google-managed key, then exchanges it for an access token
// carrying the delegated subject. One instance exists per surface scope set, so
// a delegation grant missing one scope fails only that surface.
type delegatedTokenSource struct {
	ctx     context.Context
	signer  *iamcredentials.Service
	saEmail string
	subject string
	scopes  []string

	// Overridable so tests can drive both round trips without network.
	tokenEndpoint string
	httpClient    *http.Client
	now           func() time.Time
}

// newDelegatedTokenSource returns a caching source for one subject and scope
// set. Nothing is signed until a surface actually makes a request.
func newDelegatedTokenSource(ctx context.Context, signer *iamcredentials.Service, saEmail, subject string, scopes []string) oauth2.TokenSource {
	return oauth2.ReuseTokenSource(nil, &delegatedTokenSource{
		ctx:           ctx,
		signer:        signer,
		saEmail:       saEmail,
		subject:       subject,
		scopes:        scopes,
		tokenEndpoint: googleTokenEndpoint,
		httpClient:    http.DefaultClient,
		now:           time.Now,
	})
}

func (s *delegatedTokenSource) Token() (*oauth2.Token, error) {
	assertion, err := s.signAssertion()
	if err != nil {
		return nil, err
	}
	return s.exchange(assertion)
}

// signAssertion has Google sign the delegation claim set. The signed assertion
// is a bearer credential, so it is never placed in an error.
func (s *delegatedTokenSource) signAssertion() (string, error) {
	issued := s.now().Add(-assertionSkew)
	payload, err := json.Marshal(delegationClaims{
		Issuer:   s.saEmail,
		Subject:  s.subject,
		Scope:    strings.Join(s.scopes, " "),
		Audience: s.tokenEndpoint,
		IssuedAt: issued.Unix(),
		Expiry:   issued.Add(assertionLifetime).Unix(),
	})
	if err != nil {
		return "", fmt.Errorf("building delegation assertion for %s: %w", s.subject, err)
	}

	name := "projects/-/serviceAccounts/" + s.saEmail
	resp, err := s.signer.Projects.ServiceAccounts.
		SignJwt(name, &iamcredentials.SignJwtRequest{Payload: string(payload)}).
		Context(s.ctx).
		Do()
	if err != nil {
		return "", signingFailure(s.saEmail, err)
	}
	return resp.SignedJwt, nil
}

// signingFailure explains why an assertion could not be signed, in terms of the
// thing the operator has to change.
//
// The three federated setup mistakes fail here rather than at startup, because
// the identity exchange and the signing call are both lazy. They live in
// different consoles, so a generic permission error would send an operator
// looking in the wrong one.
func signingFailure(saEmail string, err error) error {
	var apiErr *googleapi.Error
	if errors.As(err, &apiErr) {
		if apiErr.Code == 403 && isServiceDisabled(apiErr) {
			return fmt.Errorf("the IAM Service Account Credentials API is not enabled in the service account's Cloud project; enable iamcredentials.googleapis.com and retry")
		}
		if apiErr.Code == 403 || apiErr.Code == 404 {
			return fmt.Errorf("not permitted to sign delegation assertions as %s; grant roles/iam.serviceAccountTokenCreator on that service account", saEmail)
		}
	}

	// The federated exchange happens inside the signing call's own credentials,
	// so a rejected workload identity exchange surfaces here too.
	if isExternalAccountExchangeFailure(err) {
		return fmt.Errorf("the workload identity exchange was rejected before any Workspace call; check the pool, the provider's attribute condition, and that the runner principal holds roles/iam.workloadIdentityUser on %s", saEmail)
	}

	return fmt.Errorf("signing delegation assertion as %s: %w", saEmail, err)
}

func isServiceDisabled(apiErr *googleapi.Error) bool {
	for _, item := range apiErr.Errors {
		if item.Reason == "accessNotConfigured" {
			return true
		}
	}
	return strings.Contains(apiErr.Message, "SERVICE_DISABLED")
}

// isExternalAccountExchangeFailure reports whether the failure came from
// exchanging the runner's identity rather than from the Workspace call itself.
func isExternalAccountExchangeFailure(err error) bool {
	message := err.Error()
	return strings.Contains(message, "externalaccount") || strings.Contains(message, "sts.googleapis.com")
}

// exchange trades the signed assertion for an access token carrying the
// delegated subject.
func (s *delegatedTokenSource) exchange(assertion string) (*oauth2.Token, error) {
	form := url.Values{
		"grant_type": {"urn:ietf:params:oauth:grant-type:jwt-bearer"},
		"assertion":  {assertion},
	}

	req, err := http.NewRequestWithContext(s.ctx, http.MethodPost, s.tokenEndpoint, strings.NewReader(form.Encode()))
	if err != nil {
		return nil, fmt.Errorf("building token request for %s: %w", s.subject, err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := s.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("exchanging delegation assertion for %s: %w", s.subject, err)
	}
	defer func() { _ = resp.Body.Close() }()

	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return nil, fmt.Errorf("reading token response for %s: %w", s.subject, err)
	}

	var parsed struct {
		AccessToken      string `json:"access_token"`
		ExpiresIn        int64  `json:"expires_in"`
		TokenType        string `json:"token_type"`
		Error            string `json:"error"`
		ErrorDescription string `json:"error_description"`
	}
	// A failed exchange answers with an OAuth error object. Report its code and
	// description, never the request: the assertion is a bearer credential.
	if err := json.Unmarshal(body, &parsed); err != nil {
		return nil, fmt.Errorf("token endpoint returned status %d with an unreadable body for %s", resp.StatusCode, s.subject)
	}
	if parsed.Error != "" {
		return nil, fmt.Errorf("token endpoint rejected the delegation assertion for %s: %s (%s)", s.subject, parsed.Error, parsed.ErrorDescription)
	}
	if parsed.AccessToken == "" {
		return nil, fmt.Errorf("token endpoint returned status %d with no access token for %s", resp.StatusCode, s.subject)
	}

	tokenType := parsed.TokenType
	if tokenType == "" {
		tokenType = "Bearer"
	}
	return &oauth2.Token{
		AccessToken: parsed.AccessToken,
		TokenType:   tokenType,
		Expiry:      s.now().Add(time.Duration(parsed.ExpiresIn) * time.Second),
	}, nil
}

// AuthConfig selects how the collector authenticates.
//
// The mode is explicit rather than inferred, matching the AWS and Microsoft
// collectors. Omitting it keeps the service account key behaviour, so existing
// configurations are unaffected.
type AuthConfig struct {
	Mode string

	// Key mode.
	CredentialsJSON string

	// OIDC mode.
	WorkloadIdentityProvider string
	ServiceAccount           string
}

const (
	// AuthModeOIDC exchanges the runner's own OIDC identity. No stored secret.
	AuthModeOIDC = "oidc"
	// AuthModeServiceAccountKey uses a downloaded private key. The default.
	AuthModeServiceAccountKey = "service_account_key"
)

// ErrNoRunnerIdentity reports that OIDC mode was selected on a runner that
// exposes no identity to exchange.
var ErrNoRunnerIdentity = errors.New("auth_mode is oidc but the runner exposes no OIDC identity; grant the workflow the id-token: write permission and pass ACTIONS_ID_TOKEN_REQUEST_URL and ACTIONS_ID_TOKEN_REQUEST_TOKEN as secrets")

// Validate reports whether the configuration can authenticate at all.
func (a AuthConfig) Validate() error {
	switch a.Mode {
	case AuthModeOIDC:
		if a.WorkloadIdentityProvider == "" {
			return errors.New("auth_mode is oidc but workload_identity_provider is not set")
		}
		if a.ServiceAccount == "" {
			return errors.New("auth_mode is oidc but service_account is not set")
		}
		if !githubOIDCAvailable() {
			return ErrNoRunnerIdentity
		}
		return nil

	case "", AuthModeServiceAccountKey:
		if a.CredentialsJSON == "" {
			return errors.New("authentication required: provide GOOGLE_SERVICE_ACCOUNT_JSON, or set auth_mode to oidc")
		}
		return nil

	default:
		return fmt.Errorf("invalid auth_mode %q: must be %q or %q", a.Mode, AuthModeOIDC, AuthModeServiceAccountKey)
	}
}

func (a AuthConfig) federated() bool { return a.Mode == AuthModeOIDC }

// cloudPlatformScope is what the runner's identity is exchanged for. It
// authenticates the signing call only; the Workspace surfaces get their own
// narrowly scoped tokens from the delegation assertion.
const cloudPlatformScope = "https://www.googleapis.com/auth/cloud-platform"

// githubOIDCAvailable reports whether the runner exposes an identity to
// exchange. Both variables are set by GitHub Actions when the workflow grants
// the id-token permission.
func githubOIDCAvailable() bool {
	return os.Getenv("ACTIONS_ID_TOKEN_REQUEST_URL") != "" && os.Getenv("ACTIONS_ID_TOKEN_REQUEST_TOKEN") != ""
}

// githubOIDCSupplier fetches the runner's identity token for a given audience.
//
// The external account token source does not cache subject tokens, so this
// caches for the run. A token is only fetched when a surface is actually
// collected.
type githubOIDCSupplier struct {
	httpClient *http.Client

	mu     sync.Mutex
	cached string
}

func (s *githubOIDCSupplier) SubjectToken(ctx context.Context, options externalaccount.SupplierOptions) (string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.cached != "" {
		return s.cached, nil
	}

	requestURL := os.Getenv("ACTIONS_ID_TOKEN_REQUEST_URL")
	requestToken := os.Getenv("ACTIONS_ID_TOKEN_REQUEST_TOKEN")
	if requestURL == "" || requestToken == "" {
		return "", ErrNoRunnerIdentity
	}

	parsed, err := url.Parse(requestURL)
	if err != nil {
		return "", errors.New("the runner's OIDC request URL is not a valid URL")
	}
	query := parsed.Query()
	query.Set("audience", options.Audience)
	parsed.RawQuery = query.Encode()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, parsed.String(), nil)
	if err != nil {
		return "", errors.New("could not build the runner identity request")
	}
	req.Header.Set("Authorization", "Bearer "+requestToken)

	client := s.httpClient
	if client == nil {
		client = http.DefaultClient
	}
	resp, err := client.Do(req)
	if err != nil {
		return "", fmt.Errorf("fetching the runner's identity token: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return "", errors.New("reading the runner's identity token")
	}
	if resp.StatusCode != http.StatusOK {
		// The body echoes the request, so report the status only.
		return "", fmt.Errorf("the runner's OIDC endpoint returned status %d; check the workflow's id-token: write permission", resp.StatusCode)
	}

	var parsedBody struct {
		Value string `json:"value"`
	}
	if err := json.Unmarshal(body, &parsedBody); err != nil || parsedBody.Value == "" {
		return "", errors.New("the runner's OIDC endpoint returned no identity token")
	}

	s.cached = parsedBody.Value
	return s.cached, nil
}

// authenticator turns a subject and a scope set into an authenticated HTTP
// client, hiding the auth mode from the rest of the client.
//
// One instance per run. In OIDC mode it holds a single signing service, so the
// ten surface scope sets share it rather than building ten.
type authenticator struct {
	config AuthConfig
	signer *iamcredentials.Service // nil on the service account key path
}

func newAuthenticator(ctx context.Context, config AuthConfig) (*authenticator, error) {
	if err := config.Validate(); err != nil {
		return nil, err
	}

	a := &authenticator{config: config}
	if !config.federated() {
		return a, nil
	}

	base, err := a.federatedTokenSource(ctx, cloudPlatformScope)
	if err != nil {
		return nil, err
	}
	// Nothing is minted here: the source is lazy, so a run signs only for the
	// surfaces it touches.
	signer, err := iamcredentials.NewService(ctx, option.WithTokenSource(base))
	if err != nil {
		return nil, fmt.Errorf("preparing to sign delegation assertions as %s: %w", config.ServiceAccount, err)
	}
	a.signer = signer
	return a, nil
}

// federatedTokenSource exchanges the runner's identity for a token that acts as
// the service account.
//
// The exchange and impersonation endpoints are constructed here rather than
// read from a credential file, so they are always Google's and there is nothing
// external to validate.
func (a *authenticator) federatedTokenSource(ctx context.Context, scopes ...string) (oauth2.TokenSource, error) {
	source, err := externalaccount.NewTokenSource(ctx, externalaccount.Config{
		Audience:                       "//iam.googleapis.com/" + a.config.WorkloadIdentityProvider,
		SubjectTokenType:               "urn:ietf:params:oauth:token-type:jwt",
		TokenURL:                       "https://sts.googleapis.com/v1/token",
		ServiceAccountImpersonationURL: "https://iamcredentials.googleapis.com/v1/projects/-/serviceAccounts/" + a.config.ServiceAccount + ":generateAccessToken",
		SubjectTokenSupplier:           &githubOIDCSupplier{},
		Scopes:                         scopes,
	})
	if err != nil {
		return nil, fmt.Errorf("preparing the workload identity exchange for %s: %w", a.config.ServiceAccount, err)
	}
	return source, nil
}

// delegates reports whether this subject needs a signed delegation assertion.
//
// Only a federated run acting as a Workspace user does. Access Context Manager
// is an org-level Cloud API that impersonates nobody, so it passes an empty
// subject and uses the service account's own identity: asking Google to sign a
// subject-less assertion would fail.
func (a *authenticator) delegates(subject string) bool {
	return a.config.federated() && subject != ""
}

// jwtConfig builds the delegated JWT config for the service account key path.
// This is the collector's original behaviour, unchanged.
func (a *authenticator) jwtConfig(subject string, scopes []string) (*jwt.Config, error) {
	cfg, err := google.JWTConfigFromJSON([]byte(a.config.CredentialsJSON), scopes...)
	if err != nil {
		return nil, err
	}
	if subject != "" {
		cfg.Subject = subject
	}
	return cfg, nil
}

// client returns an HTTP client authenticated for one subject and scope set.
// No token is minted here; every path returns a lazy source.
func (a *authenticator) client(ctx context.Context, subject string, scopes []string) (*http.Client, error) {
	if !a.config.federated() {
		cfg, err := a.jwtConfig(subject, scopes)
		if err != nil {
			return nil, err
		}
		return cfg.Client(ctx), nil
	}

	if a.delegates(subject) {
		return oauth2.NewClient(ctx, newDelegatedTokenSource(ctx, a.signer, a.config.ServiceAccount, subject, scopes)), nil
	}

	source, err := a.federatedTokenSource(ctx, scopes...)
	if err != nil {
		return nil, err
	}
	return oauth2.NewClient(ctx, source), nil
}
