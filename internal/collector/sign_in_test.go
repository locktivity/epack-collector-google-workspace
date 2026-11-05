package collector

import (
	"context"
	"encoding/json"
	"errors"
	"reflect"
	"strconv"
	"strings"
	"testing"
	"time"

	"google.golang.org/api/googleapi"

	"github.com/locktivity/epack-collector-google-workspace/internal/googleworkspace"
	"github.com/locktivity/epack/componentsdk"
	"github.com/locktivity/epack/componentsdk/collectortest"
)

// scanSignIn runs scanSignInPolicy over client and returns what it read and
// the gaps it recorded, by pointer.
func scanSignIn(t *testing.T, client *mockClient) (*SignInPolicy, map[string]componentsdk.Gap) {
	t.Helper()
	rec := &componentsdk.Recorder{}
	c := NewWithClient(Config{AdminEmail: "admin@example.com", Recorder: rec}, client)
	policy := c.scanSignInPolicy(context.Background(), scanScope{customerID: "C123"})
	gaps := map[string]componentsdk.Gap{}
	for _, g := range rec.Gaps() {
		gaps[g.Pointer] = g
	}
	return policy, gaps
}

func TestScanSignInPolicyTakesTheWeakestSettings(t *testing.T) {
	policy, gaps := scanSignIn(t, &mockClient{
		sessionPolicies:       []googleworkspace.SessionPolicy{{WebSessionSeconds: 43200}, {WebSessionSeconds: 1209600}},
		lessSecureAppPolicies: []googleworkspace.LessSecureAppsPolicy{{}, {Allowed: true}},
	})
	if len(gaps) != 0 {
		t.Fatalf("gaps = %v, want none", gaps)
	}
	if policy == nil || showInt(policy.WebSessionDurationMaxMinutes) != "20160" || showBool(policy.LessSecureAppsAllowed) != "true" {
		t.Fatalf("policy = %+v, want 20160 minutes with less secure apps allowed", policy)
	}
}

// A session length that is not whole minutes rounds up, so it never reads
// shorter than it is.
func TestScanSignInPolicyRoundsTheSessionUp(t *testing.T) {
	policy, _ := scanSignIn(t, &mockClient{
		sessionPolicies:       []googleworkspace.SessionPolicy{{WebSessionSeconds: 43201}},
		lessSecureAppPolicies: []googleworkspace.LessSecureAppsPolicy{{}},
	})
	if policy == nil || showInt(policy.WebSessionDurationMaxMinutes) != "721" || showBool(policy.LessSecureAppsAllowed) != "false" {
		t.Fatalf("policy = %+v, want 721 minutes with less secure apps blocked", policy)
	}
}

func TestScanSignInPolicyLeavesOutWhatItCannotRead(t *testing.T) {
	refused := componentsdk.CodeError(componentsdk.CodePermissionDenied, &googleapi.Error{Code: 403, Errors: []googleapi.ErrorItem{{Reason: "forbidden"}}})
	cases := []struct {
		name   string
		client *mockClient
		want   componentsdk.Code
	}{
		{"no policy", &mockClient{}, componentsdk.CodeVendorError},
		{"no Policy API", &mockClient{
			sessionPoliciesErr:       &googleapi.Error{Code: 404},
			lessSecureAppPoliciesErr: &googleapi.Error{Code: 404},
		}, componentsdk.CodeNotLicensed},
		{"refused", &mockClient{sessionPoliciesErr: refused, lessSecureAppPoliciesErr: refused}, componentsdk.CodePermissionDenied},
	}
	for _, tc := range cases {
		policy, gaps := scanSignIn(t, tc.client)
		if policy != nil {
			t.Errorf("%s: policy = %+v, want none", tc.name, policy)
		}
		for _, pointer := range []string{webSessionPointer, lessSecureAppsPointer} {
			if g, ok := gaps[pointer]; !ok || g.Code != tc.want {
				t.Errorf("%s: gap at %s = %+v, want %s", tc.name, pointer, g, tc.want)
			}
		}
	}
}

// Google stopped supporting less secure apps on May 1, 2025, so their setting
// has no effect on legacy sign-in. Users with 2-step verification can still
// sign in with an app password, and no API reports them. So
// legacy_auth_blocked is left out with an unsupported gap for every value of
// the setting. The session length is still written.
func TestIDPPostureSignInSettings(t *testing.T) {
	for _, allowed := range []*bool{boolPtr(true), boolPtr(false), nil} {
		rec := &componentsdk.Recorder{}
		c := NewWithClient(Config{AdminEmail: "admin@example.com", Recorder: rec}, &mockClient{})
		o := NewOrgPosture(time.Date(2026, 4, 8, 12, 0, 0, 0, time.UTC))
		o.OrgDomain = strPtr("example.com")
		o.SignIn = &SignInPolicy{WebSessionDurationMaxMinutes: intPtr(720), LessSecureAppsAllowed: allowed}
		policy := o.ToIDPPosture().Policy
		if policy == nil || showInt(policy.SessionLifetimeMaxMin) != "720" {
			t.Errorf("less secure apps allowed %s: policy = %+v, want 720 minutes", showBool(allowed), policy)
		}
		raw, err := json.Marshal(policy)
		if err != nil {
			t.Fatal(err)
		}
		if strings.Contains(string(raw), "legacy_auth_blocked") {
			t.Errorf("less secure apps allowed %s: policy = %s, want legacy_auth_blocked left out", showBool(allowed), raw)
		}
		c.recordIDPPostureGaps(o, componentsdk.LevelTrust)
		var got componentsdk.Code
		for _, g := range rec.Gaps() {
			if g.Path == idpPosturePath && g.Pointer == "/policy/legacy_auth_blocked" {
				got = g.Code
			}
		}
		if got != componentsdk.CodeUnsupported {
			t.Errorf("less secure apps allowed %s: legacy_auth_blocked gap %q, want %q", showBool(allowed), got, componentsdk.CodeUnsupported)
		}
	}
}

// deniedError is a token failure for a delegation grant without scope.
type deniedError struct{ scope string }

func (e deniedError) Error() string                     { return "unauthorized_client" }
func (e deniedError) DeniedPermission() string          { return e.scope }
func (e deniedError) CollectionCode() componentsdk.Code { return componentsdk.CodePermissionDenied }

func TestAGrantWithoutTheScopeNamesItOnTheGap(t *testing.T) {
	const scope = "https://www.googleapis.com/auth/cloud-identity.policies.readonly"
	_, gaps := scanSignIn(t, &mockClient{
		sessionPoliciesErr:       errors.Join(errors.New("listing session controls policies"), deniedError{scope: scope}),
		lessSecureAppPoliciesErr: deniedError{},
	})
	if g := gaps[webSessionPointer]; g.Code != componentsdk.CodePermissionDenied || g.MissingPermission != scope {
		t.Errorf("session gap = %+v, want permission_denied naming %s", g, scope)
	}
	if g := gaps[lessSecureAppsPointer]; g.MissingPermission != "" {
		t.Errorf("less secure apps gap names %q, want no scope when the failure names none", g.MissingPermission)
	}
}

// TestLeftOutIDPPostureValuesGetTheirCodes checks the gaps on the normalized
// values the collector leaves out. Google reports per-user passkeys and the
// allowed 2-Step Verification methods, so those are not_read. The counts get
// a gap only at the audit level.
func TestLeftOutIDPPostureValuesGetTheirCodes(t *testing.T) {
	notRead := map[string]bool{
		"/privileged_access/privileged_phishing_resistant_user_count": true,
		"/privileged_access/privileged_phishing_resistant_pct":        true,
		"/policy/phishing_resistant_required_for_privileged":          true,
	}
	for _, level := range []componentsdk.Level{componentsdk.LevelTrust, componentsdk.LevelAudit} {
		rec := &componentsdk.Recorder{}
		c := NewWithClient(Config{AdminEmail: "admin@example.com", Recorder: rec}, &mockClient{})
		o := NewOrgPosture(time.Date(2026, 4, 8, 12, 0, 0, 0, time.UTC))
		o.CollectedAtLevel = string(level)
		c.recordIDPPostureGaps(o, level)
		got := map[string]componentsdk.Code{}
		for _, g := range rec.Gaps() {
			if g.Path == idpPosturePath {
				got[g.Pointer] = g.Code
			}
		}
		want := map[string]componentsdk.Code{}
		for _, u := range idpPostureLeftOut {
			if u.audit && level != componentsdk.LevelAudit {
				continue
			}
			want[u.pointer] = componentsdk.CodeUnsupported
			if notRead[u.pointer] {
				want[u.pointer] = componentsdk.CodeNotRead
			}
		}
		if !reflect.DeepEqual(got, want) {
			t.Errorf("%s: normalized gaps = %v, want %v", level, got, want)
		}
	}
	for _, u := range idpPostureLeftOut {
		if u.pointer == "/policy/session_lifetime_max_min" {
			t.Errorf("%s is left out, want it read from the Policy API", u.pointer)
		}
	}
}

// TestEachCallDeclaresItsPermission checks that the collector result lists
// the permission each call needs: the OAuth scope for a Workspace call, the
// IAM permission for Access Context Manager, and none for the token
// exchange.
func TestEachCallDeclaresItsPermission(t *testing.T) {
	replay, err := collectortest.NewReplay(collectortest.Scenario{Name: t.Name(), Responses: cleanTenant().responses()})
	if err != nil {
		t.Fatal(err)
	}
	res := componentsdk.RunInProcess(Spec("test", "collectortest"), Run, componentsdk.InProcessOptions{
		Config: kitConfig(), Secrets: kitSecrets(), Transport: replay, Clock: func() time.Time { return kitNow },
	})
	if res.ExitCode != 0 {
		t.Fatalf("run failed with exit %d: %s", res.ExitCode, res.Stderr)
	}
	got := map[string]string{}
	for _, op := range res.Operations {
		got[op.Name] = op.Permission
	}
	want := map[string]string{
		googleworkspace.OpToken:              "",
		googleworkspace.OpUsersList:          "https://www.googleapis.com/auth/admin.directory.user.readonly",
		googleworkspace.OpPoliciesList:       "https://www.googleapis.com/auth/cloud-identity.policies.readonly",
		googleworkspace.OpAccessPoliciesList: "accesscontextmanager.policies.list",
		googleworkspace.OpVaultHoldsList:     "https://www.googleapis.com/auth/ediscovery.readonly",
	}
	for op, permission := range want {
		if p, ok := got[op]; !ok || p != permission {
			t.Errorf("%s declares %q, want %q", op, p, permission)
		}
	}
	for op, permission := range got {
		if op != googleworkspace.OpToken && permission == "" {
			t.Errorf("%s declares no permission", op)
		}
	}
}

func showInt(p *int) string {
	if p == nil {
		return "null"
	}
	return strconv.Itoa(*p)
}

func showBool(b *bool) string {
	if b == nil {
		return "null"
	}
	return strconv.FormatBool(*b)
}

// Google refuses a token without the Policy API's scope with
// ACCESS_TOKEN_SCOPE_INSUFFICIENT, and the gap names the scope.
func TestARefusedScopeIsNamedOnTheGap(t *testing.T) {
	replay, err := collectortest.NewReplay(collectortest.Scenario{Name: t.Name(), Responses: sessionScopeDeniedTenant().withCustomerKey()})
	if err != nil {
		t.Fatal(err)
	}
	res := componentsdk.RunInProcess(Spec("test", "collectortest"), Run, componentsdk.InProcessOptions{
		Config: kitConfig(), Secrets: kitSecrets(), Transport: replay, Clock: func() time.Time { return kitNow },
	})
	if res.ExitCode != 0 || res.Result == nil {
		t.Fatalf("run failed with exit %d: %s", res.ExitCode, res.Stderr)
	}
	for _, g := range res.Result.Gaps {
		if g.Path != detailedPath || g.Pointer != webSessionPointer {
			continue
		}
		if g.Code != componentsdk.CodePermissionDenied || g.MissingPermission != "https://www.googleapis.com/auth/cloud-identity.policies.readonly" {
			t.Fatalf("gap = %+v, want permission_denied naming the Policy API's scope", g)
		}
		return
	}
	t.Fatalf("no gap at %s in %+v", webSessionPointer, res.Result.Gaps)
}
