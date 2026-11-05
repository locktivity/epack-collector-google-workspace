package collector

import (
	"context"
	"errors"
	"testing"
	"time"

	"google.golang.org/api/googleapi"

	"github.com/locktivity/epack-collector-google-workspace/internal/googleworkspace"
	"github.com/locktivity/epack/componentsdk"
)

func TestAggregatePasswordPoliciesSinglePolicyPassesValuesThrough(t *testing.T) {
	got := aggregatePasswordPolicies([]googleworkspace.PasswordPolicy{
		{
			MinimumLength:              12,
			MaximumLength:              100,
			AllowedStrength:            "STRONG",
			EnforceRequirementsAtLogin: true,
			AllowReuse:                 false,
			ExpirationDays:             90,
		},
	})

	want := PasswordPolicyConfig{
		MinimumLength:              12,
		MaximumLength:              100,
		AllowedStrength:            strengthStrong,
		EnforceRequirementsAtLogin: true,
		AllowReuse:                 false,
		ExpirationDays:             90,
		DistinctPolicies:           1,
	}
	if got != want {
		t.Fatalf("aggregate = %+v, want %+v", got, want)
	}
}

func TestAggregatePasswordPoliciesTakesTheWeakestValue(t *testing.T) {
	strict := googleworkspace.PasswordPolicy{
		MinimumLength:              14,
		MaximumLength:              64,
		AllowedStrength:            "STRONG",
		EnforceRequirementsAtLogin: true,
		AllowReuse:                 false,
		ExpirationDays:             30,
	}

	tests := []struct {
		name  string
		other googleworkspace.PasswordPolicy
		check func(t *testing.T, got PasswordPolicyConfig)
	}{
		{
			name:  "shorter minimum wins",
			other: googleworkspace.PasswordPolicy{MinimumLength: 8, AllowedStrength: "STRONG", EnforceRequirementsAtLogin: true, ExpirationDays: 30},
			check: func(t *testing.T, got PasswordPolicyConfig) {
				if got.MinimumLength != 8 {
					t.Fatalf("MinimumLength = %d, want 8", got.MinimumLength)
				}
			},
		},
		{
			name:  "any weak strength makes the tenant weak",
			other: googleworkspace.PasswordPolicy{MinimumLength: 14, AllowedStrength: "WEAK", EnforceRequirementsAtLogin: true, ExpirationDays: 30},
			check: func(t *testing.T, got PasswordPolicyConfig) {
				if got.AllowedStrength != strengthWeak {
					t.Fatalf("AllowedStrength = %q, want %q", got.AllowedStrength, strengthWeak)
				}
			},
		},
		{
			name:  "any unenforced policy makes the tenant unenforced",
			other: googleworkspace.PasswordPolicy{MinimumLength: 14, AllowedStrength: "STRONG", EnforceRequirementsAtLogin: false, ExpirationDays: 30},
			check: func(t *testing.T, got PasswordPolicyConfig) {
				if got.EnforceRequirementsAtLogin {
					t.Fatal("EnforceRequirementsAtLogin = true, want false when any policy does not enforce")
				}
			},
		},
		{
			name:  "reuse permitted anywhere is permitted",
			other: googleworkspace.PasswordPolicy{MinimumLength: 14, AllowedStrength: "STRONG", EnforceRequirementsAtLogin: true, AllowReuse: true, ExpirationDays: 30},
			check: func(t *testing.T, got PasswordPolicyConfig) {
				if !got.AllowReuse {
					t.Fatal("AllowReuse = false, want true when any policy permits reuse")
				}
			},
		},
		{
			name:  "longer expiry wins over shorter",
			other: googleworkspace.PasswordPolicy{MinimumLength: 14, AllowedStrength: "STRONG", EnforceRequirementsAtLogin: true, ExpirationDays: 180},
			check: func(t *testing.T, got PasswordPolicyConfig) {
				if got.ExpirationDays != 180 {
					t.Fatalf("ExpirationDays = %d, want 180", got.ExpirationDays)
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tt.check(t, aggregatePasswordPolicies([]googleworkspace.PasswordPolicy{strict, tt.other}))
			tt.check(t, aggregatePasswordPolicies([]googleworkspace.PasswordPolicy{tt.other, strict}))
		})
	}
}

// Never-expires is 0, which is weaker than any finite expiry. A plain maximum
// would report 0 as the strongest value and invert the meaning of the field.
func TestAggregatePasswordPoliciesNeverExpiresBeatsAnyFiniteExpiry(t *testing.T) {
	expiring := googleworkspace.PasswordPolicy{MinimumLength: 12, AllowedStrength: "STRONG", EnforceRequirementsAtLogin: true, ExpirationDays: 90}
	never := googleworkspace.PasswordPolicy{MinimumLength: 12, AllowedStrength: "STRONG", EnforceRequirementsAtLogin: true, ExpirationDays: 0}

	for _, policies := range [][]googleworkspace.PasswordPolicy{
		{expiring, never},
		{never, expiring},
	} {
		if got := aggregatePasswordPolicies(policies); got.ExpirationDays != 0 {
			t.Fatalf("ExpirationDays = %d, want 0 (never expires is the weakest)", got.ExpirationDays)
		}
	}
}

// Two org units set to the same rules have one password policy between them.
func TestAggregatePasswordPoliciesCountsDistinctPolicies(t *testing.T) {
	policies := []googleworkspace.PasswordPolicy{
		{MinimumLength: 12, AllowedStrength: "STRONG", EnforceRequirementsAtLogin: true},
		{MinimumLength: 10, AllowedStrength: "STRONG", EnforceRequirementsAtLogin: true},
		{MinimumLength: 8, AllowedStrength: "STRONG", EnforceRequirementsAtLogin: true},
		{MinimumLength: 12, AllowedStrength: "STRONG", EnforceRequirementsAtLogin: true},
	}
	if got := aggregatePasswordPolicies(policies); got.DistinctPolicies != 3 {
		t.Fatalf("DistinctPolicies = %d, want 3", got.DistinctPolicies)
	}
	same := googleworkspace.PasswordPolicy{MinimumLength: 12, MaximumLength: 100, AllowedStrength: "STRONG", EnforceRequirementsAtLogin: true, ExpirationDays: 90}
	if got := aggregatePasswordPolicies([]googleworkspace.PasswordPolicy{same, same}); got.DistinctPolicies != 1 {
		t.Fatalf("DistinctPolicies = %d for two policies with the same rules, want 1", got.DistinctPolicies)
	}
}

// With no password policy in the Policy API's answer, the policy is left out
// with a vendor_error gap. The sign-in settings get the same gap.
func TestScanPasswordPolicyWithNoPolicyLeavesAGap(t *testing.T) {
	rec := &componentsdk.Recorder{}
	c := NewWithClient(Config{AdminEmail: "admin@example.com", Recorder: rec}, &mockClient{})
	if policy := c.scanPasswordPolicy(context.Background(), scanScope{customerID: "C123"}); policy != nil {
		t.Fatalf("policy = %+v, want it left out", policy)
	}
	gaps := rec.Gaps()
	if len(gaps) != 1 || gaps[0].Pointer != "/passwords/policy" || gaps[0].Code != componentsdk.CodeVendorError {
		t.Errorf("gaps = %+v, want one vendor_error gap at /passwords/policy", gaps)
	}
}

func TestAggregatePasswordPoliciesTreatsStrengthCaseInsensitively(t *testing.T) {
	got := aggregatePasswordPolicies([]googleworkspace.PasswordPolicy{
		{MinimumLength: 12, AllowedStrength: "Strong", EnforceRequirementsAtLogin: true},
	})
	if got.AllowedStrength != strengthStrong {
		t.Fatalf("AllowedStrength = %q, want %q", got.AllowedStrength, strengthStrong)
	}
}

// collectWithPolicyResult runs a full trust-level collection whose only
// variable is what the Policy API returned.
func collectWithPolicyResult(t *testing.T, policies []googleworkspace.PasswordPolicy, policyErr error) *OrgPosture {
	t.Helper()

	now := time.Date(2026, 4, 8, 12, 0, 0, 0, time.UTC)
	client := &mockClient{
		customer: googleworkspace.Customer{ID: "C123", PrimaryDomain: "example.com"},
		usageReport: googleworkspace.CustomerUsageReport{
			NumUsers:                           100,
			NumUsers2SVEnrolled:                90,
			NumUsers2SVEnforced:                100,
			NumUsersPasswordStrengthWeak:       8,
			NumUsersPasswordLengthNonCompliant: 4,
		},
		users: []googleworkspace.User{
			{PrimaryEmail: "admin@example.com", IsAdmin: true, IsEnrolledIn2Sv: true, IsEnforcedIn2Sv: true, LastLoginTime: now},
			{PrimaryEmail: "active@example.com", LastLoginTime: now},
		},
		passwordPolicies:    policies,
		passwordPoliciesErr: policyErr,
	}

	c := NewWithClient(Config{
		AdminEmail: "admin@example.com",
		Now:        func() time.Time { return now },
	}, client)

	posture, err := c.Collect(context.Background(), componentsdk.LevelTrust)
	if err != nil {
		t.Fatalf("Collect() error = %v, want the password policy surface to degrade rather than fail", err)
	}
	return posture
}

func TestScanPasswordPolicyPermissionFailuresDegrade(t *testing.T) {
	tests := []struct {
		name       string
		err        error
		wantErrHas string
	}{
		{
			name:       "scope not granted on the delegation",
			err:        &googleapi.Error{Code: 403, Errors: []googleapi.ErrorItem{{Reason: "ACCESS_TOKEN_SCOPE_INSUFFICIENT"}}},
			wantErrHas: "cloud-identity.policies.readonly",
		},
		{
			name:       "impersonation user lacks the admin role",
			err:        &googleapi.Error{Code: 403, Errors: []googleapi.ErrorItem{{Reason: "INSUFFICIENT_PERMISSIONS"}}},
			wantErrHas: "admin role",
		},
		{
			name:       "cloud identity API not enabled in the project",
			err:        &googleapi.Error{Code: 403, Errors: []googleapi.ErrorItem{{Reason: "accessNotConfigured"}}, Message: "cloudidentity.googleapis.com SERVICE_DISABLED"},
			wantErrHas: "not enabled",
		},
		{
			// Under a workload identity credential the delegation assertion is
			// rejected at the token endpoint rather than at the API call, but
			// it carries the same OAuth code. The surface must degrade exactly
			// as it does with a service account key, not abort the run.
			name:       "delegation scope not granted under a federated credential",
			err:        errors.New(`token endpoint rejected the delegation assertion for admin@example.com: unauthorized_client (Client is unauthorized to retrieve access tokens using this method)`),
			wantErrHas: "cloud-identity.policies.readonly",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			posture := collectWithPolicyResult(t, nil, tt.err)

			if posture.Passwords.Policy != nil {
				t.Fatalf("Passwords.Policy = %+v, want nil so the fields stay absent", posture.Passwords.Policy)
			}
			if !hasPermissionError(posture, "password_policy") {
				t.Fatalf("permission errors = %v, want one naming the password_policy surface", permissionErrorsOf(posture))
			}
			if !hasPermissionError(posture, tt.wantErrHas) {
				t.Fatalf("permission errors = %v, want one naming %q", permissionErrorsOf(posture), tt.wantErrHas)
			}

			// The outcome percentages come from the usage report and must
			// survive a policy failure untouched.
			wantPct(t, "Passwords.WeakPasswordPct", posture.Passwords.WeakPasswordPct, 8)
		})
	}
}

func TestScanPasswordPolicyInformationalFailuresWarn(t *testing.T) {
	tests := []struct {
		name        string
		policies    []googleworkspace.PasswordPolicy
		err         error
		wantWarning string
	}{
		{
			name:        "edition does not include the Policy API",
			err:         &googleapi.Error{Code: 404},
			wantWarning: "Policy API",
		},
		{
			name:        "tenant exposes no password policy",
			policies:    nil,
			wantWarning: "no password policy returned",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			posture := collectWithPolicyResult(t, tt.policies, tt.err)

			if posture.Passwords.Policy != nil {
				t.Fatalf("Passwords.Policy = %+v, want nil", posture.Passwords.Policy)
			}
			if !hasWarning(posture, tt.wantWarning) {
				t.Fatalf("warnings = %v, want one naming %q", warningsOf(posture), tt.wantWarning)
			}
			// A licensing gap or an unconfigured tenant is not a
			// misconfiguration the customer can necessarily fix, so it must not
			// be reported as a permission error.
			if hasPermissionError(posture, "password_policy") {
				t.Fatalf("permission errors = %v, want none for an informational degradation", permissionErrorsOf(posture))
			}
		})
	}
}

func TestScanPasswordPolicySuccessPopulatesTheArtifact(t *testing.T) {
	posture := collectWithPolicyResult(t, []googleworkspace.PasswordPolicy{
		{MinimumLength: 12, MaximumLength: 100, AllowedStrength: "STRONG", EnforceRequirementsAtLogin: true, ExpirationDays: 90},
		{MinimumLength: 8, MaximumLength: 64, AllowedStrength: "WEAK", EnforceRequirementsAtLogin: false, AllowReuse: true, ExpirationDays: 0},
	}, nil)

	policy := posture.Passwords.Policy
	if policy == nil {
		t.Fatal("Passwords.Policy = nil, want the aggregated policy")
	}

	want := PasswordPolicyConfig{
		MinimumLength:              8,
		MaximumLength:              100,
		AllowedStrength:            strengthWeak,
		EnforceRequirementsAtLogin: false,
		AllowReuse:                 true,
		ExpirationDays:             0,
		DistinctPolicies:           2,
	}
	if *policy != want {
		t.Fatalf("Policy = %+v, want %+v", *policy, want)
	}
}
