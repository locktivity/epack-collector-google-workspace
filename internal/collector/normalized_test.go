package collector

import (
	"encoding/json"
	"strings"
	"testing"
)

func postureWithPasswordPolicy(policy *PasswordPolicyConfig) *OrgPosture {
	return &OrgPosture{
		Users:     UserMetrics{Total: 100},
		Passwords: PasswordMetrics{WeakPasswordPct: 0, PasswordLengthNonCompliantPct: 0, Policy: policy},
	}
}

func TestToIDPPostureMapsPasswordPolicy(t *testing.T) {
	idp := postureWithPasswordPolicy(&PasswordPolicyConfig{
		MinimumLength:              12,
		MaximumLength:              100,
		AllowedStrength:            strengthStrong,
		EnforceRequirementsAtLogin: true,
		ExpirationDays:             90,
		DistinctPolicies:           1,
	}).ToIDPPosture()

	if idp == nil {
		t.Fatal("ToIDPPosture() = nil, want a posture")
	}
	if idp.Policy.MinimumPasswordLength == nil || *idp.Policy.MinimumPasswordLength != 12 {
		t.Fatalf("MinimumPasswordLength = %v, want 12", idp.Policy.MinimumPasswordLength)
	}
	if idp.Policy.PasswordStrengthRequired == nil || !*idp.Policy.PasswordStrengthRequired {
		t.Fatalf("PasswordStrengthRequired = %v, want true", idp.Policy.PasswordStrengthRequired)
	}
	if idp.Policy.PasswordPolicyEnforcedForExistingUsers == nil || !*idp.Policy.PasswordPolicyEnforcedForExistingUsers {
		t.Fatalf("PasswordPolicyEnforcedForExistingUsers = %v, want true", idp.Policy.PasswordPolicyEnforcedForExistingUsers)
	}
}

func TestToIDPPostureDerivesStrengthRequiredBothWays(t *testing.T) {
	tests := []struct {
		strength string
		want     bool
	}{
		{strengthStrong, true},
		{strengthWeak, false},
	}

	for _, tt := range tests {
		t.Run(tt.strength, func(t *testing.T) {
			idp := postureWithPasswordPolicy(&PasswordPolicyConfig{
				MinimumLength:   8,
				AllowedStrength: tt.strength,
			}).ToIDPPosture()

			if idp.Policy.PasswordStrengthRequired == nil {
				t.Fatal("PasswordStrengthRequired = nil, want it set whenever the policy is readable")
			}
			if *idp.Policy.PasswordStrengthRequired != tt.want {
				t.Fatalf("PasswordStrengthRequired = %v, want %v for strength %q", *idp.Policy.PasswordStrengthRequired, tt.want, tt.strength)
			}
		})
	}
}

// A weak policy that is readable must still emit false. Only an unreadable
// policy omits the keys, so a consumer can tell "not required" from "unknown".
func TestToIDPPostureEmitsFalseRatherThanOmittingIt(t *testing.T) {
	idp := postureWithPasswordPolicy(&PasswordPolicyConfig{
		MinimumLength:              8,
		AllowedStrength:            strengthWeak,
		EnforceRequirementsAtLogin: false,
	}).ToIDPPosture()

	raw, err := json.Marshal(idp.Policy)
	if err != nil {
		t.Fatalf("marshalling policy: %v", err)
	}
	for _, want := range []string{`"password_strength_required":false`, `"password_policy_enforced_for_existing_users":false`} {
		if !strings.Contains(string(raw), want) {
			t.Fatalf("policy JSON = %s, want it to contain %s", raw, want)
		}
	}
}

func TestToIDPPostureOmitsPasswordPolicyWhenUnreadable(t *testing.T) {
	idp := postureWithPasswordPolicy(nil).ToIDPPosture()

	if idp.Policy == nil {
		t.Fatal("Policy = nil, want the block present for the MFA fields")
	}

	raw, err := json.Marshal(idp.Policy)
	if err != nil {
		t.Fatalf("marshalling policy: %v", err)
	}
	for _, key := range []string{"minimum_password_length", "password_strength_required", "password_policy_enforced_for_existing_users"} {
		if strings.Contains(string(raw), key) {
			t.Fatalf("policy JSON = %s, want %q absent when the policy could not be read", raw, key)
		}
	}
}
