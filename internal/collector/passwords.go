package collector

import (
	"context"
	"strings"

	"github.com/locktivity/epack-collector-google-workspace/internal/googleworkspace"
)

const (
	strengthStrong = "strong"
	strengthWeak   = "weak"
)

// scanPasswordPolicy collects the tenant password policy (trust and above).
//
// Returns nil whenever the policy could not be read, so the caller leaves the
// fields absent rather than emitting zeroes. An absent minimum length must
// never be readable as a minimum length of zero.
func (c *Collector) scanPasswordPolicy(ctx context.Context, scope scanScope) *PasswordPolicyConfig {
	var policies []googleworkspace.PasswordPolicy
	err := c.client.ListPasswordPolicies(ctx, scope.customerID, func(batch []googleworkspace.PasswordPolicy) error {
		policies = append(policies, batch...)
		return nil
	})
	if err != nil {
		// An edition without the Policy API answers 404, which is a licensing
		// gap the customer may not be able to fix. Checked before the
		// permission paths so it is reported as informational, not as a
		// misconfiguration. Mirrors scanVault.
		if isFeatureNotLicensed(err) {
			c.warnFeatureNotLicensed("password_policy", "Policy API")
			return nil
		}
		c.warnSurfaceScan("password_policy", "cloud-identity.policies.readonly", "Super Admin", err)
		return nil
	}
	if len(policies) == 0 {
		c.warn("surface password_policy: no password policy returned; the tenant may not expose one through the Policy API")
		return nil
	}

	aggregate := aggregatePasswordPolicies(policies)
	return &aggregate
}

// aggregatePasswordPolicies reduces every policy in force to the weakest value
// for each field. See PasswordPolicyConfig for why the floor is the useful
// answer.
func aggregatePasswordPolicies(policies []googleworkspace.PasswordPolicy) PasswordPolicyConfig {
	aggregate := PasswordPolicyConfig{
		AllowedStrength:            strengthStrong,
		EnforceRequirementsAtLogin: true,
		DistinctPolicies:           len(policies),
	}

	neverExpires := false
	longestExpiry := 0

	for i, policy := range policies {
		if i == 0 || policy.MinimumLength < aggregate.MinimumLength {
			aggregate.MinimumLength = policy.MinimumLength
		}
		if policy.MaximumLength > aggregate.MaximumLength {
			aggregate.MaximumLength = policy.MaximumLength
		}
		if !strings.EqualFold(policy.AllowedStrength, "STRONG") {
			aggregate.AllowedStrength = strengthWeak
		}
		if !policy.EnforceRequirementsAtLogin {
			aggregate.EnforceRequirementsAtLogin = false
		}
		if policy.AllowReuse {
			aggregate.AllowReuse = true
		}

		// 0 means never expires, so it is weaker than any finite expiry and has
		// to win over a plain maximum.
		if policy.ExpirationDays == 0 {
			neverExpires = true
		} else if policy.ExpirationDays > longestExpiry {
			longestExpiry = policy.ExpirationDays
		}
	}

	if !neverExpires {
		aggregate.ExpirationDays = longestExpiry
	}

	return aggregate
}
