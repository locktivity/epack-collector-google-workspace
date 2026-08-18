package googleworkspace

import (
	"context"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"

	cloudidentity "google.golang.org/api/cloudidentity/v1"
)

// passwordSettingType is the Policy API setting that holds the tenant password
// policy. The filter accepts at most one setting-type clause and one customer
// clause, combined with &&.
//
// The dot is deliberately unescaped. Google's filter documentation shows an
// escaped dot, but every escaped variant is rejected with "Error(7003): Filter
// is invalid" against a live tenant; only the plain dot is accepted. It matches
// any character rather than a literal dot, which is harmless here because no
// other setting type collides.
const passwordSettingType = `^settings/security.password$`

// passwordSettingValue mirrors the JSON in a policy's setting value. The
// discovery document types the value as an opaque message, so the field names
// come from the Policy API supported-settings reference rather than generated
// code.
type passwordSettingValue struct {
	MinimumLength              int    `json:"minimumLength"`
	MaximumLength              int    `json:"maximumLength"`
	AllowedStrength            string `json:"allowedStrength"`
	EnforceRequirementsAtLogin bool   `json:"enforceRequirementsAtLogin"`
	AllowReuse                 bool   `json:"allowReuse"`
	ExpirationDuration         string `json:"expirationDuration"`
}

// ListPasswordPolicies lists the tenant password policies for the customer.
//
// A tenant may define a policy per org unit or group, so this can return more
// than one. The caller aggregates them; the org unit, group, resource name, and
// CEL query on each policy are deliberately never read.
func (c *APIClient) ListPasswordPolicies(ctx context.Context, customerID string, callback func([]PasswordPolicy) error) error {
	if customerID == "" {
		customerID = DefaultCustomerKey
	}

	call := c.cloudIdentityPolicies.Policies.List().
		Filter(fmt.Sprintf("setting.type.matches('%s') && customer == \"customers/%s\"", passwordSettingType, customerID)).
		PageSize(maxPoliciesPerPage)

	return call.Pages(ctx, func(resp *cloudidentity.ListPoliciesResponse) error {
		policies := make([]PasswordPolicy, 0, len(resp.Policies))
		for _, policy := range resp.Policies {
			if policy == nil || policy.Setting == nil || len(policy.Setting.Value) == 0 {
				continue
			}

			var value passwordSettingValue
			if err := json.Unmarshal(policy.Setting.Value, &value); err != nil {
				return fmt.Errorf("parsing password setting value: %w", err)
			}

			policies = append(policies, PasswordPolicy{
				MinimumLength:              value.MinimumLength,
				MaximumLength:              value.MaximumLength,
				AllowedStrength:            value.AllowedStrength,
				EnforceRequirementsAtLogin: value.EnforceRequirementsAtLogin,
				AllowReuse:                 value.AllowReuse,
				ExpirationDays:             durationToDays(value.ExpirationDuration),
			})
		}
		if len(policies) == 0 {
			return nil
		}
		return callback(policies)
	})
}

// durationToDays converts a protobuf duration string such as "7776000s" to
// whole days. An unset or unparsable duration is 0, which the aggregation
// treats as "never expires".
func durationToDays(duration string) int {
	seconds, err := strconv.ParseFloat(strings.TrimSuffix(duration, "s"), 64)
	if err != nil || seconds <= 0 {
		return 0
	}
	return int(seconds / 86400)
}
