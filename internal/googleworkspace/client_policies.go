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
	return listSettingValues(ctx, c, customerID, passwordSettingType, "password", func(raw []byte) (PasswordPolicy, error) {
		var value passwordSettingValue
		if err := json.Unmarshal(raw, &value); err != nil {
			return PasswordPolicy{}, invalidResponse("parsing password setting value: %v", err)
		}
		return PasswordPolicy{
			MinimumLength:              value.MinimumLength,
			MaximumLength:              value.MaximumLength,
			AllowedStrength:            value.AllowedStrength,
			EnforceRequirementsAtLogin: value.EnforceRequirementsAtLogin,
			AllowReuse:                 value.AllowReuse,
			ExpirationDays:             durationToDays(value.ExpirationDuration),
		}, nil
	}, callback)
}

// sessionSettingType and lessSecureAppsSettingType are the Policy API
// settings that hold the web session length and whether users can reach
// apps that use less secure sign-in. Their dots are unescaped, as in
// passwordSettingType.
const (
	sessionSettingType        = `^settings/security.session_controls$`
	lessSecureAppsSettingType = `^settings/security.less_secure_apps$`
)

// sessionSettingValue and lessSecureAppsSettingValue mirror the JSON in those
// policies' setting values, with the field names from the Policy API
// supported-settings reference. The JSON leaves out a false boolean.
type sessionSettingValue struct {
	WebSessionDuration string `json:"webSessionDuration"`
}

type lessSecureAppsSettingValue struct {
	AllowLessSecureApps bool `json:"allowLessSecureApps"`
}

// ListSessionPolicies lists the web session length of each session controls
// policy for the customer, one per org unit or group that sets one. A policy
// without a positive webSessionDuration fails the read, since its session
// length is unknown.
func (c *APIClient) ListSessionPolicies(ctx context.Context, customerID string, callback func([]SessionPolicy) error) error {
	return listSettingValues(ctx, c, customerID, sessionSettingType, "session controls", func(raw []byte) (SessionPolicy, error) {
		var value sessionSettingValue
		if err := json.Unmarshal(raw, &value); err != nil {
			return SessionPolicy{}, invalidResponse("parsing session controls setting value: %v", err)
		}
		seconds, err := strconv.ParseFloat(strings.TrimSuffix(value.WebSessionDuration, "s"), 64)
		if err != nil || seconds <= 0 {
			return SessionPolicy{}, invalidResponse("a session controls policy has no positive webSessionDuration")
		}
		return SessionPolicy{WebSessionSeconds: seconds}, nil
	}, callback)
}

// ListLessSecureAppsPolicies lists whether each less secure apps policy for
// the customer lets users reach apps that use less secure sign-in.
func (c *APIClient) ListLessSecureAppsPolicies(ctx context.Context, customerID string, callback func([]LessSecureAppsPolicy) error) error {
	return listSettingValues(ctx, c, customerID, lessSecureAppsSettingType, "less secure apps", func(raw []byte) (LessSecureAppsPolicy, error) {
		var value lessSecureAppsSettingValue
		if err := json.Unmarshal(raw, &value); err != nil {
			return LessSecureAppsPolicy{}, invalidResponse("parsing less secure apps setting value: %v", err)
		}
		return LessSecureAppsPolicy{Allowed: value.AllowLessSecureApps}, nil
	}, callback)
}

// listSettingValues lists the customer's policies of one setting type, parses
// each one's value with parse, and passes each page that holds any to
// callback. A policy with no setting value is skipped. The org unit, group,
// resource name, and CEL query on each policy are never read.
func listSettingValues[T any](ctx context.Context, c *APIClient, customerID, settingType, what string, parse func([]byte) (T, error), callback func([]T) error) error {
	if customerID == "" {
		customerID = DefaultCustomerKey
	}

	call := c.cloudIdentityPolicies.Policies.List().
		Filter(fmt.Sprintf("setting.type.matches('%s') && customer == \"customers/%s\"", settingType, customerID)).
		PageSize(maxPoliciesPerPage)

	err := call.Pages(named(ctx, OpPoliciesList), func(resp *cloudidentity.ListPoliciesResponse) error {
		values := make([]T, 0, len(resp.Policies))
		for _, policy := range resp.Policies {
			if policy == nil || policy.Setting == nil || len(policy.Setting.Value) == 0 {
				continue
			}
			value, err := parse(policy.Setting.Value)
			if err != nil {
				return err
			}
			values = append(values, value)
		}
		if len(values) == 0 {
			return nil
		}
		return callback(values)
	})
	return listError(OpPoliciesList, "listing "+what+" policies", err)
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
