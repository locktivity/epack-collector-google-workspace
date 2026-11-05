package googleworkspace

import (
	"context"
	"net/http"
	"os"
	"strings"
	"testing"
	"time"
)

// TestPasswordPolicyShape checks the two things about the Policy API that can
// only be confirmed against a live tenant, and that a future Google change
// could silently break:
//
//   - the filter is accepted. Google's documented escaped-dot form is rejected
//     with "Error(7003): Filter is invalid"; only the plain dot works.
//   - the setting value still uses the field names passwordSettingValue expects.
//     The discovery document types the value as an opaque message, so a rename
//     would otherwise parse to zeroes and read as a maximally permissive policy.
//
// Skipped unless credentials are supplied. Prints setting values only: the org
// unit, group, resource name, and CEL query on each policy are deliberately not
// printed, matching what the collector refuses to read.
func TestPasswordPolicyShape(t *testing.T) {
	creds := os.Getenv("GOOGLE_SERVICE_ACCOUNT_JSON")
	adminEmail := strings.TrimSpace(os.Getenv("GOOGLE_WORKSPACE_E2E_ADMIN_EMAIL"))
	if creds == "" || adminEmail == "" {
		t.Skip("Skipping: set GOOGLE_SERVICE_ACCOUNT_JSON and GOOGLE_WORKSPACE_E2E_ADMIN_EMAIL to run")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	client, err := NewClient(ctx, adminEmail, AuthConfig{CredentialsJSON: creds}, http.DefaultTransport)
	if err != nil {
		t.Fatalf("NewClient() error = %v", err)
	}

	customerID := strings.TrimSpace(os.Getenv("GOOGLE_WORKSPACE_E2E_CUSTOMER"))
	if customer, err := client.GetCustomer(ctx, customerID); err == nil && customer.ID != "" {
		customerID = customer.ID
	}

	var policies []PasswordPolicy
	if err := client.ListPasswordPolicies(ctx, customerID, func(batch []PasswordPolicy) error {
		policies = append(policies, batch...)
		return nil
	}); err != nil {
		t.Fatalf("ListPasswordPolicies() error = %v", err)
	}

	if len(policies) == 0 {
		t.Skip("tenant returned no password policy; nothing to verify")
	}

	for i, policy := range policies {
		t.Logf("policy %d: %+v", i+1, policy)

		// A parse failure looks like a maximally permissive policy rather than
		// an error, so assert the value actually carried through. The admin
		// console will not accept a minimum below 8.
		if policy.MinimumLength < 8 {
			t.Errorf("policy %d: MinimumLength = %d, want at least 8; the field names in passwordSettingValue no longer match what the API returns", i+1, policy.MinimumLength)
		}
		if policy.AllowedStrength == "" {
			t.Errorf("policy %d: AllowedStrength is empty; the field names in passwordSettingValue no longer match what the API returns", i+1)
		}
	}
}
