package collector

import (
	"slices"
	"testing"
	"time"

	"github.com/locktivity/epack/componentsdk"
	"github.com/locktivity/epack/componentsdk/collectortest"
)

// customerTarget runs the collector over tenant with config's keys added to
// the kit's and returns its one target declaration. It fails t when the run
// fails or the artifacts don't bear the declaration out.
func customerTarget(t *testing.T, tenant kitTenant, config map[string]any) componentsdk.ResultTarget {
	t.Helper()
	cfg := kitConfig()
	for k, v := range config {
		cfg[k] = v
	}
	replay, err := collectortest.NewReplay(collectortest.Scenario{Name: t.Name(), Responses: tenant.responses()})
	if err != nil {
		t.Fatal(err)
	}
	res := componentsdk.RunInProcess(Spec("test", "collectortest"), Run, componentsdk.InProcessOptions{
		Config:    cfg,
		Secrets:   kitSecrets(),
		Transport: replay,
		Clock:     func() time.Time { return kitNow },
	})
	if res.ExitCode != 0 || res.Result == nil {
		t.Fatalf("run failed with exit %d: %s", res.ExitCode, res.Stderr)
	}
	for _, f := range res.Result.Checks {
		if f.Check == componentsdk.CheckTargets {
			t.Errorf("targets finding %+v", f)
		}
	}
	if len(res.Result.Targets) != 1 || res.Result.Targets[0].Kind != componentsdk.TargetCustomer {
		t.Fatalf("targets = %+v, want the customer alone", res.Result.Targets)
	}
	return res.Result.Targets[0]
}

var customerAt = componentsdk.Location{Path: detailedPath, Pointer: ""}

// Without the customer key, the run collects the admin's own customer, which
// an audit run declares, counted and complete.
func TestTargetsAtAudit(t *testing.T) {
	got := customerTarget(t, cleanTenant(), map[string]any{"level": "audit"})
	if got.ChosenBy != componentsdk.ChosenByDiscovery || got.ConfigKey != "" {
		t.Errorf("customer chosen by %q with %q, want %q", got.ChosenBy, got.ConfigKey, componentsdk.ChosenByDiscovery)
	}
	if got.At == nil || *got.At != customerAt || !slices.Equal(got.Name, []string{"/customer_id"}) || got.Label != "/org_domain" {
		t.Errorf("customer at %+v named by %q with label %q, want %+v named by /customer_id with /org_domain", got.At, got.Name, got.Label, customerAt)
	}
	if got.Count == nil || *got.Count != 1 || got.Complete == nil || !*got.Complete {
		t.Errorf("customer count %v, complete %v; want 1 and true", got.Count, got.Complete)
	}
}

// The customer key chooses the customer by config.
func TestTargetsWithTheCustomerKey(t *testing.T) {
	got := customerTarget(t, cleanTenant(), map[string]any{"level": "audit", "customer": "my_customer"})
	if got.ChosenBy != componentsdk.ChosenByConfig || got.ConfigKey != "customer" {
		t.Errorf("customer chosen by %q with %q, want %q with customer", got.ChosenBy, got.ConfigKey, componentsdk.ChosenByConfig)
	}
}

// A trust run writes no customer ID, so the customer is known by its
// primary domain alone, uncounted.
func TestTargetsAtTrust(t *testing.T) {
	got := customerTarget(t, cleanTenant(), map[string]any{"level": "trust"})
	if got.At == nil || *got.At != customerAt || got.Label != "/org_domain" || got.Count != nil || got.Complete == nil || !*got.Complete {
		t.Errorf("customer = %+v at trust, want it at %+v with its domain label, uncounted and complete", got, customerAt)
	}
}

// When Google refuses the tenant record, the customer ID is null with a gap,
// so the audit run declares the one customer it was pointed at, unnamed and
// incomplete.
func TestTargetsWithTheTenantRecordRefused(t *testing.T) {
	got := customerTarget(t, delegatedAdminTenant(), map[string]any{"level": "audit"})
	if got.At == nil || *got.At != customerAt {
		t.Errorf("customer at %+v, want %+v", got.At, customerAt)
	}
	if got.Count == nil || *got.Count != 1 || got.Complete == nil || *got.Complete {
		t.Errorf("customer count %v, complete %v; want 1 and false", got.Count, got.Complete)
	}
}
