package collector

import (
	"time"

	"github.com/locktivity/epack-collector-google-workspace/docs/schema"
	"github.com/locktivity/epack-collector-google-workspace/internal/googleworkspace"
	"github.com/locktivity/epack/componentsdk"
)

// Spec describes the collector to componentsdk.RunCollector.
func Spec(version, commit string) componentsdk.CollectorSpec {
	return componentsdk.CollectorSpec{
		Name:        collectorName,
		Version:     version,
		Commit:      commit,
		Description: "Collects Google Workspace identity posture metrics",
		Timeout:     5 * time.Minute,
		// The normalized idp-posture artifact is checked against the SDK's
		// own schema for its type, with the sentences in Methods added.
		Schemas:  map[string][]byte{detailedPath: schema.V1},
		Methods:  schema.Methods(),
		TraceMap: schema.TraceMap,
		Writes:   []string{idpSchema},
	}
}

// Run is the collector's handler. It fails only for invalid configuration or
// a failed sign-in, and otherwise emits what it collected with a gap recorded
// for each value it could not read.
func Run(ctx componentsdk.CollectorContext) error {
	cfg := ctx.Config()
	config := Config{
		Customer:        getString(cfg, "customer"),
		OrganizationID:  getString(cfg, "organization_id"),
		AccessPolicy:    getString(cfg, "access_policy"),
		AdminEmail:      getString(cfg, "admin_email"),
		CredentialsJSON: ctx.Secret("GOOGLE_SERVICE_ACCOUNT_JSON"),

		AuthMode:                 getString(cfg, "auth_mode"),
		WorkloadIdentityProvider: getString(cfg, "workload_identity_provider"),
		ServiceAccount:           getString(cfg, "service_account"),
		OnStatus:                 ctx.Status,
		OnProgress:               ctx.Progress,
		Now:                      func() time.Time { return componentsdk.Now(ctx) },
		Recorder:                 componentsdk.Records(ctx),
	}

	if config.AdminEmail == "" {
		return componentsdk.NewConfigError("admin_email is required")
	}
	config.HTTPClient = componentsdk.NewHTTPClient(ctx, componentsdk.HTTPOptions{
		CredentialHosts:  googleworkspace.CredentialHosts(config.authConfig()),
		NameOperation:    googleworkspace.NameOperation,
		ClassifyResponse: googleworkspace.ClassifyResponse,
		NamesPermission:  googleworkspace.NamesPermission,
	})

	// Every way of misconfiguring authentication is a config error: the operator
	// changes a profile key or a workflow permission, not a Google grant.
	c, err := New(ctx.Context(), config)
	if err != nil {
		return componentsdk.NewConfigError("creating collector: %v", err)
	}

	posture, err := c.Collect(ctx.Context(), ctx.Level())
	if err != nil {
		return err
	}
	declareTargets(config.Recorder, config.Customer)
	return ctx.Emit(c.Artifacts(posture))
}

// declareTargets declares the customer the run collected: the one the
// customer key names, or without it the admin's own customer. The detailed
// artifact describes it, named by its ID and labelled by its primary domain.
func declareTargets(rec *componentsdk.Recorder, customer string) {
	how, key := componentsdk.ChosenByDiscovery, ""
	if customer != "" {
		how, key = componentsdk.ChosenByConfig, "customer"
	}
	rec.Targets(componentsdk.TargetCustomer, componentsdk.Location{Path: detailedPath, Pointer: ""}, "/customer_id").
		ChosenBy(how, key).
		Label("/org_domain")
}

// Artifacts returns the artifacts for posture: the detailed one, and the
// normalized one when the tenant's primary domain is known. A normalized value
// left out carries the gap of the detailed value it comes from, and a value
// Google Workspace has no data for gets an unsupported gap. Call it once,
// after Collect.
func (c *Collector) Artifacts(posture *OrgPosture) []componentsdk.CollectedArtifact {
	artifacts := []componentsdk.CollectedArtifact{{Data: posture, Path: detailedPath}}
	idp := posture.ToIDPPosture()
	if idp == nil {
		c.gaps.mirror("", "/org_domain")
		return artifacts
	}
	c.recordIDPPostureGaps(posture, componentsdk.Level(posture.CollectedAtLevel))
	return append(artifacts, componentsdk.CollectedArtifact{
		Data:   idp,
		Schema: idpSchema,
		Path:   idpPosturePath,
	})
}

func getString(cfg map[string]any, key string) string {
	if cfg == nil {
		return ""
	}
	if v, ok := cfg[key].(string); ok {
		return v
	}
	return ""
}
