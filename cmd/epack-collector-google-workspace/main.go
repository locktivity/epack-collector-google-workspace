// epack-collector-google-workspace collects Google Workspace identity posture.
package main

import (
	"errors"
	"time"
	_ "time/tzdata" // Embed timezone database for minimal container environments.

	"google.golang.org/api/googleapi"

	"github.com/locktivity/epack-collector-google-workspace/internal/collector"
	"github.com/locktivity/epack/componentsdk"
)

var (
	Version = "dev"
	Commit  = "unknown"
)

func main() {
	componentsdk.RunCollector(componentsdk.CollectorSpec{
		Name:        "google-workspace",
		Version:     Version,
		Commit:      Commit,
		Description: "Collects Google Workspace identity posture metrics",
		Timeout:     5 * time.Minute,
	}, run)
}

func run(ctx componentsdk.CollectorContext) error {
	cfg := ctx.Config()
	config := collector.Config{
		Customer:        getString(cfg, "customer"),
		AdminEmail:      getString(cfg, "admin_email"),
		CredentialsJSON: ctx.Secret("GOOGLE_SERVICE_ACCOUNT_JSON"),
		OnStatus:        ctx.Status,
		OnProgress:      ctx.Progress,
	}

	if config.AdminEmail == "" {
		return componentsdk.NewConfigError("admin_email is required")
	}
	if config.CredentialsJSON == "" {
		return componentsdk.NewConfigError("authentication required: provide GOOGLE_SERVICE_ACCOUNT_JSON")
	}

	c, err := collector.New(ctx.Context(), config)
	if err != nil {
		return componentsdk.NewConfigError("creating collector: %v", err)
	}

	posture, err := c.Collect(ctx.Context())
	if err != nil {
		return classifyError(err)
	}

	artifacts := []componentsdk.CollectedArtifact{
		{
			Data: posture,
			Path: "artifacts/google-workspace.json",
		},
	}

	if idpPosture := posture.ToIDPPosture(); idpPosture != nil {
		artifacts = append(artifacts, componentsdk.CollectedArtifact{
			Data:   idpPosture,
			Schema: "evidencepack/idp-posture@v1",
			Path:   "artifacts/google-workspace.idp-posture.json",
		})
	}

	return ctx.Emit(artifacts)
}

func classifyError(err error) error {
	var apiErr *googleapi.Error
	if errors.As(err, &apiErr) {
		switch apiErr.Code {
		case 400, 404:
			return componentsdk.NewConfigError("collecting posture: %v", err)
		case 401:
			return componentsdk.NewAuthError("collecting posture: %v", err)
		case 403:
			if isRateLimitOrQuota(apiErr) {
				return componentsdk.NewNetworkError("collecting posture: %v", err)
			}
			return componentsdk.NewAuthError("collecting posture: %v", err)
		case 429, 500, 502, 503:
			return componentsdk.NewNetworkError("collecting posture: %v", err)
		}
	}
	return componentsdk.NewNetworkError("collecting posture: %v", err)
}

func isRateLimitOrQuota(apiErr *googleapi.Error) bool {
	for _, item := range apiErr.Errors {
		switch item.Reason {
		case "rateLimitExceeded", "userRateLimitExceeded", "quotaExceeded":
			return true
		}
	}
	return false
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
