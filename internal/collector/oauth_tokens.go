package collector

import (
	"context"
	"strings"
	"time"

	"github.com/locktivity/epack/componentsdk"
)

const tokenEventAuthorize = "authorize"

// scanOAuthTokens collects the OAuth token audit surface (connected apps,
// 7-day window; internal only). Emits issuance counts, counts by app and by
// scope-sensitivity bucket, plus the per-token list. Token values are never
// available via the API and are never emitted. Returns nil below internal or on
// scope / role denial.
func (c *Collector) scanOAuthTokens(ctx context.Context, scope scanScope) *OAuthTokens {
	if !scope.level.AtLeast(componentsdk.LevelInternal) {
		return nil
	}

	since := scope.collectedAt.AddDate(0, 0, -AuditLogWindowDays)
	events, ok := c.fetchAuditEvents(ctx, "oauth_tokens", scope.customerID, "token", []string{tokenEventAuthorize}, since)
	if !ok {
		return nil
	}

	result := &OAuthTokens{
		WindowDays:               AuditLogWindowDays,
		CountsByApp:              map[string]int{},
		CountsByScopeSensitivity: map[string]int{},
	}

	apps := map[string]struct{}{}
	var tokens []OAuthToken

	for _, e := range events {
		clientID := e.Parameters["client_id"]
		appName := e.Parameters["app_name"]
		scopes := e.MultiParameters["scope"]

		result.TokensIssued++
		if clientID != "" {
			apps[clientID] = struct{}{}
		}

		label := appName
		if label == "" {
			label = clientID
		}
		result.CountsByApp[label]++
		result.CountsByScopeSensitivity[scopeSensitivity(scopes)]++

		row := OAuthToken{
			UserEmail:   e.ActorEmail,
			ClientID:    clientID,
			DisplayName: appName,
			Scopes:      scopes,
		}
		if !e.Time.IsZero() {
			row.GrantedAt = e.Time.UTC().Format(time.RFC3339)
		}
		tokens = append(tokens, row)
	}
	result.AppsWithNewTokens = len(apps)

	result.Tokens, result.TruncatedDropped, result.Truncated = truncateAndWarn(c, tokens, AuditEventsCap, "oauth token list", "/oauth_tokens/tokens", func(a, b OAuthToken) bool {
		return a.GrantedAt > b.GrantedAt
	})
	return result
}

// scopeSensitivity buckets an app's OAuth scopes into low / medium / high, where
// the bucket is the highest sensitivity among the scopes. Low covers identity
// and profile scopes only, and medium covers read-only access. High covers
// every other scope, such as read-write access to mail, Drive, or calendar. A
// scope that is not known to be read-only counts as high, since it may be able
// to change data.
func scopeSensitivity(scopes []string) string {
	bucket := "low"
	for _, s := range scopes {
		switch classifyScope(s) {
		case "high":
			return "high"
		case "medium":
			bucket = "medium"
		}
	}
	return bucket
}

func classifyScope(scope string) string {
	s := strings.ToLower(scope)
	switch {
	case strings.Contains(s, "userinfo"), strings.Contains(s, "openid"), strings.HasSuffix(s, "/profile"), strings.HasSuffix(s, "/email"), s == "profile", s == "email":
		return "low"
	case isReadOnlyScope(s):
		return "medium"
	default:
		return "high"
	}
}

// isReadOnlyScope checks a lowercased scope for Google's read-only markers,
// such as drive.readonly, devstorage.read_only, cloud-platform.read-only, and
// fitness.activity.read. devstorage.read_write is not read-only.
func isReadOnlyScope(s string) bool {
	return strings.Contains(s, "readonly") || strings.Contains(s, "read_only") || strings.Contains(s, "read-only") || strings.HasSuffix(s, ".read")
}
