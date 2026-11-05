package collector

import (
	"context"
	"slices"
	"time"

	"github.com/locktivity/epack/componentsdk"
)

// securityRelevantAdminEvents maps the admin Reports API event names this
// collector counts to the category bucket reported at audit level. The keys are
// eventName values from Google's admin activity reference, passed as the
// EventName filter to the Reports API; the values are our reporting buckets.
var securityRelevantAdminEvents = map[string]string{
	// User lifecycle and admin-privilege grants.
	"SUSPEND_USER":           "USER_SETTINGS",
	"UNSUSPEND_USER":         "USER_SETTINGS",
	"DELETE_USER":            "USER_SETTINGS",
	"GRANT_ADMIN_PRIVILEGE":  "USER_SETTINGS",
	"REVOKE_ADMIN_PRIVILEGE": "USER_SETTINGS",

	// 2-step verification, OAuth app access, and session policy.
	"ENFORCE_STRONG_AUTHENTICATION":                "SECURITY_SETTINGS",
	"ALLOW_STRONG_AUTHENTICATION":                  "SECURITY_SETTINGS",
	"CHANGE_ALLOWED_TWO_STEP_VERIFICATION_METHODS": "SECURITY_SETTINGS",
	"CHANGE_TWO_STEP_VERIFICATION_FREQUENCY":       "SECURITY_SETTINGS",
	"ALLOW_SERVICE_FOR_OAUTH2_ACCESS":              "SECURITY_SETTINGS",
	"DISALLOW_SERVICE_FOR_OAUTH2_ACCESS":           "SECURITY_SETTINGS",
	"BLOCK_ALL_THIRD_PARTY_API_ACCESS":             "SECURITY_SETTINGS",
	"UNBLOCK_ALL_THIRD_PARTY_API_ACCESS":           "SECURITY_SETTINGS",
	"SESSION_CONTROL_SETTINGS_CHANGE":              "SECURITY_SETTINGS",

	// SSO and password policy.
	"CHANGE_SSO_SETTINGS":        "DOMAIN_SETTINGS",
	"TOGGLE_SSO_ENABLED":         "DOMAIN_SETTINGS",
	"UPLOAD_OAUTH_CERTIFICATE":   "DOMAIN_SETTINGS",
	"CHANGE_PASSWORD_MIN_LENGTH": "DOMAIN_SETTINGS",
	"CHANGE_PASSWORD_MAX_LENGTH": "DOMAIN_SETTINGS",

	// Admin role and privilege management.
	"CREATE_ROLE":      "ADMIN_ROLES",
	"DELETE_ROLE":      "ADMIN_ROLES",
	"RENAME_ROLE":      "ADMIN_ROLES",
	"UPDATE_ROLE":      "ADMIN_ROLES",
	"ASSIGN_ROLE":      "ADMIN_ROLES",
	"UNASSIGN_ROLE":    "ADMIN_ROLES",
	"ADD_PRIVILEGE":    "ADMIN_ROLES",
	"REMOVE_PRIVILEGE": "ADMIN_ROLES",

	// Group lifecycle and settings.
	"CREATE_GROUP":         "GROUP_SETTINGS",
	"DELETE_GROUP":         "GROUP_SETTINGS",
	"CHANGE_GROUP_SETTING": "GROUP_SETTINGS",

	// Application (Drive / Docs / Gmail) sharing-policy changes.
	"CHANGE_APPLICATION_SETTING": "APPLICATION_SETTINGS",
	"CREATE_APPLICATION_SETTING": "APPLICATION_SETTINGS",
	"DELETE_APPLICATION_SETTING": "APPLICATION_SETTINGS",
}

// scanAdminAuditLog collects the Admin audit log surface (security-relevant
// admin actions, 7-day window). Audit emits counts by category; internal adds
// the event slice. Returns nil (omitted) at trust or when the events cannot be
// read.
func (c *Collector) scanAdminAuditLog(ctx context.Context, scope scanScope) *AdminAuditLog {
	if !scope.level.AtLeast(componentsdk.LevelAudit) {
		return nil
	}

	eventNames := make([]string, 0, len(securityRelevantAdminEvents))
	for name := range securityRelevantAdminEvents {
		eventNames = append(eventNames, name)
	}
	// Sorted, so the requests and the event slice come in the same order on
	// every run.
	slices.Sort(eventNames)

	since := scope.collectedAt.AddDate(0, 0, -AuditLogWindowDays)
	events, ok := c.fetchAuditEvents(ctx, "admin_audit_log", scope.customerID, "admin", eventNames, since)
	if !ok {
		return nil
	}

	result := &AdminAuditLog{WindowDays: AuditLogWindowDays, CountsByCategory: map[string]int{}}
	includeEvents := scope.level.AtLeast(componentsdk.LevelInternal)
	var slice []AuditLogEvent

	for _, e := range events {
		category := securityRelevantAdminEvents[e.Name]
		result.CountsByCategory[category]++
		if includeEvents {
			row := AuditLogEvent{ActorEmail: e.ActorEmail, Name: e.Name, Category: category}
			if !e.Time.IsZero() {
				row.Time = e.Time.UTC().Format(time.RFC3339)
			}
			slice = append(slice, row)
		}
	}

	if includeEvents {
		result.Events, result.TruncatedDropped, result.Truncated = truncateAndWarn(c, slice, AuditEventsCap, "admin audit-log event slice", "/admin_audit_log/events", func(a, b AuditLogEvent) bool {
			return a.Time > b.Time
		})
	}
	return result
}
