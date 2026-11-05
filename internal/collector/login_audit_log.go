package collector

import (
	"context"
	"time"

	"github.com/locktivity/epack/componentsdk"
)

// Security-relevant login event names. A blocked suspicious sign-in has one
// of three event names, and each counts as a suspicious login.
const (
	loginEventFailure                 = "login_failure"
	loginEventSuspicious              = "suspicious_login"
	loginEventSuspiciousLessSecureApp = "suspicious_login_less_secure_app"
	loginEventSuspiciousProgrammatic  = "suspicious_programmatic_login"
	loginEventPasswordLeak            = "account_disabled_password_leak"
)

var securityRelevantLoginEvents = []string{
	loginEventFailure,
	loginEventSuspicious,
	loginEventSuspiciousLessSecureApp,
	loginEventSuspiciousProgrammatic,
	loginEventPasswordLeak,
}

// scanLoginAuditLog collects the Login audit surface (suspicious / failed
// logins, 7-day window). Audit emits counts; internal adds the event slice with
// actor, timestamp, and IP (for forensic correlation, no geolocation). Returns
// nil (omitted) at trust or on scope / role denial.
func (c *Collector) scanLoginAuditLog(ctx context.Context, scope scanScope) *LoginAuditLog {
	if !scope.level.AtLeast(componentsdk.LevelAudit) {
		return nil
	}

	since := scope.collectedAt.AddDate(0, 0, -AuditLogWindowDays)
	events, ok := c.fetchAuditEvents(ctx, "login_audit_log", scope.customerID, "login", securityRelevantLoginEvents, since)
	if !ok {
		return nil
	}

	result := &LoginAuditLog{WindowDays: AuditLogWindowDays}
	includeEvents := scope.level.AtLeast(componentsdk.LevelInternal)
	var slice []LoginEvent

	for _, e := range events {
		switch e.Name {
		case loginEventSuspicious, loginEventSuspiciousLessSecureApp, loginEventSuspiciousProgrammatic:
			result.SuspiciousLogins++
		case loginEventFailure:
			result.FailedLogins++
		case loginEventPasswordLeak:
			result.PasswordLeakEvents++
		}
		if includeEvents {
			row := LoginEvent{ActorEmail: e.ActorEmail, IPAddress: e.IPAddress, Name: e.Name}
			if !e.Time.IsZero() {
				row.Time = e.Time.UTC().Format(time.RFC3339)
			}
			slice = append(slice, row)
		}
	}

	if includeEvents {
		result.Events, result.TruncatedDropped, result.Truncated = truncateAndWarn(c, slice, AuditEventsCap, "login audit-log event slice", "/login_audit_log/events", func(a, b LoginEvent) bool {
			return a.Time > b.Time
		})
	}
	return result
}
