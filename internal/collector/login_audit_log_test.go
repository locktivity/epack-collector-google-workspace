package collector

import (
	"context"
	"testing"
	"time"

	"github.com/locktivity/epack-collector-google-workspace/internal/googleworkspace"
	"github.com/locktivity/epack/componentsdk"
)

// The challenges of one sign-in are grouped into one activity, so an activity
// returned for login_failure can hold other events.
func TestScanLoginAuditLogListsOnlyTheSecurityEvents(t *testing.T) {
	const failureOnly = `{"name":"login_failure"}`
	const withChallenge = `{"name":"login_challenge","parameters":[{"name":"login_challenge_status","value":"Failed"}]},{"name":"login_failure"}`
	for _, events := range []string{failureOnly, withChallenge} {
		tenant := cleanTenant()
		tenant.activities = map[string]map[string]string{"login": {
			"login_failure": `{"kind":"admin#reports#activities","items":[{"actor":{"email":"bob@example.com"},"ipAddress":"203.0.113.7","id":{"time":"2026-04-07T10:00:00.000Z","applicationName":"login"},"events":[` + events + `]}]}`,
		}}
		log := runKitTenant(t, tenant).LoginAuditLog
		if log == nil {
			t.Fatal("the run left out login_audit_log")
		}
		if log.FailedLogins != 1 || len(log.Events) != 1 || log.Events[0].Name != loginEventFailure {
			t.Errorf("events %s gave failed_logins %d and rows %+v, want one login_failure", events, log.FailedLogins, log.Events)
		}
	}
}

func TestScanLoginAuditLogCountsEverySuspiciousLoginEvent(t *testing.T) {
	now := time.Date(2026, 4, 8, 12, 0, 0, 0, time.UTC)
	recent := now.AddDate(0, 0, -2)
	client := &mockClient{
		customer:    googleworkspace.Customer{ID: "C123", PrimaryDomain: "example.com"},
		usageReport: googleworkspace.CustomerUsageReport{NumUsers: 5},
		users:       []googleworkspace.User{{PrimaryEmail: "u@example.com", LastLoginTime: now}},
		activitiesByApp: map[string][]googleworkspace.AuditEvent{"login": {
			{Time: recent, ActorEmail: "a@example.com", Name: "suspicious_login"},
			{Time: recent, ActorEmail: "b@example.com", Name: "suspicious_login_less_secure_app"},
			{Time: recent, ActorEmail: "c@example.com", Name: "suspicious_programmatic_login"},
			{Time: recent, ActorEmail: "d@example.com", Name: "login_failure"},
			{Time: recent, ActorEmail: "e@example.com", Name: "account_disabled_password_leak"},
		}},
	}
	c := NewWithClient(Config{AdminEmail: "admin@example.com", Now: func() time.Time { return now }}, client)
	posture, err := c.Collect(context.Background(), componentsdk.LevelInternal)
	if err != nil {
		t.Fatalf("Collect() error = %v", err)
	}

	log := posture.LoginAuditLog
	if log.SuspiciousLogins != 3 || log.FailedLogins != 1 || log.PasswordLeakEvents != 1 {
		t.Fatalf("login counts = %+v, want 3 suspicious, 1 failed, and 1 leaked password", log)
	}
	if len(log.Events) != 5 {
		t.Fatalf("login events = %+v, want all 5", log.Events)
	}
}
