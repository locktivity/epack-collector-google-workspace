package googleworkspace

import (
	"context"
	"strconv"
	"strings"
	"time"

	reports "google.golang.org/api/admin/reports/v1"
	"google.golang.org/api/googleapi"
)

// ListContextAwareAccessEvents lists Context-Aware Access deny events since the
// provided start time. This is used to detect deny events that explicitly cite
// device-state conditions.
func (c *APIClient) ListContextAwareAccessEvents(ctx context.Context, customerID string, startTime time.Time, callback func([]ContextAwareAccessEvent) error) error {
	call := c.auditReports.Activities.List("all", "context_aware_access").
		CustomerId(customerID).
		EventName("ACCESS_DENY_EVENT").
		StartTime(startTime.UTC().Format(time.RFC3339)).
		MaxResults(maxActivitiesPerPage).
		Fields(
			googleapi.Field("nextPageToken,items(actor/email,id/time,events(name,parameters(name,value,multiValue,intValue,boolValue)))"),
		)

	return call.Pages(ctx, func(resp *reports.Activities) error {
		events := make([]ContextAwareAccessEvent, 0, len(resp.Items))
		for _, activity := range resp.Items {
			events = append(events, mapContextAwareAccessEvents(activity)...)
		}
		if len(events) == 0 {
			return nil
		}
		return callback(events)
	})
}

// ListActivities lists Reports API activity events for an application within a
// time window. When eventNames is non-empty, one filtered request is made per
// event name (the security-relevant subsets are small); when empty, all events
// for the application are returned. Used by the audit-log surfaces.
func (c *APIClient) ListActivities(ctx context.Context, customerID, applicationName string, eventNames []string, startTime time.Time, callback func([]AuditEvent) error) error {
	do := func(eventName string) error {
		call := c.auditReports.Activities.List("all", applicationName).
			CustomerId(customerID).
			StartTime(startTime.UTC().Format(time.RFC3339)).
			MaxResults(maxActivitiesPerPage).
			Fields(googleapi.Field("nextPageToken,items(actor/email,ipAddress,id/time,id/applicationName,events(name,parameters(name,value,multiValue,intValue,boolValue)))"))
		if eventName != "" {
			call = call.EventName(eventName)
		}
		return call.Pages(ctx, func(resp *reports.Activities) error {
			events := mapAuditEvents(resp.Items)
			if len(events) == 0 {
				return nil
			}
			return callback(events)
		})
	}

	if len(eventNames) == 0 {
		return do("")
	}
	for _, name := range eventNames {
		if err := do(name); err != nil {
			return err
		}
	}
	return nil
}

func mapAuditEvents(activities []*reports.Activity) []AuditEvent {
	var out []AuditEvent
	for _, activity := range activities {
		if activity == nil {
			continue
		}
		var occurredAt time.Time
		application := ""
		if activity.Id != nil {
			occurredAt = parseAuditEventTime(activity.Id.Time)
			application = activity.Id.ApplicationName
		}
		actorEmail := ""
		if activity.Actor != nil {
			actorEmail = activity.Actor.Email
		}
		ipAddress := activity.IpAddress
		for _, event := range activity.Events {
			if event == nil {
				continue
			}
			mapped := AuditEvent{
				Time:        occurredAt,
				ActorEmail:  actorEmail,
				IPAddress:   ipAddress,
				Application: application,
				Name:        event.Name,
			}
			for _, p := range event.Parameters {
				if p == nil || p.Name == "" {
					continue
				}
				if len(p.MultiValue) > 0 {
					if mapped.MultiParameters == nil {
						mapped.MultiParameters = map[string][]string{}
					}
					mapped.MultiParameters[p.Name] = p.MultiValue
					continue
				}
				if v := parameterStringValue(p); v != "" {
					if mapped.Parameters == nil {
						mapped.Parameters = map[string]string{}
					}
					mapped.Parameters[p.Name] = v
				}
			}
			out = append(out, mapped)
		}
	}
	return out
}

func mapContextAwareAccessEvents(activity *reports.Activity) []ContextAwareAccessEvent {
	if activity == nil {
		return nil
	}

	var occurredAt time.Time
	if activity.Id != nil {
		occurredAt = parseActivityTime(activity.Id.Time)
	}

	userEmail := ""
	if activity.Actor != nil {
		userEmail = activity.Actor.Email
	}

	events := make([]ContextAwareAccessEvent, 0, len(activity.Events))
	for _, event := range activity.Events {
		if event == nil || event.Name != "ACCESS_DENY_EVENT" {
			continue
		}

		mapped := ContextAwareAccessEvent{
			OccurredAt: occurredAt,
			UserEmail:  userEmail,
		}

		for _, parameter := range event.Parameters {
			if parameter == nil {
				continue
			}
			value := parameterStringValue(parameter)
			switch parameter.Name {
			case "BLOCKED_API_ACCESS":
				mapped.BlockedAPIAccess = value
			case "CAA_ACCESS_LEVEL_APPLIED":
				mapped.AccessLevelApplied = value
			case "CAA_ACCESS_LEVEL_SATISFIED":
				mapped.AccessLevelSatisfied = value
			case "CAA_ACCESS_LEVEL_UNSATISFIED":
				mapped.AccessLevelUnsatisfied = value
			case "CAA_APPLICATION":
				mapped.Application = value
			case "CAA_DEVICE_ID":
				mapped.DeviceID = value
			case "CAA_DEVICE_STATE":
				mapped.DeviceState = value
			}
		}

		events = append(events, mapped)
	}

	return events
}

func parameterStringValue(parameter *reports.ActivityEventsParameters) string {
	if parameter == nil {
		return ""
	}
	if parameter.Value != "" {
		return parameter.Value
	}
	if len(parameter.MultiValue) > 0 {
		return strings.Join(parameter.MultiValue, ",")
	}
	if parameter.IntValue != 0 {
		return strconv.FormatInt(parameter.IntValue, 10)
	}
	if parameter.BoolValue {
		return "true"
	}
	return ""
}

// parseAuditEventTime parses the Reports API activity timestamp, which is an
// RFC3339 string (e.g. "2026-05-01T12:00:00.000Z").
func parseAuditEventTime(raw string) time.Time {
	if raw == "" {
		return time.Time{}
	}
	if ts, err := time.Parse(time.RFC3339, raw); err == nil {
		return ts.UTC()
	}
	return time.Time{}
}

func parseActivityTime(raw string) time.Time {
	if raw == "" {
		return time.Time{}
	}

	seconds, err := strconv.ParseInt(raw, 10, 64)
	if err != nil {
		return time.Time{}
	}

	return time.Unix(seconds, 0).UTC()
}
