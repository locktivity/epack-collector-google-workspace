package collector

import (
	"context"
	"strings"
	"time"

	"github.com/locktivity/epack-collector-google-workspace/internal/googleworkspace"
	"github.com/locktivity/epack/componentsdk"
)

const (
	driveEventChangeUserAccess        = "change_user_access"
	driveEventChangeDocumentVisbility = "change_document_visibility"
)

var driveExternalSharingEvents = []string{driveEventChangeUserAccess, driveEventChangeDocumentVisbility}

// scanDriveExternalSharing collects the Drive external-sharing audit surface.
// Audit emits external-share and public-on-web event counts over a 30-day
// window; internal adds an event slice over a tighter 7-day window. File names
// and contents are never emitted; recipients appear as their email domain only.
// Returns nil (omitted) at trust or on scope / role denial.
func (c *Collector) scanDriveExternalSharing(ctx context.Context, scope scanScope) *DriveExternalSharing {
	if !scope.level.AtLeast(componentsdk.LevelAudit) {
		return nil
	}

	since := scope.collectedAt.AddDate(0, 0, -DriveExternalSharingCountDays)
	events, ok := c.fetchAuditEvents(ctx, "drive_external_sharing", scope.customerID, "drive", driveExternalSharingEvents, since)
	if !ok {
		return nil
	}

	result := &DriveExternalSharing{CountWindowDays: DriveExternalSharingCountDays}
	includeEvents := scope.level.AtLeast(componentsdk.LevelInternal)
	eventWindowStart := scope.collectedAt.AddDate(0, 0, -AuditLogWindowDays)
	if includeEvents {
		result.EventWindowDays = AuditLogWindowDays
	}
	var slice []DriveShareEvent

	for _, e := range events {
		recipient := e.Parameters["target_user"]
		recipientDomain := emailDomain(recipient)
		isExternal := recipientDomain != "" && !strings.EqualFold(recipientDomain, scope.primaryDomain)

		switch e.Name {
		case driveEventChangeUserAccess:
			if isExternal {
				result.ExternalShareEvents++
			}
		case driveEventChangeDocumentVisbility:
			if isPublicVisibility(e) {
				result.PublicOnWebEvents++
			}
		}

		if includeEvents && !e.Time.Before(eventWindowStart) && (isExternal || e.Name == driveEventChangeDocumentVisbility) {
			row := DriveShareEvent{
				FileID:          e.Parameters["doc_id"],
				SharerEmail:     e.ActorEmail,
				RecipientDomain: recipientDomain,
				TargetRole:      driveTargetRole(e),
			}
			if !e.Time.IsZero() {
				row.Time = e.Time.UTC().Format(time.RFC3339)
			}
			slice = append(slice, row)
		}
	}

	if includeEvents {
		result.Events, result.TruncatedDropped, result.Truncated = truncateAndWarn(c, slice, AuditEventsCap, "drive external-sharing event slice", func(a, b DriveShareEvent) bool {
			return a.Time > b.Time
		})
	}
	return result
}

// emailDomain returns the host part of an email address, or "" if there is no
// "@". The full address is never retained; only the domain leaves this function
// (sharing-recipient privacy).
func emailDomain(email string) string {
	parts := strings.SplitN(email, "@", 2)
	if len(parts) != 2 {
		return ""
	}
	return parts[1]
}

func isPublicVisibility(e googleworkspace.AuditEvent) bool {
	v := strings.ToLower(e.Parameters["visibility"])
	return strings.Contains(v, "public") || strings.Contains(v, "people_with_link")
}

func driveTargetRole(e googleworkspace.AuditEvent) string {
	if roles := e.MultiParameters["new_value"]; len(roles) > 0 {
		return roles[0]
	}
	return e.Parameters["new_value"]
}
