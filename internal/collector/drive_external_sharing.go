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
// Returns nil (omitted) at trust or when the events cannot be read. Telling an
// external recipient from an internal one takes the tenant's primary domain,
// so the external count and the event slice are left out without it.
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
	domainKnown := scope.primaryDomain != ""
	externalShares := 0
	var slice []DriveShareEvent

	for _, e := range events {
		recipientDomain := targetDomain(e.Parameters["target_user"])
		// A change_user_access event whose new role is none took the
		// target's access away.
		isExternal := e.Name == driveEventChangeUserAccess && driveTargetRole(e) != "none" &&
			recipientDomain != "" && !strings.EqualFold(recipientDomain, scope.primaryDomain)

		switch e.Name {
		case driveEventChangeUserAccess:
			if isExternal {
				externalShares++
			}
		case driveEventChangeDocumentVisbility:
			if isPublicVisibility(e) {
				result.PublicOnWebEvents++
			}
		}

		if includeEvents && domainKnown && !e.Time.Before(eventWindowStart) && (isExternal || e.Name == driveEventChangeDocumentVisbility) {
			row := DriveShareEvent{
				FileID:          e.Parameters["doc_id"],
				SharerEmail:     e.ActorEmail,
				RecipientDomain: recipientDomain,
			}
			// On a visibility change, new_value holds the new link
			// visibility, which is not a role.
			if e.Name == driveEventChangeUserAccess {
				row.TargetRole = driveTargetRole(e)
			}
			if !e.Time.IsZero() {
				row.Time = e.Time.UTC().Format(time.RFC3339)
			}
			slice = append(slice, row)
		}
	}

	if !domainKnown {
		c.gaps.leaveOutAs("/org_domain", "/drive_external_sharing/external_share_events")
		if includeEvents {
			c.gaps.leaveOutAs("/org_domain", "/drive_external_sharing/events")
		}
		return result
	}
	result.ExternalShareEvents = &externalShares
	if includeEvents {
		result.Events, result.TruncatedDropped, result.Truncated = truncateAndWarn(c, slice, AuditEventsCap, "drive external-sharing event slice", "/drive_external_sharing/events", func(a, b DriveShareEvent) bool {
			return a.Time > b.Time
		})
	}
	return result
}

// targetDomain returns the domain of a share's target_user. The target is an
// email address, or the name of a domain when the file was shared with a
// whole domain. The full address is never retained. Only the domain leaves
// this function (sharing-recipient privacy).
func targetDomain(target string) string {
	if _, domain, ok := strings.Cut(target, "@"); ok {
		return domain
	}
	return target
}

// isPublicVisibility checks whether a visibility change left the file public
// on the web or open to anyone with the link. Under public_in_the_domain and
// people_within_domain_with_link, only the domain's audience can open it.
func isPublicVisibility(e googleworkspace.AuditEvent) bool {
	switch strings.ToLower(e.Parameters["visibility"]) {
	case "public_on_the_web", "people_with_link":
		return true
	}
	return false
}

func driveTargetRole(e googleworkspace.AuditEvent) string {
	if roles := e.MultiParameters["new_value"]; len(roles) > 0 {
		return roles[0]
	}
	return e.Parameters["new_value"]
}
