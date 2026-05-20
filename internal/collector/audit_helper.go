package collector

import (
	"context"
	"time"

	"github.com/locktivity/epack-collector-google-workspace/internal/googleworkspace"
)

// fetchAuditEvents fetches Reports API activity events for an application within
// the window, accumulating across pages and event names. It degrades
// gracefully: on a "data not yet available" lag error it warns and returns the
// partial results gathered so far (the 7-day window absorbs Google's audit-log
// lag, so an aggressive sleep-retry is unnecessary); on scope / role denial it
// warns and signals the surface should be omitted (ok=false).
func (c *Collector) fetchAuditEvents(ctx context.Context, surface, customerID, application string, eventNames []string, since time.Time) (events []googleworkspace.AuditEvent, ok bool) {
	err := c.client.ListActivities(ctx, customerID, application, eventNames, since, func(batch []googleworkspace.AuditEvent) error {
		events = append(events, batch...)
		return nil
	})
	if err != nil {
		if isDataNotYetAvailable(err) {
			c.warn("surface %s: audit-log data not yet available for the requested window; returning partial results", surface)
			return events, true
		}
		c.warnSurfaceScan(surface, "admin.reports.audit.readonly", "Reports Admin (or Super Admin)", err)
		return nil, false
	}
	return events, true
}
