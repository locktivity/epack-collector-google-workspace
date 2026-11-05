package collector

import (
	"context"
	"time"

	"github.com/locktivity/epack-collector-google-workspace/internal/googleworkspace"
	"github.com/locktivity/epack/componentsdk"
)

// fetchAuditEvents fetches Reports API activity events for an application within
// the window, accumulating across pages and event names. surface is the
// surface's key in the artifact. When the events cannot all be read, including
// when Google reports the window's data is not yet available, it warns, leaves
// the surface out with a gap, and returns ok=false: counts over part of the
// window would read as the whole.
func (c *Collector) fetchAuditEvents(ctx context.Context, surface, customerID, application string, eventNames []string, since time.Time) (events []googleworkspace.AuditEvent, ok bool) {
	err := c.client.ListActivities(ctx, customerID, application, eventNames, since, func(batch []googleworkspace.AuditEvent) error {
		events = append(events, batch...)
		return nil
	})
	if err != nil {
		if isDataNotYetAvailable(err) {
			c.warn("surface %s: audit-log data not yet available for the requested window; surface omitted", surface)
			err = componentsdk.CodeError(componentsdk.CodeVendorError, err)
		} else {
			c.warnSurfaceScan(surface, "admin.reports.audit.readonly", "a role with the Reports privilege (or Super Admin)", err)
		}
		c.gaps.leaveOut(failed(err), "/"+surface)
		return nil, false
	}
	return events, true
}
