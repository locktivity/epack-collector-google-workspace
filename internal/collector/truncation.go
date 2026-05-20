package collector

import "sort"

// truncateAndWarn caps items with Truncate and, on cap-hit, records a diagnostic
// naming the surface. label is a short noun phrase for the warning (e.g.
// "user inventory", "login audit-log event slice"). Callers that expose
// truncated/dropped on the artifact use the returned values; others discard them.
func truncateAndWarn[T any](c *Collector, items []T, limit int, label string, less func(a, b T) bool) (kept []T, dropped int, truncated bool) {
	kept, dropped, truncated = Truncate(items, limit, less)
	if truncated {
		c.warn("%s truncated to %d (dropped %d)", label, limit, dropped)
	}
	return kept, dropped, truncated
}

// Truncate applies a per-surface cap to a slice. If len(items) is within the cap,
// the slice is returned unchanged with droppedCount=0 and truncated=false. Otherwise
// the slice is sorted stably with the provided less function and the first maxItems
// rows are returned; remaining rows are dropped and truncated=true.
//
// Surfaces use this to keep internal-level output bounded for very large orgs.
// The sort order is the surface's choice (users ACTIVE-first then email-asc,
// groups by member-count-desc, audit-log events by timestamp-desc, and so on),
// so on cap-hit the most posture-relevant rows stick.
func Truncate[T any](items []T, maxItems int, less func(a, b T) bool) (kept []T, droppedCount int, truncated bool) {
	if len(items) <= maxItems {
		return items, 0, false
	}
	sort.SliceStable(items, func(i, j int) bool { return less(items[i], items[j]) })
	return items[:maxItems], len(items) - maxItems, true
}
