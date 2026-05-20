package collector

import (
	"reflect"
	"testing"
)

func TestTruncate_WithinCap(t *testing.T) {
	items := []int{3, 1, 2}
	kept, dropped, truncated := Truncate(items, 5, func(a, b int) bool { return a < b })

	if truncated {
		t.Fatalf("truncated = true, want false when within cap")
	}
	if dropped != 0 {
		t.Fatalf("dropped = %d, want 0", dropped)
	}
	// Within cap, the slice is returned unchanged (not sorted).
	if !reflect.DeepEqual(kept, []int{3, 1, 2}) {
		t.Fatalf("kept = %v, want unchanged input order", kept)
	}
}

func TestTruncate_AtCap(t *testing.T) {
	items := []int{1, 2, 3}
	_, dropped, truncated := Truncate(items, 3, func(a, b int) bool { return a < b })
	if truncated || dropped != 0 {
		t.Fatalf("len == cap should not truncate; got truncated=%v dropped=%d", truncated, dropped)
	}
}

func TestTruncate_OverCapSortsAndKeepsMostRelevant(t *testing.T) {
	// less sorts descending so the largest values survive the cap.
	items := []int{1, 5, 3, 4, 2}
	kept, dropped, truncated := Truncate(items, 2, func(a, b int) bool { return a > b })

	if !truncated {
		t.Fatalf("truncated = false, want true over cap")
	}
	if dropped != 3 {
		t.Fatalf("dropped = %d, want 3", dropped)
	}
	if !reflect.DeepEqual(kept, []int{5, 4}) {
		t.Fatalf("kept = %v, want the two largest [5 4]", kept)
	}
}

func TestTruncate_StableForEqualKeys(t *testing.T) {
	type row struct {
		key   int
		order int
	}
	items := []row{{1, 0}, {1, 1}, {1, 2}, {0, 3}}
	kept, _, truncated := Truncate(items, 2, func(a, b row) bool { return a.key > b.key })
	if !truncated {
		t.Fatalf("expected truncation")
	}
	// Equal keys retain input order under a stable sort.
	if kept[0].order != 0 || kept[1].order != 1 {
		t.Fatalf("stable order not preserved: %+v", kept)
	}
}
