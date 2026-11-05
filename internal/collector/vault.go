package collector

import (
	"context"
	"time"

	"github.com/locktivity/epack-collector-google-workspace/internal/googleworkspace"
	"github.com/locktivity/epack/componentsdk"
)

// scanVault collects the Vault eDiscovery surface (audit and above). Audit emits
// the licensed flag, matter / hold counts, and per-matter summaries; internal
// adds per-hold metadata (never the search query or contents). On a tenant
// without a Vault license (404) it reports licensed=false and leaves the counts
// out; when the matters cannot be read the surface is omitted. Returns nil at
// trust.
func (c *Collector) scanVault(ctx context.Context, scope scanScope) *Vault {
	if !scope.level.AtLeast(componentsdk.LevelAudit) {
		return nil
	}

	var matters []googleworkspace.VaultMatter
	err := c.client.ListVaultMatters(ctx, func(batch []googleworkspace.VaultMatter) error {
		matters = append(matters, batch...)
		return nil
	})
	if err != nil {
		if isFeatureNotLicensed(err) {
			c.warnFeatureNotLicensed("vault", "Vault (eDiscovery)")
			c.gaps.leaveOut(unlicensed("the tenant's edition does not include Vault"), "/vault/matters_count", "/vault/holds_count")
			return &Vault{Licensed: false}
		}
		c.warnSurfaceScan("vault", "ediscovery.readonly", "a custom role with Vault privileges (or Super Admin)", err)
		c.gaps.leaveOut(failed(err), "/vault")
		return nil
	}

	result := &Vault{Licensed: true, MattersCount: intPtr(len(matters))}
	includeHolds := scope.level.AtLeast(componentsdk.LevelInternal)
	holdsTotal := 0
	holdsFailed := 0
	var holdsErr error
	var holdRows []VaultHoldSummary

	for i, m := range matters {
		var holds []googleworkspace.VaultHold
		herr := c.client.ListVaultHolds(ctx, m.MatterID, func(batch []googleworkspace.VaultHold) error {
			holds = append(holds, batch...)
			return nil
		})
		summary := VaultMatterSummary{MatterID: m.MatterID, Name: m.Name, State: m.State}
		result.Matters = append(result.Matters, summary)
		if herr != nil {
			c.warn("vault: holds unavailable for matter %s: %v", m.MatterID, herr)
			c.gaps.leaveOut(failed(herr), itemPointer("/vault/matters", i, "hold_count"))
			holdsFailed++
			if holdsErr == nil {
				holdsErr = herr
			}
			continue
		}
		result.Matters[i].HoldCount = intPtr(len(holds))
		holdsTotal += len(holds)

		if includeHolds {
			for _, h := range holds {
				row := VaultHoldSummary{
					HoldID:        h.HoldID,
					MatterID:      h.MatterID,
					Corpus:        h.Corpus,
					AccountCount:  h.AccountCount,
					OrgUnitScoped: h.OrgUnitScoped,
				}
				if !h.UpdateTime.IsZero() {
					row.UpdatedAt = h.UpdateTime.UTC().Format(time.RFC3339)
				}
				holdRows = append(holdRows, row)
			}
		}
	}
	if holdsFailed > 0 {
		c.gaps.partial(holdsFailed, failed(holdsErr), "/vault/holds_count")
		if includeHolds {
			c.gaps.leaveOut(failed(holdsErr), "/vault/holds")
		}
		return result
	}
	result.HoldsCount = &holdsTotal
	result.Holds = holdRows
	return result
}
