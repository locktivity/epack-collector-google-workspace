package collector

import (
	"context"
	"time"

	"github.com/locktivity/epack-collector-google-workspace/internal/googleworkspace"
	"github.com/locktivity/epack/componentsdk"
)

// scanVault collects the Vault eDiscovery surface (audit and above). Audit emits
// the licensed flag, matter / hold counts, and per-matter summaries; internal
// adds per-hold metadata (never the search query or contents). It degrades on
// customers without a Vault license (404 -> licensed=false + diagnostic) and on
// scope / role denial (surface omitted). Returns nil at trust.
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
			return &Vault{Licensed: false}
		}
		c.warnSurfaceScan("vault", "ediscovery.readonly", "a custom role with Vault privileges (or Super Admin)", err)
		return nil
	}

	result := &Vault{Licensed: true, MattersCount: len(matters)}
	collectMatters := scope.level.AtLeast(componentsdk.LevelAudit)
	includeHolds := scope.level.AtLeast(componentsdk.LevelInternal)

	for _, m := range matters {
		var holds []googleworkspace.VaultHold
		herr := c.client.ListVaultHolds(ctx, m.MatterID, func(batch []googleworkspace.VaultHold) error {
			holds = append(holds, batch...)
			return nil
		})
		if herr != nil {
			c.warn("vault: holds unavailable for matter %s: %v", m.MatterID, herr)
		}
		result.HoldsCount += len(holds)

		if collectMatters {
			result.Matters = append(result.Matters, VaultMatterSummary{
				MatterID:  m.MatterID,
				Name:      m.Name,
				State:     m.State,
				HoldCount: len(holds),
			})
		}
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
				result.Holds = append(result.Holds, row)
			}
		}
	}
	return result
}
