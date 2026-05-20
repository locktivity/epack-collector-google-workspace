package googleworkspace

import (
	"context"
	"time"

	"google.golang.org/api/googleapi"
	vault "google.golang.org/api/vault/v1"
)

// ListVaultMatters lists Vault eDiscovery matters. A 404 indicates the customer
// is not licensed for Vault; callers map that to a clean skip.
func (c *APIClient) ListVaultMatters(ctx context.Context, callback func([]VaultMatter) error) error {
	call := c.vault.Matters.List().
		PageSize(maxVaultMattersPerPage).
		View("BASIC").
		Fields(googleapi.Field("nextPageToken,matters(matterId,name,state)"))

	return call.Pages(ctx, func(resp *vault.ListMattersResponse) error {
		matters := make([]VaultMatter, 0, len(resp.Matters))
		for _, m := range resp.Matters {
			if m == nil {
				continue
			}
			matters = append(matters, VaultMatter{MatterID: m.MatterId, Name: m.Name, State: m.State})
		}
		if len(matters) == 0 {
			return nil
		}
		return callback(matters)
	})
}

// ListVaultHolds lists the holds for a matter. The hold's search query is never
// requested; only corpus, account count, and org-unit scope are mapped.
func (c *APIClient) ListVaultHolds(ctx context.Context, matterID string, callback func([]VaultHold) error) error {
	call := c.vault.Matters.Holds.List(matterID).
		PageSize(maxVaultHoldsPerPage).
		Fields(googleapi.Field("nextPageToken,holds(holdId,name,corpus,updateTime,accounts(accountId),orgUnit(orgUnitId))"))

	return call.Pages(ctx, func(resp *vault.ListHoldsResponse) error {
		holds := make([]VaultHold, 0, len(resp.Holds))
		for _, h := range resp.Holds {
			if h == nil {
				continue
			}
			hold := VaultHold{
				HoldID:        h.HoldId,
				MatterID:      matterID,
				Name:          h.Name,
				Corpus:        h.Corpus,
				AccountCount:  len(h.Accounts),
				OrgUnitScoped: h.OrgUnit != nil,
			}
			if ts, err := time.Parse(time.RFC3339, h.UpdateTime); err == nil {
				hold.UpdateTime = ts
			}
			holds = append(holds, hold)
		}
		if len(holds) == 0 {
			return nil
		}
		return callback(holds)
	})
}
