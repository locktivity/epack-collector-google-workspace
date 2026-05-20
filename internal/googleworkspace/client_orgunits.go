package googleworkspace

import (
	"context"

	"google.golang.org/api/googleapi"
)

// ListOrgUnits lists all organizational units for the customer. The orgunits
// list endpoint is not paginated; it returns the full hierarchy in one call.
func (c *APIClient) ListOrgUnits(ctx context.Context, customerID string) ([]OrgUnit, error) {
	resp, err := c.dirOrgUnits.Orgunits.List(customerID).
		Type("all").
		Fields(googleapi.Field("organizationUnits(orgUnitPath,parentOrgUnitPath,name,description,blockInheritance)")).
		Context(ctx).
		Do()
	if err != nil {
		return nil, err
	}

	out := make([]OrgUnit, 0, len(resp.OrganizationUnits))
	for _, ou := range resp.OrganizationUnits {
		if ou == nil {
			continue
		}
		out = append(out, OrgUnit{
			Path:             ou.OrgUnitPath,
			ParentPath:       ou.ParentOrgUnitPath,
			Name:             ou.Name,
			Description:      ou.Description,
			BlockInheritance: ou.BlockInheritance,
		})
	}
	return out, nil
}
