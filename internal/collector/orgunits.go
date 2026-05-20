package collector

import (
	"context"
	"slices"
	"strings"

	"github.com/locktivity/epack/componentsdk"
)

// scanOrgUnits collects the OrgUnits surface (audit and above). Audit emits the
// count, max hierarchy depth, and the per-OU inventory (path, parent,
// description, user count from the user scan, and the block-inheritance
// policy-override flag). Returns nil at trust or on scope / role denial.
func (c *Collector) scanOrgUnits(ctx context.Context, scope scanScope, usersByOU map[string]int) *OrgUnits {
	if !scope.level.AtLeast(componentsdk.LevelAudit) {
		return nil
	}

	units, err := c.client.ListOrgUnits(ctx, scope.customerID)
	if err != nil {
		c.warnSurfaceScan("org_units", "admin.directory.orgunit.readonly", "Groups Admin (or Super Admin)", err)
		return nil
	}

	result := &OrgUnits{Total: len(units)}
	collectInventory := scope.level.AtLeast(componentsdk.LevelAudit)

	var inventory []OrgUnit
	for _, ou := range units {
		if depth := orgUnitDepth(ou.Path); depth > result.MaxDepth {
			result.MaxDepth = depth
		}
		if collectInventory {
			inventory = append(inventory, OrgUnit{
				Path:             ou.Path,
				ParentPath:       ou.ParentPath,
				Description:      ou.Description,
				UserCount:        usersByOU[ou.Path],
				BlockInheritance: ou.BlockInheritance,
			})
		}
	}

	if collectInventory {
		slices.SortFunc(inventory, func(a, b OrgUnit) int {
			return strings.Compare(a.Path, b.Path)
		})
		result.Inventory = inventory
	}
	return result
}

// orgUnitDepth returns the nesting depth of an org-unit path. The root ("/") is
// depth 0; "/Eng" is depth 1; "/Eng/Backend" is depth 2.
func orgUnitDepth(path string) int {
	if path == "" || path == "/" {
		return 0
	}
	return strings.Count(path, "/")
}
