package collector

import (
	"context"
	"net/url"

	"github.com/locktivity/epack-collector-google-workspace/internal/googleworkspace"
	"github.com/locktivity/epack/componentsdk"
)

// scanDomainSettings collects the domain + SSO surface (audit and above). Audit
// emits the SSO-configured flag, SAML-profile and verified-domain counts, and
// per-profile and per-domain inventories; internal adds the SSO service host
// (host only). Signing certs, metadata XML, and full SSO URLs are never
// emitted. The SAML and domain halves degrade independently on scope / role
// denial. Returns nil at trust or if both halves fail.
func (c *Collector) scanDomainSettings(ctx context.Context, scope scanScope) *DomainSettings {
	if !scope.level.AtLeast(componentsdk.LevelAudit) {
		return nil
	}

	collectInventory := scope.level.AtLeast(componentsdk.LevelAudit)
	includeInternal := scope.level.AtLeast(componentsdk.LevelInternal)

	result := &DomainSettings{}

	var profiles []googleworkspace.SAMLProfile
	samlErr := c.client.ListSAMLProfiles(ctx, func(batch []googleworkspace.SAMLProfile) error {
		profiles = append(profiles, batch...)
		return nil
	})
	if samlErr != nil {
		c.warnSurfaceScan("domain_settings:sso", "cloud-identity.inboundsso.readonly", "Super Admin", samlErr)
	} else {
		result.SAMLProfileCount = len(profiles)
		result.SSOConfigured = len(profiles) > 0
		if collectInventory {
			for _, p := range profiles {
				row := SAMLProfileSummary{DisplayName: p.DisplayName, IdpEntityID: p.IdpEntityID}
				if includeInternal {
					row.SSOServiceHost = ssoServiceHost(p.SSOServiceURI)
				}
				result.SAMLProfiles = append(result.SAMLProfiles, row)
			}
		}
	}

	domains, domainErr := c.client.ListDomains(ctx, scope.customerID)
	if domainErr != nil {
		c.warnSurfaceScan("domain_settings:domains", "admin.directory.domain.readonly", "Super Admin", domainErr)
	} else {
		for _, d := range domains {
			if d.Verified {
				result.VerifiedDomainCount++
			}
			if d.IsPrimary {
				result.PrimaryDomain = d.DomainName
			}
			if collectInventory {
				result.Domains = append(result.Domains, DomainSummary{
					DomainName: d.DomainName,
					Verified:   d.Verified,
					Primary:    d.IsPrimary,
				})
			}
		}
	}

	if samlErr != nil && domainErr != nil {
		return nil
	}
	return result
}

// ssoServiceHost returns the host of an IdP single-sign-on URL, never the full
// URL or its query. An unparseable value yields "".
func ssoServiceHost(rawURL string) string {
	if rawURL == "" {
		return ""
	}
	parsed, err := url.Parse(rawURL)
	if err != nil {
		return ""
	}
	return parsed.Hostname()
}
