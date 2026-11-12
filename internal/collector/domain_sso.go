package collector

import (
	"context"
	"fmt"
	"net/url"
	"slices"
	"strings"

	"github.com/locktivity/epack-collector-google-workspace/internal/googleworkspace"
	"github.com/locktivity/epack/componentsdk"
)

// ssoSignIn is the tenant's SAML profiles, or profilesErr, and why the
// normalized MFA values are left out, as OrgPosture.thirdPartySSO says.
type ssoSignIn struct {
	profiles      []googleworkspace.SAMLProfile
	profilesErr   error
	thirdPartySSO *missing
}

// readSSO lists the SAML profiles and, when there is one, the SSO
// assignments that say which org units and groups sign in through it.
func (c *Collector) readSSO(ctx context.Context) ssoSignIn {
	var s ssoSignIn
	s.profilesErr = c.client.ListSAMLProfiles(ctx, func(batch []googleworkspace.SAMLProfile) error {
		s.profiles = append(s.profiles, batch...)
		return nil
	})
	if s.profilesErr != nil {
		c.warnSurfaceScan("domain_settings:sso", "cloud-identity.inboundsso.readonly", "Super Admin", s.profilesErr)
		s.thirdPartySSO = failed(s.profilesErr)
		return s
	}
	if len(s.profiles) == 0 {
		return s
	}
	var assignments []googleworkspace.SSOAssignment
	err := c.client.ListSSOAssignments(ctx, func(batch []googleworkspace.SSOAssignment) error {
		assignments = append(assignments, batch...)
		return nil
	})
	if err != nil {
		c.warnSurfaceScan("sso_assignments", "cloud-identity.inboundsso.readonly", "Super Admin", err)
		s.thirdPartySSO = failed(err)
		return s
	}
	if providers := samlProviders(s.profiles, assignments); len(providers) > 0 {
		s.thirdPartySSO = &missing{code: componentsdk.CodeUnsupported, detail: fmt.Sprintf(
			"Users the SSO assignments send to %s sign in there, and that identity provider decides whether they use MFA, "+
				"so Google 2-Step Verification does not cover them. The collector does not work out which users the assignments cover.",
			strings.Join(providers, " and "))}
	}
	return s
}

// samlProviders names the identity providers that assignments send users
// to: each profile a SAML_SSO assignment uses, by its display name and
// entity ID, and the domain-wide SSO profile a DOMAIN_WIDE_SAML_IF_ENABLED
// assignment uses.
func samlProviders(profiles []googleworkspace.SAMLProfile, assignments []googleworkspace.SSOAssignment) []string {
	var names []string
	add := func(name string) {
		if !slices.Contains(names, name) {
			names = append(names, name)
		}
	}
	for _, a := range assignments {
		switch a.SSOMode {
		case "SAML_SSO":
			name := a.Profile
			for _, p := range profiles {
				if p.Name == a.Profile {
					name = fmt.Sprintf("%s (%s)", p.DisplayName, p.IdpEntityID)
				}
			}
			add(name)
		case "DOMAIN_WIDE_SAML_IF_ENABLED":
			add("the domain-wide SSO profile")
		}
	}
	return names
}

// scanDomainSettings collects the domain + SSO surface (audit and above). Audit
// emits the SSO-configured flag, SAML-profile and verified-domain counts, and
// per-profile and per-domain inventories; internal adds the SSO service host
// (host only). Signing certs, metadata XML, and full SSO URLs are never
// emitted. The SAML and domain halves are left out independently when they
// cannot be read. Returns nil at trust or if both halves fail.
func (c *Collector) scanDomainSettings(ctx context.Context, scope scanScope, sso ssoSignIn) *DomainSettings {
	if !scope.level.AtLeast(componentsdk.LevelAudit) {
		return nil
	}

	collectInventory := scope.level.AtLeast(componentsdk.LevelAudit)
	includeInternal := scope.level.AtLeast(componentsdk.LevelInternal)

	result := &DomainSettings{}

	profiles, samlErr := sso.profiles, sso.profilesErr
	if samlErr == nil {
		count := len(profiles)
		configured := count > 0
		result.SAMLProfileCount = &count
		result.SSOConfigured = &configured
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
		verified := 0
		for _, d := range domains {
			if d.Verified {
				verified++
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
		result.VerifiedDomainCount = &verified
	}

	if samlErr != nil && domainErr != nil {
		c.gaps.leaveOut(failed(samlErr), "/domain_settings")
		return nil
	}
	if samlErr != nil {
		c.gaps.leaveOut(failed(samlErr), "/domain_settings/sso_configured", "/domain_settings/saml_profile_count", "/domain_settings/saml_profiles")
	}
	if domainErr != nil {
		c.gaps.leaveOut(failed(domainErr), "/domain_settings/verified_domain_count", "/domain_settings/primary_domain", "/domain_settings/domains")
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
