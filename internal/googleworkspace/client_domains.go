package googleworkspace

import (
	"context"

	cloudidentity "google.golang.org/api/cloudidentity/v1"
	"google.golang.org/api/googleapi"
)

// ListSAMLProfiles lists inbound SAML SSO profiles (Workspace acting as SP for
// an external IdP). Signing certs and metadata XML are never requested.
func (c *APIClient) ListSAMLProfiles(ctx context.Context, callback func([]SAMLProfile) error) error {
	call := c.cloudIdentity.InboundSamlSsoProfiles.List().
		PageSize(maxSAMLProfilesPerPage).
		Fields(googleapi.Field("nextPageToken,inboundSamlSsoProfiles(name,displayName,idpConfig(entityId,singleSignOnServiceUri))"))

	return call.Pages(ctx, func(resp *cloudidentity.ListInboundSamlSsoProfilesResponse) error {
		profiles := make([]SAMLProfile, 0, len(resp.InboundSamlSsoProfiles))
		for _, p := range resp.InboundSamlSsoProfiles {
			if p == nil {
				continue
			}
			profile := SAMLProfile{Name: p.Name, DisplayName: p.DisplayName}
			if p.IdpConfig != nil {
				profile.IdpEntityID = p.IdpConfig.EntityId
				profile.SSOServiceURI = p.IdpConfig.SingleSignOnServiceUri
			}
			profiles = append(profiles, profile)
		}
		if len(profiles) == 0 {
			return nil
		}
		return callback(profiles)
	})
}

// ListDomains lists the customer's domains. The list endpoint is not paginated.
func (c *APIClient) ListDomains(ctx context.Context, customerID string) ([]Domain, error) {
	resp, err := c.dirDomains.Domains.List(customerID).
		Fields(googleapi.Field("domains(domainName,verified,isPrimary)")).
		Context(ctx).
		Do()
	if err != nil {
		return nil, err
	}

	out := make([]Domain, 0, len(resp.Domains))
	for _, d := range resp.Domains {
		if d == nil {
			continue
		}
		out = append(out, Domain{
			DomainName: d.DomainName,
			Verified:   d.Verified,
			IsPrimary:  d.IsPrimary,
		})
	}
	return out, nil
}
