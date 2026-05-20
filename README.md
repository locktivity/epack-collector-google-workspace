# epack-collector-google-workspace

Google Workspace identity and security posture collector for [epack](https://github.com/locktivity/epack).

It collects tenant-wide posture metrics from the Admin SDK Reports API and Directory API and emits:

- a detailed Google Workspace artifact at `artifacts/google-workspace.json` (always)
- a normalized `evidencepack/idp-posture@v1` artifact at `artifacts/google-workspace.idp-posture.json` (when usage report data is available)

See [docs/overview.md](docs/overview.md), [docs/configuration.md](docs/configuration.md), [docs/examples.md](docs/examples.md), and [docs/schema/v1.0.0.json](docs/schema/v1.0.0.json).

## What It Collects

Trust-level (always):

- user population counts (total, suspended, archived)
- login activity (7-day and 30-day active percentages)
- 2-step verification enrollment, enforcement, and protection coverage
- passkey adoption and security key counts
- unique privileged user counts plus admin 2SV enrollment and enforcement
- password hygiene (weak passwords, length non-compliance)
- authorized third-party app count
- Context-Aware Access device-state deny evidence when audit logs are available

Audit and internal add the expanded surfaces (groups, org units, managed
devices, SAML/domain settings, Vault, OAuth tokens, and the admin / login /
Drive-sharing audit logs) plus per-resource detail. Trust collects only the
surfaces above, so it needs only the base scopes. See
[Collection levels](#collection-levels).

## Collection levels

The collector accepts an optional `level` config knob (`trust` / `audit` /
`internal`) controlling collection depth. Levels are cumulative: `internal` is a
strict superset of `audit`, which is a strict superset of `trust`. Unknown or
absent values fall back to `trust`. The active level is stamped on the artifact
as `collected_at_level`.

| Level | Question it answers | What is in the artifact |
|---|---|---|
| `trust` (default) | Do they pass? | Org-wide aggregates and on/off flags. No user emails, group names, device details, or audit-log events. |
| `audit` | Where is the gap? | Per-resource inventories (users, admins + roles, groups, org units, devices, SAML profiles, domains) and recent audit-log counts. No per-user activity timestamps, event bodies, file names, or file contents. |
| `internal` | Who or what specifically? | Per-user activity, group rosters, per-device records, security-relevant admin / login event slices, per-OAuth-token grants, SSO service hosts, and Vault hold metadata. |

See [docs/levels.md](docs/levels.md) for the full per-surface breakdown.

```yaml
collectors:
  google-workspace:
    config:
      admin_email: admin@example.com
      level: audit
```

> Bumping to a level-aware collector version without first granting the new
> OAuth scopes (below) AND ensuring the impersonation user holds the right admin
> role will produce partial collection: the affected surfaces emit a diagnostic
> warning and are skipped, rather than failing the run.

## Quick Start

```yaml
stream: myorg/google-workspace-posture

collectors:
  google-workspace:
    source: locktivity/epack-collector-google-workspace@^0.2
    config:
      admin_email: admin@example.com
    secrets:
      - GOOGLE_SERVICE_ACCOUNT_JSON
```

```bash
export GOOGLE_SERVICE_ACCOUNT_JSON="$(cat /secure/path/google-service-account.json)"
epack collect
```

## Configuration

`admin_email` is required. The collector defaults to `customer: my_customer` and resolves the primary domain from Google Workspace directly.

Optional config keys:

- `customer`: custom Google customer key. Defaults to `my_customer`.
- `organization_id`: optional Google Cloud organization ID used to discover an Access Context Manager policy for `device_access` config enrichment.
- `access_policy`: optional Access Context Manager policy name or numeric ID. If set, it takes precedence over `organization_id`.

## Authentication

The collector uses a Google service account with domain-wide delegation, acting
as (impersonating) a Workspace admin user.

> Audit and internal collection require additional OAuth scopes beyond the
> trust-level set, AND the impersonation user must hold an admin role that can
> read each surface. Granting scopes alone is not sufficient: a scope-granted
> service account still fails a surface if the impersonation user lacks the
> matching role. Both the domain-wide-delegation scope re-grant and the
> impersonation-user role check are required before audit / internal will return
> complete data.

### Required OAuth scopes

| Surface | Scope | Needed at |
|---|---|---|
| Customer + Users | `admin.directory.user.readonly`, `admin.directory.customer.readonly` | trust |
| Activity / usage | `admin.reports.usage.readonly` | trust |
| Context-Aware Access (device_access) | `admin.reports.audit.readonly` | trust |
| Audit logs (admin, login, token, drive sharing) | `admin.reports.audit.readonly` | audit / internal |
| Admin roles | `admin.directory.rolemanagement.readonly` | audit / internal |
| Groups | `admin.directory.group.readonly`, `admin.directory.group.member.readonly`, `apps.groups.settings` | audit / internal |
| Org units | `admin.directory.orgunit.readonly` | audit / internal |
| Endpoint (devices) | `admin.directory.device.mobile.readonly`, `admin.directory.device.chromeos.readonly` | audit / internal |
| Domain settings | `admin.directory.domain.readonly` | audit / internal |
| SSO (SAML profiles) | `cloud-identity.inboundsso.readonly` | audit / internal |
| Vault (eDiscovery) | `ediscovery.readonly` | audit / internal (requires a Vault license) |
| Access Context Manager (Google Cloud) | service account IAM role `roles/accesscontextmanager.policyReader` on the organization | trust (device_access enrichment) |

Trust needs only the first three rows (the base directory + usage scopes, plus
`admin.reports.audit.readonly` for Context-Aware Access evidence). The expanded
surfaces are collected only at audit / internal, so their scopes are requested
only when you run at those levels and degrade per-surface if ungranted.

The domain-wide-delegation grant takes each scope individually in the admin
console (there is no bulk-update API). The copy-pasteable comma-joined list:

```
https://www.googleapis.com/auth/admin.directory.user.readonly,https://www.googleapis.com/auth/admin.directory.customer.readonly,https://www.googleapis.com/auth/admin.directory.rolemanagement.readonly,https://www.googleapis.com/auth/admin.directory.group.readonly,https://www.googleapis.com/auth/admin.directory.group.member.readonly,https://www.googleapis.com/auth/admin.directory.orgunit.readonly,https://www.googleapis.com/auth/admin.directory.device.mobile.readonly,https://www.googleapis.com/auth/admin.directory.device.chromeos.readonly,https://www.googleapis.com/auth/admin.directory.domain.readonly,https://www.googleapis.com/auth/admin.reports.usage.readonly,https://www.googleapis.com/auth/admin.reports.audit.readonly,https://www.googleapis.com/auth/apps.groups.settings,https://www.googleapis.com/auth/cloud-identity.inboundsso.readonly,https://www.googleapis.com/auth/ediscovery.readonly
```

### Required Cloud-project APIs

Separate from the OAuth scopes above: the Google APIs the collector calls must
be **enabled in the service account's Cloud project**, or a granted scope still
fails with a `SERVICE_DISABLED` diagnostic for that surface. Enable: **Admin SDK
API** (all levels), and for audit / internal also **Groups Settings API**,
**Cloud Identity API**, and **Google Vault API**. See
[docs/configuration.md](docs/configuration.md) Step 1 for the full list.

### Required impersonation-user admin role

The impersonation user must hold a Workspace admin role able to read each
surface:

- **Super Admin** reads everything (simplest for a dedicated collector user).
- **Reports Admin** + **User Management Admin** + **Groups Admin** cover most
  surfaces (users, admins, groups, org units, devices, domains, audit logs).
- **Vault Admin** is required for the Vault surface specifically.

Most customers configure a dedicated `epack-collector@<domain>` admin user with
Super Admin or a tailored bundle of the roles above.

See [docs/configuration.md](docs/configuration.md) for the full setup flow.

## Development

```bash
make build
make test
make lint
make sdk-test
make sdk-run
```

## Testing

Unit tests cover collector aggregation, Reports API parsing, and Directory API client behavior:

```bash
go test ./...
go test -race ./...
```

## Release

Tag a version to trigger the release workflow:

```bash
git tag v0.1.0
git push origin v0.1.0
```

## License

Apache-2.0
