# epack-collector-google-workspace

Google Workspace identity and security posture collector for [epack](https://github.com/locktivity/epack).

It collects tenant-wide posture metrics from the Admin SDK Reports API and Directory API and emits:

- a detailed Google Workspace artifact at `artifacts/google-workspace.json` (always)
- a normalized `evidencepack/idp-posture@v1` artifact at `artifacts/google-workspace.idp-posture.json` (when usage report data is available)

See [docs/overview.md](docs/overview.md), [docs/configuration.md](docs/configuration.md), [docs/examples.md](docs/examples.md), and [docs/schema/v1.0.0.json](docs/schema/v1.0.0.json).

## What it collects

Trust-level (always):

- user population counts (total, suspended, archived)
- login activity (7-day and 30-day active percentages)
- 2-step verification enrollment, enforcement, and protection coverage
- passkey adoption and security key counts
- unique privileged user counts plus admin 2SV enrollment and enforcement
- password hygiene (weak passwords, length non-compliance) and the configured password policy (minimum length, strength requirement, whether it binds existing users)
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

## Quick start

In `epack.yaml`:

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

Then run it:

```bash
export GOOGLE_SERVICE_ACCOUNT_JSON="$(cat /secure/path/google-service-account.json)"
epack collect
```

This uses a service account key. To run on CI without one, see
[Authentication](#authentication).

## Configuration

`admin_email` is required. The collector defaults to `customer: my_customer` and resolves the primary domain from Google Workspace directly.

Optional config keys:

- `customer`: custom Google customer key. Defaults to `my_customer`.
- `organization_id`: optional Google Cloud organization ID used to discover an Access Context Manager policy for `device_access` config enrichment.
- `access_policy`: optional Access Context Manager policy name or numeric ID. If set, it takes precedence over `organization_id`.

## Authentication

The collector impersonates a Workspace admin user through a service account with
domain-wide delegation. The `auth_mode` config key chooses how it authenticates
as that service account.

[docs/configuration.md](docs/configuration.md) has the full setup.

### auth_mode: oidc

The runner proves its own identity and Google signs the delegation assertion.
No key exists, so there is nothing to store or rotate. Use this on CI.

In `epack.yaml`:

```yaml
collectors:
  google-workspace:
    source: locktivity/epack-collector-google-workspace@^0.2
    config:
      admin_email: admin@example.com
      auth_mode: oidc
      workload_identity_provider: projects/123456/locations/global/workloadIdentityPools/epack/providers/github
      service_account: collector@your-project.iam.gserviceaccount.com
    secrets:
      - ACTIONS_ID_TOKEN_REQUEST_URL
      - ACTIONS_ID_TOKEN_REQUEST_TOKEN
```

In the workflow:

```yaml
permissions:
  contents: read
  id-token: write

steps:
  - uses: actions/checkout@v4
  - run: epack collect
```

The collector performs the exchange itself, so no auth step is needed.

### auth_mode: service_account_key

A downloadable private key, passed as `GOOGLE_SERVICE_ACCOUNT_JSON`. Anyone
holding it has the service account's reach until the key is deleted. This is the
default when `auth_mode` is omitted. Use it for local runs.

In `epack.yaml`:

```yaml
collectors:
  google-workspace:
    source: locktivity/epack-collector-google-workspace@^0.2
    config:
      admin_email: admin@example.com
    secrets:
      - GOOGLE_SERVICE_ACCOUNT_JSON
```

### Switching between modes

Both modes produce the same artifact. Delegation is keyed to the service
account's client ID, so switching a profile to `oidc` needs no Workspace
changes: the scope grants below carry over.

## What the collector needs granted

Three separate things, each failing differently. A surface that is missing any
of them is omitted from the artifact with a diagnostic, and the run still
succeeds.

### OAuth scopes

Granted in the Workspace admin console under domain-wide delegation, one at a
time.

| Surface | Scope | Needed at |
|---|---|---|
| Customer + Users | `admin.directory.user.readonly`, `admin.directory.customer.readonly` | trust |
| Activity / usage | `admin.reports.usage.readonly` | trust |
| Context-Aware Access (device_access) | `admin.reports.audit.readonly` | trust |
| Password policy | `cloud-identity.policies.readonly` | trust |
| Audit logs (admin, login, token, drive sharing) | `admin.reports.audit.readonly` | audit / internal |
| Admin roles | `admin.directory.rolemanagement.readonly` | audit / internal |
| Groups | `admin.directory.group.readonly`, `admin.directory.group.member.readonly`, `apps.groups.settings` | audit / internal |
| Org units | `admin.directory.orgunit.readonly` | audit / internal |
| Endpoint (devices) | `admin.directory.device.mobile.readonly`, `admin.directory.device.chromeos.readonly` | audit / internal |
| Domain settings | `admin.directory.domain.readonly` | audit / internal |
| SSO (SAML profiles) | `cloud-identity.inboundsso.readonly` | audit / internal |
| Vault (eDiscovery) | `ediscovery.readonly` | audit / internal (requires a Vault license) |
| Access Context Manager (Google Cloud) | service account IAM role `roles/accesscontextmanager.policyReader` on the organization | trust (device_access enrichment) |

Grants are not retroactive. Adding a scope later requires re-granting; until
then that surface records a scope-denied diagnostic.

All scopes as one comma-separated list, for pasting into the admin console:

```
https://www.googleapis.com/auth/admin.directory.user.readonly,https://www.googleapis.com/auth/admin.directory.customer.readonly,https://www.googleapis.com/auth/admin.directory.rolemanagement.readonly,https://www.googleapis.com/auth/admin.directory.group.readonly,https://www.googleapis.com/auth/admin.directory.group.member.readonly,https://www.googleapis.com/auth/admin.directory.orgunit.readonly,https://www.googleapis.com/auth/admin.directory.device.mobile.readonly,https://www.googleapis.com/auth/admin.directory.device.chromeos.readonly,https://www.googleapis.com/auth/admin.directory.domain.readonly,https://www.googleapis.com/auth/admin.reports.usage.readonly,https://www.googleapis.com/auth/admin.reports.audit.readonly,https://www.googleapis.com/auth/apps.groups.settings,https://www.googleapis.com/auth/cloud-identity.inboundsso.readonly,https://www.googleapis.com/auth/cloud-identity.policies.readonly,https://www.googleapis.com/auth/ediscovery.readonly
```

### Cloud-project APIs

Enabled in the service account's Cloud project. A granted scope still fails with
a `SERVICE_DISABLED` diagnostic if its API is off.

| API | Needed at |
|---|---|
| Admin SDK API | all levels |
| Cloud Identity API | all levels |
| IAM Service Account Credentials API | `auth_mode: oidc` only |
| Groups Settings API | audit / internal |
| Google Vault API | audit / internal |

### Admin roles

The impersonated user needs a Workspace admin role that can read each surface.
Scopes alone are not enough.

| Role | Covers |
|---|---|
| Super Admin | Everything. Simplest for a dedicated collector user. |
| Reports Admin + User Management Admin + Groups Admin | Users, admins, groups, org units, devices, domains, audit logs. |
| Vault Admin | The Vault surface. |

Most customers create a dedicated `epack-collector@<domain>` user with Super
Admin.

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
