# epack-collector-google-workspace

Google Workspace identity and security posture collector for [epack](https://github.com/locktivity/epack).

It collects tenant-wide posture metrics from the Admin SDK Reports API and Directory API and emits:

- a detailed Google Workspace artifact at `artifacts/google-workspace.details.json` (always)
- a normalized `evidencepack/idp-posture@v1` artifact at `artifacts/google-workspace.idp-posture.json` (when the tenant's primary domain can be read)
- a collector result at `artifacts/google-workspace.collector-result.json` (always), which lists each value the collector could not read and why, and the API calls it made

See [docs/overview.md](docs/overview.md), [docs/configuration.md](docs/configuration.md), [docs/examples.md](docs/examples.md), and [docs/schema/v1.0.0.json](docs/schema/v1.0.0.json).

## What it collects

Trust-level (always):

- user population counts (total, suspended, archived)
- login activity (7-day and 30-day active percentages)
- 2-step verification enrollment, enforcement, and protection coverage
- passkey adoption and security key counts
- unique privileged user counts plus admin 2SV enrollment and enforcement
- password hygiene (weak passwords, length non-compliance) and the configured password policy (minimum length, strength requirement, whether it binds existing users)
- the longest web session and whether less secure apps are allowed, from the Policy API
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

## Values left out and exit codes

A value the collector cannot read is left out of the artifact as `null` or an
absent field, never written as `0`, `false`, or an empty list. The collector
result names each one with a code, such as `permission_denied` for a missing
scope or role, and the run still succeeds. A percentage over no users is
`null` too.

The run fails only when it cannot start: invalid configuration exits 2, and a
failed sign-in exits 3 with the code `auth_failed` when Google rejects the key
or the assertion. A failed sign-in also exits 3, with `permission_denied`, when
the delegation grant lacks `admin.directory.user.readonly`, and exits 2, with
`config_invalid`, when Google answers the token request with `invalid_request`.

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

Scopes, Cloud-project APIs, and an admin role for the impersonated user. Each
is granted in a different place, and each fails differently when missing: the
affected surface is omitted from the artifact with a diagnostic and a gap in
the collector result, and the run still succeeds. The
[configuration page](docs/configuration.md) lists all three at the step where
each is granted.

Only a Super Admin can read the tenant record. With a narrower admin role,
`org_domain` is null, and so is `customer_id`, which runs write from the
`audit` level. The normalized artifact is not emitted, and the Drive
external-share count is left out, since telling an external recipient from an
internal one takes the primary domain. Everything
else is collected under the customer key.

## Development

```bash
make build
make test
make lint
make sdk-test
make sdk-run
```

## Testing

Unit tests cover collector aggregation, Reports API parsing, and Directory API client behavior.
`internal/collector/collectortest_test.go` runs the collector against canned API responses with the
epack `collectortest` kit, which injects failures into every API call and checks that each value
keeps its value or is left out with a matching code:

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
