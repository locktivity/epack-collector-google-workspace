# epack-collector-google-workspace

Google Workspace identity and security posture collector for [epack](https://github.com/locktivity/epack).

It collects tenant-wide posture metrics from the Admin SDK Reports API and Directory API and emits:

- a detailed Google Workspace artifact at `artifacts/google-workspace.json` (always)
- a normalized `evidencepack/idp-posture@v1` artifact at `artifacts/google-workspace.idp-posture.json` (when usage report data is available)

See [docs/overview.md](docs/overview.md), [docs/configuration.md](docs/configuration.md), [docs/examples.md](docs/examples.md), and [docs/schema/v1.0.0.json](docs/schema/v1.0.0.json).

## What It Collects

- user population counts (total, suspended, archived)
- login activity (7-day and 30-day active percentages)
- 2-step verification enrollment, enforcement, and protection coverage
- passkey adoption and security key counts
- unique privileged user counts plus admin 2SV enrollment and enforcement
- password hygiene (weak passwords, length non-compliance)
- authorized third-party app count
- Context-Aware Access device-state deny evidence when audit logs are available

## Quick Start

```yaml
stream: myorg/google-workspace-posture

collectors:
  google-workspace:
    source: locktivity/epack-collector-google-workspace@^0.1
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

The collector uses a Google service account with domain-wide delegation.

Required scopes:

- `https://www.googleapis.com/auth/admin.directory.user.readonly`
- `https://www.googleapis.com/auth/admin.directory.customer.readonly`
- `https://www.googleapis.com/auth/admin.reports.usage.readonly`

Recommended optional scope for `device_access` enrichment:

- `https://www.googleapis.com/auth/admin.reports.audit.readonly`

Optional Google Cloud permission for Access Context Manager enrichment:

- service account IAM role `roles/accesscontextmanager.policyReader` on the relevant organization

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
