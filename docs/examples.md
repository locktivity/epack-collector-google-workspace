# Examples

## Basic Usage

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

Then run:

```bash
export GOOGLE_SERVICE_ACCOUNT_JSON="$(cat /path/to/service-account.json)"
epack collect
```

See [Configuration](configuration.md) for service account setup instructions.

## Explicit Customer Key

If your service account has access to a specific Google Workspace tenant, set the customer key explicitly:

```yaml
collectors:
  google-workspace:
    source: locktivity/epack-collector-google-workspace@^0.1
    config:
      customer: C0123abc
      admin_email: admin@example.com
    secrets:
      - GOOGLE_SERVICE_ACCOUNT_JSON
```

## Sample Output

The collector always emits the detailed artifact. The normalized artifact is included when the usage report contains data (omitted for new tenants or delayed reports).

### `artifacts/google-workspace.json`

```json
{
  "schema_version": "1.0.0",
  "collected_at": "2026-04-08T12:00:00Z",
  "usage_report_date": "2026-04-07",
  "provider": "google-workspace",
  "org_domain": "example.com",
  "customer_id": "C123abc",
  "users": {
    "total": 120,
    "suspended": 10,
    "archived": 5,
    "locked_pct": 0.83,
    "inactive_pct": 4.76,
    "inactive_days": 90
  },
  "activity": {
    "active_7d_pct": 78.33,
    "active_30d_pct": 91.67
  },
  "authentication": {
    "2sv_enrolled_pct": 92.5,
    "2sv_enforced_pct": 88.33,
    "2sv_protected_pct": 90.0,
    "passkey_users_pct": 12.5,
    "security_keys_total": 35
  },
  "admins": {
    "super_admin_count": 3,
    "delegated_admin_count": 5,
    "privileged_users_2sv_enforced_pct": 100.0
  },
  "passwords": {
    "weak_password_pct": 4.17,
    "password_length_non_compliant_pct": 2.5
  },
  "apps": {
    "authorized_apps_count": 47
  }
}
```

### `artifacts/google-workspace.idp-posture.json`

```json
{
  "schema_version": "1.0.0",
  "collected_at": "2026-04-08T12:00:00Z",
  "provider": "google_workspace",
  "org_domain": "example.com",
  "user_security": {
    "mfa_coverage_pct": 90.0,
    "mfa_phishing_resistant_pct": 12.5,
    "inactive_pct": 4.76,
    "locked_out_pct": 0.83
  },
  "policy": {
    "mfa_required": true
  }
}
```

All coverage values are percentages (0-100). See [Overview](overview.md) for detailed metric descriptions.

## CI/CD Integration

### GitHub Actions

```yaml
name: Collect Google Workspace Posture

on:
  schedule:
    - cron: "0 6 * * *"
  workflow_dispatch:

jobs:
  collect:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Install epack
        run: |
          curl -sSL https://install.epack.dev | bash

      - name: Collect evidence
        run: epack collect --frozen
        env:
          GOOGLE_SERVICE_ACCOUNT_JSON: ${{ secrets.GOOGLE_SERVICE_ACCOUNT_JSON }}
```

Store the service account JSON as a repository secret named `GOOGLE_SERVICE_ACCOUNT_JSON`.

## Multiple Google Workspace Tenants

If a single service account has domain-wide delegation across tenants, use the `customer` key to target each one in its own `epack.yaml`:

```yaml
# epack-prod.yaml
collectors:
  google-workspace:
    source: locktivity/epack-collector-google-workspace@^0.1
    config:
      customer: C0abc123
      admin_email: admin@company.com
    secrets:
      - GOOGLE_SERVICE_ACCOUNT_JSON
```

```yaml
# epack-subsidiary.yaml
collectors:
  google-workspace:
    source: locktivity/epack-collector-google-workspace@^0.1
    config:
      customer: C0def456
      admin_email: admin@subsidiary.com
    secrets:
      - GOOGLE_SERVICE_ACCOUNT_JSON
```

```bash
export GOOGLE_SERVICE_ACCOUNT_JSON="$(cat service-account.json)"
epack collect -c epack-prod.yaml
epack collect -c epack-subsidiary.yaml
```

If each tenant requires its own service account, run separate invocations with different credentials:

```bash
GOOGLE_SERVICE_ACCOUNT_JSON="$(cat prod-sa.json)" epack collect -c epack-prod.yaml
GOOGLE_SERVICE_ACCOUNT_JSON="$(cat subsidiary-sa.json)" epack collect -c epack-subsidiary.yaml
```
