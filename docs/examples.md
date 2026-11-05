# Examples

## Basic Usage

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
    source: locktivity/epack-collector-google-workspace@^0.2
    config:
      customer: C0123abc
      organization_id: "987654321"
      admin_email: admin@example.com
    secrets:
      - GOOGLE_SERVICE_ACCOUNT_JSON
```

## Sample Output

The collector always emits the detailed artifact. The normalized artifact is included when the tenant's primary domain can be read, which takes a Super Admin.

### `artifacts/google-workspace.details.json`

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
    "active": 105,
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
    "privileged_users_count": 7,
    "super_admin_count": 3,
    "delegated_admin_count": 5,
    "privileged_users_2sv_enrolled_pct": 85.71,
    "privileged_users_2sv_enforced_pct": 100.0
  },
  "passwords": {
    "weak_password_pct": 4.17,
    "password_length_non_compliant_pct": 2.5,
    "policy": {
      "minimum_length": 8,
      "maximum_length": 100,
      "allowed_strength": "strong",
      "enforce_requirements_at_login": false,
      "allow_reuse": false,
      "expiration_days": 0,
      "distinct_policies": 2
    }
  },
  "sign_in": {
    "web_session_duration_max_minutes": 20160,
    "less_secure_apps_allowed": false
  },
  "apps": {
    "authorized_apps_count": 47
  },
  "device_access": {
    "lookback_days": 90,
    "context_aware_access_denied_events": 12,
    "device_state_denied_events": 4,
    "managed_device_requirement_evidenced": true,
    "access_context_manager": {
      "access_policy_name": "accessPolicies/123456789",
      "access_policy_parent": "organizations/987654321",
      "basic_access_levels_count": 6,
      "custom_access_levels_count": 1,
      "basic_device_policy_access_levels_count": 2,
      "basic_managed_device_access_levels_count": 1,
      "basic_device_policy_access_level_titles": ["Corp Device", "High Trust Device"]
    }
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
    "users_present": true,
    "user_count": 105,
    "inactive_user_count": 5,
    "mfa_coverage_pct": 92,
    "mfa_phishing_resistant_pct": 12,
    "inactive_pct": 5,
    "locked_out_pct": 1,
    "weak_password_pct": 5,
    "password_policy_noncompliant_pct": 3
  },
  "privileged_access": {
    "privileged_users_present": true,
    "privileged_users_count": 7,
    "super_admin_count": 3,
    "privileged_mfa_user_count": 6,
    "privileged_mfa_coverage_pct": 85
  },
  "policy": {
    "mfa_required": false,
    "mfa_required_user_count": 93,
    "mfa_required_coverage_pct": 88,
    "session_lifetime_max_min": 20160
  },
  "lifecycle": {
    "accounts_present": true,
    "account_count": 120,
    "suspended_account_count": 10,
    "archived_account_count": 5,
    "suspended_pct": 9,
    "archived_pct": 5
  },
  "device_access": {
    "managed_device_required": true
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
    source: locktivity/epack-collector-google-workspace@^0.2
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
    source: locktivity/epack-collector-google-workspace@^0.2
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
