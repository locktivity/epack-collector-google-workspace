# Google Workspace Collector Overview

The Google Workspace collector gathers security posture metrics from your Google Workspace tenant. It covers authentication strength, account hygiene, privileged access, password health, and third-party app exposure.

## Output

The collector always emits a detailed artifact, and conditionally emits a normalized artifact when the usage report contains data:

- `artifacts/google-workspace.json` — detailed Google Workspace posture metrics (always emitted)
- `artifacts/google-workspace.idp-posture.json` — normalized `evidencepack/idp-posture@v1` artifact for cross-provider comparison (omitted when the usage report is empty, e.g. for new tenants)

### Google Workspace Artifact

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

### Normalized IDP Posture Artifact

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

The normalized artifact follows the `evidencepack/idp-posture@v1` schema, matching the same shape used by the Okta and other IDP collectors.

| Normalized field | Google Workspace source | Notes |
|---|---|---|
| `mfa_coverage_pct` | `2sv_protected_pct` | Effective MFA coverage, not just enrollment |
| `mfa_phishing_resistant_pct` | `passkey_users_pct` | Passkey adoption as phishing-resistant proxy |
| `policy.mfa_required` | `2sv_enforced_pct == 100` | Only `true` when all users have 2SV enforced by policy; omitted otherwise |

`app_security` is omitted (SSO/provisioning data not available). `policy.session_lifetime_max_min` and `policy.idle_timeout_max_min` are omitted (session settings not exposed by these APIs). When 2SV enforcement is less than 100%, the entire `policy` block is omitted.

## Metrics Reference

### users

User population and account health.

| Metric | Why It Matters |
|--------|----------------|
| `total` | **Tenant size.** Total user accounts including suspended and archived. |
| `suspended` | **Disabled accounts.** Users administratively suspended from the tenant. |
| `archived` | **Retained accounts.** Users archived but not deleted, often for compliance retention. |
| `locked_pct` | **Potential attack indicator.** Spikes in lockout rates may indicate brute force or credential stuffing attacks. |
| `inactive_pct` | **Orphan account risk.** Inactive accounts (90+ days no login) are prime targets for attackers. They may belong to departed employees or unused service accounts. |
| `inactive_days` | **Inactivity threshold.** The number of days used to classify a user as inactive (default: 90). |

### activity

Login activity rates across the tenant.

| Metric | Why It Matters |
|--------|----------------|
| `active_7d_pct` | **Short-term engagement.** Percentage of users who logged in within the last 7 days. Low values may indicate shadow IT or alternative access paths. |
| `active_30d_pct` | **Monthly engagement.** Percentage of users active in the last 30 days. A large gap between this and 7-day activity may indicate periodic or seasonal users. |

### authentication

Two-step verification and phishing-resistant credential adoption.

| Metric | Why It Matters |
|--------|----------------|
| `2sv_enrolled_pct` | **Account takeover protection.** 2-step verification significantly reduces credential-based attacks. Low enrollment leaves accounts vulnerable to password spraying and phishing. |
| `2sv_enforced_pct` | **Policy enforcement.** Users with 2SV enforced by admin policy, not just voluntarily enrolled. The gap between enrolled and enforced indicates reliance on user opt-in. |
| `2sv_protected_pct` | **Effective protection.** Users actually protected by 2SV (enrolled, enforced, and no bypass). This is the strongest signal of real MFA coverage. |
| `passkey_users_pct` | **Passwordless adoption.** Passkeys are phishing-resistant by design. Tracks progress toward eliminating password-based authentication. |
| `security_keys_total` | **Hardware key inventory.** Total registered security keys (FIDO2/U2F). Useful for tracking hardware rollout across the organization. |

### admins

Privileged account exposure and enforcement.

| Metric | Why It Matters |
|--------|----------------|
| `super_admin_count` | **Blast radius.** Super admins have unrestricted access. Fewer is better. Industry guidance recommends 2-4 for business continuity without excess risk. |
| `delegated_admin_count` | **Delegated access scope.** Delegated admins have subset privileges. High counts may indicate over-delegation. |
| `privileged_users_2sv_enforced_pct` | **Admin MFA enforcement.** The single most important metric for third-party risk. 100% means all active privileged users have 2SV enforced by policy. |

### passwords

Password hygiene across the tenant.

| Metric | Why It Matters |
|--------|----------------|
| `weak_password_pct` | **Credential strength.** Users with passwords classified as weak by Google. Indicates exposure to brute force and dictionary attacks. |
| `password_length_non_compliant_pct` | **Policy compliance.** Users whose passwords don't meet the configured minimum length requirement. Non-zero values indicate policy enforcement gaps. |

### apps

Third-party application exposure.

| Metric | Why It Matters |
|--------|----------------|
| `authorized_apps_count` | **OAuth exposure surface.** Number of third-party apps authorized to access tenant data. High counts increase data exfiltration risk and expand the supply chain attack surface. |

## Use Cases

- **Third-Party Risk Assessment**: Share aggregated posture metrics under NDA without exposing user-level details
- **Security Baseline Monitoring**: Track 2SV enrollment, admin MFA enforcement, and password hygiene over time
- **Compliance Evidence**: Demonstrate MFA coverage and account lifecycle controls for SOC 2, ISO 27001, and similar frameworks
- **Privileged Access Review**: Monitor super admin counts and admin 2SV enforcement as a leading indicator of identity risk
