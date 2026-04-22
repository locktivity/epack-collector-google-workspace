# Google Workspace Collector Overview

The Google Workspace collector gathers security posture metrics from your Google Workspace tenant. It covers authentication strength, account hygiene, privileged access, password health, third-party app exposure, and positive-only Context-Aware Access deny evidence related to device state.

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
    "privileged_users_count": 7,
    "super_admin_count": 3,
    "delegated_admin_count": 5,
    "privileged_users_2sv_enrolled_pct": 85.71,
    "privileged_users_2sv_enforced_pct": 100.0
  },
  "passwords": {
    "weak_password_pct": 4.17,
    "password_length_non_compliant_pct": 2.5
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
    "locked_out_pct": 0.83,
    "weak_password_pct": 4.17,
    "password_policy_noncompliant_pct": 2.5
  },
  "app_security": {
    "authorized_third_party_apps_count": 47
  },
  "privileged_access": {
    "privileged_users_count": 7,
    "super_admin_count": 3,
    "privileged_mfa_coverage_pct": 85.71,
    "standing_privileged_users_count": 7
  },
  "policy": {
    "mfa_required": false,
    "mfa_required_coverage_pct": 88.33,
    "legacy_auth_blocked": true
  },
  "lifecycle": {
    "suspended_pct": 8.33,
    "archived_pct": 4.17
  },
  "device_access": {
    "managed_device_required": true
  }
}
```

The normalized artifact follows the `evidencepack/idp-posture@v1` schema, matching the same shape used by the Okta and other IDP collectors.

`policy.legacy_auth_blocked` is emitted as `true` for Google Workspace because Google no longer supports less secure username/password-only app access for Workspace accounts.

| Normalized field | Google Workspace source | Notes |
|---|---|---|
| `mfa_coverage_pct` | `2sv_protected_pct` | Effective MFA coverage, not just enrollment |
| `mfa_phishing_resistant_pct` | `passkey_users_pct` | Passkey adoption as phishing-resistant proxy |
| `weak_password_pct` | `weak_password_pct` | Weak password coverage comes directly from the usage report |
| `password_policy_noncompliant_pct` | `password_length_non_compliant_pct` | Tracks users that fail the tenant password length policy |
| `app_security.authorized_third_party_apps_count` | `authorized_apps_count` | OAuth-connected third-party application count |
| `privileged_access.privileged_users_count` | `privileged_users_count` | Counts unique active privileged users only |
| `privileged_access.super_admin_count` | `super_admin_count` | Excludes suspended and archived admins |
| `privileged_access.privileged_mfa_coverage_pct` | `privileged_users_2sv_enrolled_pct` | Percent of active privileged users with 2SV enrolled |
| `privileged_access.standing_privileged_users_count` | `privileged_users_count` | Google Workspace has standing admin roles in this collector model |
| `policy.mfa_required` | `2sv_enforced_pct == 100` | Only `true` when all users have 2SV enforced by policy |
| `policy.mfa_required_coverage_pct` | `2sv_enforced_pct` | Preserves partial enforcement coverage instead of dropping the policy block |
| `policy.legacy_auth_blocked` | Google Workspace platform behavior | Google Workspace no longer supports less secure username/password apps for tenant access |
| `lifecycle.suspended_pct` | `suspended / total` | Uses the usage report's suspended user count |
| `lifecycle.archived_pct` | `archived / total` | Uses the usage report's archived user count |
| `device_access.managed_device_required` | `device_access.managed_device_requirement_evidenced` | Emitted only when Context-Aware Access deny events include a device-state parameter |

`app_security.sso_coverage_pct`, `app_security.provisioning_enabled_pct`, and `app_security.deprovisioning_enabled_pct` are omitted because the Reports and Directory APIs do not expose per-app SSO or provisioning settings. `policy.session_lifetime_max_min`, `policy.idle_timeout_max_min`, `policy.phishing_resistant_required_for_privileged`, and `device_access.managed_device_required_for_admins` are also omitted because those tenant controls are not available through these APIs in a reliable tenant-wide form.

`device_access.managed_device_required` is positive-only evidence derived from Context-Aware Access audit logs. The collector sets it only when Google reports `ACCESS_DENY_EVENT` entries whose parameters include a device-state field. This is evidence that a device-state access level fired, not proof of complete policy coverage, and Google does not emit grant events for clean passes. Context-Aware Access monitor mode can also produce similar deny-style events, so the collector surfaces this as evidence with an explicit diagnostics caveat rather than as a full configuration truth.

When `organization_id` or `access_policy` is configured and the service account has `roles/accesscontextmanager.policyReader`, the detailed artifact also includes an `access_context_manager` summary under `device_access`. This summarizes basic access levels with `devicePolicy` conditions and counts any custom CEL access levels, but it still does not prove which Workspace apps those levels are attached to.

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
| `privileged_users_count` | **Unique privileged identities.** Counts active users with any privileged role without double-counting users that hold multiple admin role types. |
| `super_admin_count` | **Blast radius.** Super admins have unrestricted access. Fewer is better. Industry guidance recommends 2-4 for business continuity without excess risk. |
| `delegated_admin_count` | **Delegated access scope.** Delegated admins have subset privileges. High counts may indicate over-delegation. |
| `privileged_users_2sv_enrolled_pct` | **Admin MFA coverage.** Tracks whether privileged users have actually enrolled in 2SV, which is the closest Google Workspace signal to real privileged MFA coverage. |
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

### device_access

Context-Aware Access deny evidence.

| Metric | Why It Matters |
|--------|----------------|
| `lookback_days` | **Evidence window.** Number of days of audit history searched for device-state-based denials. |
| `context_aware_access_denied_events` | **Control activity.** Total Context-Aware Access deny events seen in the audit window. |
| `device_state_denied_events` | **Managed-device evidence.** Denials that specifically included a device-state parameter, indicating device posture was part of the access decision. |
| `managed_device_requirement_evidenced` | **Positive-only signal.** `true` means Google audit logs show device-state access levels firing somewhere in the tenant; it is not proof of full policy coverage, and monitor-mode events can look similar. |
| `access_context_manager.*` | **Config enrichment.** Optional Google Cloud access-level summary that helps you see whether the org has basic device-policy access levels configured, even though Workspace-side app assignment is still API-thin. |

## Use Cases

- **Third-Party Risk Assessment**: Share aggregated posture metrics under NDA without exposing user-level details
- **Security Baseline Monitoring**: Track 2SV enrollment, admin MFA enforcement, and password hygiene over time
- **Compliance Evidence**: Demonstrate MFA coverage and account lifecycle controls for SOC 2, ISO 27001, and similar frameworks
- **Privileged Access Review**: Monitor super admin counts and admin 2SV enforcement as a leading indicator of identity risk
