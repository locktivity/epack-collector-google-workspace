# Google Workspace Collector Overview

The Google Workspace collector gathers security posture metrics from your Google Workspace tenant. It covers authentication strength, account hygiene, privileged access, password health, third-party app exposure, and positive-only Context-Aware Access deny evidence related to device state.

## Output

The collector always emits a detailed artifact and a collector result, and emits a normalized artifact when it can read the tenant's primary domain:

- `artifacts/google-workspace.details.json`: detailed Google Workspace posture metrics (always emitted)
- `artifacts/google-workspace.idp-posture.json`: normalized `evidencepack/idp-posture@v1` artifact for cross-provider comparison (omitted when the tenant record cannot be read, which takes a Super Admin)
- `artifacts/google-workspace.collector-result.json`: the values the collector could not read, each with a code such as `permission_denied` or `not_licensed`, and the API calls it made (always emitted)

### Values left out

A value the collector could not read is `null` in the detailed artifact, or absent in the normalized one, and the collector result says why. A percentage over no users is `null` in both. A normalized value Google Workspace has no data for is absent too, and the collector result lists it with the code `unsupported`. A normalized value Google reports through a read the collector does not make yet is absent with the code `not_read`. The usage report counts (`users.total`, `suspended`, `archived`) and the percentages derived from them are as of `usage_report_date`, two to three days back; `users.active` and the 2-step verification, activity, inactivity, and admin metrics come from the live Directory scan.

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

`customer_id`, `access_policy_name`, and `access_policy_parent` are written from the `audit` level. A trust run leaves them out.

### Normalized IDP Posture Artifact

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

The normalized artifact follows the `evidencepack/idp-posture@v1` schema, matching the same shape used by the Okta and other IDP collectors. The example is an audit-level artifact. At the trust level the counts are left out and the `*_present` flags stay. `app_security.authorized_third_party_apps_count` is written at the internal level only.

Each normalized percentage is a whole number. A percentage where more is better, such as MFA coverage, rounds down. One where more is worse, such as inactive users, rounds up. The detailed artifact keeps two decimal places.

`user_security.user_count` is the live Directory scan's active users. `inactive_pct` is taken over it, and so is the 2SV share in `mfa_coverage_pct`. The other `user_security` percentages come from the usage report and are taken over its total users, which include suspended and archived accounts. Their counts are left out, because their total differs from `user_count`. When the user scan fails, `users_present` is unknown and those percentages are left out.

| Normalized field | Google Workspace source | Notes |
|---|---|---|
| `user_security.users_present`, `user_count` | `users.active` | Users in the live Directory scan who are not suspended or archived |
| `user_security.mfa_coverage_pct` | `authentication.2sv_enrolled_pct`, `passkey_users_pct` | The larger of two shares. One is the active users enrolled in 2SV, over the live scan's active users. The other is the usage report's passkey users, over its total users. Suspended and archived users are left out of the 2SV share |
| `user_security.mfa_phishing_resistant_pct` | `passkey_users_pct` | Passkey adoption as phishing-resistant proxy |
| `user_security.inactive_pct`, `inactive_user_count` | `users.inactive_pct` | Over the live scan's active users |
| `user_security.locked_out_pct` | `users.locked_pct` | Over the usage report's total users |
| `user_security.weak_password_pct` | `weak_password_pct` | Over the usage report's total users |
| `user_security.password_policy_noncompliant_pct` | `password_length_non_compliant_pct` | Users that fail the tenant password length policy |
| `app_security.authorized_third_party_apps_count` | `authorized_apps_count` | OAuth-connected third-party application count |
| `privileged_access.privileged_users_present`, `privileged_users_count` | `privileged_users_count` | Unique active privileged users only |
| `privileged_access.super_admin_count` | `super_admin_count` | Excludes suspended and archived admins |
| `privileged_access.privileged_mfa_coverage_pct`, `privileged_mfa_user_count` | `privileged_users_2sv_enrolled_pct` | Active privileged users with 2SV enrolled |
| `privileged_access.standing_privileged_users_present`, `standing_privileged_users_count` | `privileged_users_count` | `false` and 0 for a tenant with no admins, and absent otherwise |
| `policy.mfa_required` | `2sv_enforced_pct` | `true` only when every active user has 2SV enforced by policy |
| `policy.mfa_required_coverage_pct`, `mfa_required_user_count` | `2sv_enforced_pct` | Active users with 2SV enforced by policy |
| `policy.session_lifetime_max_min` | `sign_in.web_session_duration_max_minutes` | The longest web session any org unit or group allows |
| `lifecycle.accounts_present`, `account_count` | `users.total` | The usage report's total users, in every state |
| `lifecycle.suspended_pct`, `suspended_account_count` | `users.suspended` | Uses the usage report's suspended user count |
| `lifecycle.archived_pct`, `archived_account_count` | `users.archived` | Uses the usage report's archived user count |
| `device_access.managed_device_required` | `device_access.managed_device_requirement_evidenced` | Emitted only when Context-Aware Access deny events include a device-state parameter |

The password policy stays in the detailed artifact under `passwords.policy`, since the `idp-posture` schema has no password policy fields.

These normalized values are left out with an `unsupported` gap, since Google Workspace has no data for them:

- `app_security.sso_coverage_pct`, `provisioning_enabled_pct`, `deprovisioning_enabled_pct`, and `apps_present`, with their counts. No Google Workspace API lists the apps set up for SSO or their provisioning settings.
- `policy.idle_timeout_max_min`. Google Workspace has no idle timeout for sign-in sessions. Its session controls set only a web session length.
- `device_access.managed_device_required_for_admins`. No API reports the Context-Aware Access levels assigned to apps.
- `policy.legacy_auth_blocked`. Google stopped supporting less secure apps on May 1, 2025, so that setting has no effect on it. App passwords still allow password-only sign-in for users with 2-step verification, and no API reports whether they are in use.

These normalized values are left out with a `not_read` gap, since Google reports them through reads the collector does not make yet:

- `privileged_access.privileged_phishing_resistant_pct` and its count. The Reports API's user usage report gives each user's passkeys as `accounts:num_passkeys_enrolled`, under `admin.reports.usage.readonly`.
- `policy.phishing_resistant_required_for_privileged`. The Policy API gives each org unit's and group's allowed 2-Step Verification methods in `security.two_step_verification_enforcement_factor`, under `cloud-identity.policies.readonly`.
- `privileged_access.standing_privileged_users_present` and its count, for a tenant with admins. An admin role can be assigned until a set time. The Directory API gives that time in a role assignment's `expirationDetails.expireTime`, under `admin.directory.rolemanagement.readonly`.

`device_access.managed_device_required` is positive-only evidence derived from Context-Aware Access audit logs. The collector sets it only when Google reports `ACCESS_DENY_EVENT` entries whose parameters include a device-state field. This is evidence that a device-state access level fired, not proof of complete policy coverage, and Google does not emit grant events for clean passes. Context-Aware Access monitor mode can also produce similar deny-style events, so the collector surfaces this as evidence with an explicit diagnostics caveat rather than as a full configuration truth.

When `organization_id` or `access_policy` is configured and the service account has `roles/accesscontextmanager.policyReader`, the detailed artifact also includes an `access_context_manager` summary under `device_access`. This summarizes basic access levels with `devicePolicy` conditions and counts any custom CEL access levels, but it still does not prove which Workspace apps those levels are attached to. A level's device requirements come only from conditions every request has to meet, so a condition joined with OR or set to Don't meet is left out of them.

## Metrics Reference

### users

User population and account health.

| Metric | Why It Matters |
|--------|----------------|
| `total` | **Tenant size.** Total user accounts including suspended and archived. |
| `suspended` | **Disabled accounts.** Users administratively suspended from the tenant. |
| `archived` | **Retained accounts.** Users archived but not deleted, often for compliance retention. |
| `locked_pct` | **Potential attack indicator.** Spikes in lockout rates may indicate brute force or credential stuffing attacks. |
| `active` | **Live population.** Users not suspended or archived in the live Directory scan. The inactivity, 2-step verification enrollment and enforcement, and activity percentages are calculated against it. |
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
| `2sv_protected_pct` | **Protected users.** Share of users protected by 2SV in the usage report. It includes users still in an enrollment grace period, who have not set up a second factor yet. |
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
| `policy.minimum_length` | **The requirement itself.** The shortest password the tenant will accept. Without it, a zero non-compliance rate is ambiguous: it reads the same whether the minimum is 14 or Google's floor of 8. |
| `policy.maximum_length` | **Upper bound.** Informational. |
| `policy.allowed_strength` | **Strength requirement.** `strong` means Google rejects passwords its strength algorithm rates weak. Google Workspace has no character-class complexity setting; this is the equivalent control. |
| `policy.enforce_requirements_at_login` | **Does the policy bind existing users?** False means a password that predates the policy survives until its owner chooses to change it. This is what makes the non-compliance percentage interpretable: with enforcement off, a zero rate is voluntary compliance rather than a forced migration. |
| `policy.allow_reuse` | **Reuse restriction.** True means a previous password can be set again. |
| `policy.expiration_days` | **Rotation.** 0 means passwords never expire, which is the weakest setting rather than the strongest. |
| `policy.distinct_policies` | **Uniformity.** Greater than 1 means org units or groups have different policies and every value above describes the weakest one in force. |

The policy values describe the weakest policy anywhere in the tenant, so a
reviewer can rely on them holding everywhere. The whole `policy` object is
omitted when it could not be read: absence never means permissive.

Google does not apply these requirements to passwords set through the Directory
API, the bulk upload tool, sync tools, or an administrator reset. That is why
the outcome percentages stay alongside the policy rather than being replaced by
it: the percentages observe what the policy bypasses.

### sign_in

Sign-in settings from the Policy API. Each value is the weakest one any org unit or group gets. A value is absent, with a gap, when its policies could not be read or the Policy API returned none.

| Metric | Why It Matters |
|--------|----------------|
| `web_session_duration_max_minutes` | **Session length.** The longest time anyone stays signed in on the web before Google asks them to sign in again. A shorter session limits how long a stolen session cookie works. Rounded up to whole minutes. |
| `less_secure_apps_allowed` | **Retired setting.** True when any org unit or group still has the less secure apps setting turned on. Google stopped supporting less secure apps on May 1, 2025, so the value no longer means people can sign in with only a username and password. |

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
