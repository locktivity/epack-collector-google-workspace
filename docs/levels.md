# Collection Levels

The Google Workspace collector accepts an optional `level` config knob
controlling how much detail it gathers. There are three levels, and they are
cumulative: `internal` is a strict superset of `audit`, which is a strict
superset of `trust`. No level removes a field that a lower level produced.

## The three levels

| Level | Question it answers | What's in the artifact |
|---|---|---|
| `trust` (default) | Do they pass? | Org-wide aggregates and on/off flags: user / admin counts, 2-step-verification and passkey coverage, password-hygiene percentages and the configured password policy, authorized-app counts, and Context-Aware Access device-state deny evidence. No user emails, group names, device details, or audit-log events. Needs only the base scopes. |
| `audit` | Where is the gap? | Per-resource inventories (users, admins + role assignments, custom roles, groups, org units, devices, SAML profiles, domains) and counts of admin, login, OAuth-token, and external-Drive-sharing events over a recent window. Email / login is the only user identifier. |
| `internal` | Who or what specifically? | Per-user last-login, per-group member rosters, per-device records, security-relevant admin / login event slices, per-OAuth-token grants with scopes, SSO service hosts, and Vault hold metadata. |

## Configuration

Set the level in your epack.yaml under the collector's `config` block:

```yaml
collectors:
  google-workspace:
    source: locktivity/epack-collector-google-workspace@^0.2
    config:
      admin_email: admin@example.com
      level: audit
    secrets:
      - GOOGLE_SERVICE_ACCOUNT_JSON
```

Default is `trust` when the key is absent or empty; unknown values fall back to
`trust`. The active level appears in the output artifact as the top-level
`collected_at_level` field.

`audit` and `internal` require additional OAuth scopes, and the impersonation
user must hold an admin role able to read each surface. The scope table and
role options are on the [configuration page](configuration.md#step-5-authorize-scopes-in-google-workspace).
When a scope is missing, a role is insufficient, or a feature is not licensed,
the affected surface degrades rather than failing the run: scope and role
denials are recorded under `diagnostics.permission_errors`, and licensing gaps,
report lag, and truncation under `diagnostics.warnings`.

## What each level adds, per surface

The core posture surfaces (users, activity, authentication, admins, passwords,
apps) are always present, derived from the Reports usage report and a live
Directory user scan. If either core fetch is denied or unavailable, its fields
emit zeroed and a diagnostic is recorded; the rest of the artifact still ships.

### Users (`users`)

- **trust**: total / suspended / archived counts, locked / inactive percentages
  (inactivity threshold 90 days).
- **audit**: `inventory[]` per-user rows (email, suspended / archived, org unit,
  agreed-to-terms, IP-allowlisted, 2SV enrolled / enforced, 7d / 30d active).
- **internal**: each row gains last-login timestamp and the
  change-password-at-next-login flag.

### Activity (`activity`) and Authentication (`authentication`)

- **trust**: 7-day / 30-day active percentages; 2SV enrolled / enforced /
  protected coverage, passkey-user coverage, security-key total. 2SV enrollment
  and enforcement and the activity percentages are reconciled against live
  Directory data.

### Admins (`admins`)

- **trust**: privileged-user / super-admin / delegated-admin counts, privileged
  2SV enrolled / enforced coverage.
- **audit**: `inventory[]` per-privileged-user rows (email, super / delegated
  flags, 2SV flags, assigned role names) and `custom_roles[]` (non-system admin
  roles with privilege counts).
- **internal**: each admin row gains the org-unit-scoped flag.

### Passwords (`passwords`) and Apps (`apps`)

- **trust**: weak-password and password-length-non-compliant percentages; the
  configured password policy (`passwords.policy`); authorized-app count.

The password policy is org-wide configuration naming no person and no org unit,
so it sits at trust beside the percentages. It needs
`cloud-identity.policies.readonly`, which is not one of the base scopes: without
it the percentages still collect and the policy object is omitted with a
scope-denied diagnostic.

### Device access (`device_access`)

Inferred from deny-only Context-Aware Access audit events (90-day lookback) plus,
when configured, Access Context Manager access-level config.

- **trust**: context-aware-access and device-state deny-event counts, the
  managed-device-requirement-evidenced flag, and (when `organization_id` or
  `access_policy` is set) basic / custom access-level counts and device-policy
  level titles.

The surfaces below first appear at `audit`; they return nothing at `trust`.

### Groups (`groups`)

- **audit**: total, admin-created / user-created counts, external-members-allowed
  count, and `inventory[]` per-group rows (email, name, description, member count,
  admin-created, allow-external-members, who-can-join, who-can-post).
- **internal**: each group gains `members[]` (email, role, type, status, delivery
  settings; capped, see Truncation).

### Org units (`org_units`)

- **audit**: total, max-depth, and `inventory[]` per-org-unit rows (path, parent,
  description, user count, block-inheritance).

### Endpoint (`endpoint`)

- **audit**: total managed devices, counts by OS, not-synced-30d, and compliant /
  non-compliant by OS.
- **internal**: `inventory[]` per-device rows (platform, OS, model, owner email,
  compliant, encrypted, screen-lock-enforced, last sync).

### Domain settings (`domain_settings`)

- **audit**: SSO-configured flag, SAML-profile and verified-domain counts, primary
  domain, plus `saml_profiles[]` (display name, IdP entity ID) and `domains[]`
  (name, verified, primary).
- **internal**: each SAML profile gains the SSO service host (host only).

### Vault (`vault`)

- **audit**: licensed flag, matters and holds counts, and `matters[]` (matter ID,
  name, state, hold count).
- **internal**: `holds[]` (hold ID, matter, corpus, account count, org-unit-scoped,
  updated-at).

Requires a Vault (eDiscovery) license; on an unlicensed tenant the surface is
omitted and a diagnostic is recorded.

### Drive external sharing (`drive_external_sharing`)

- **trust**: omitted.
- **audit**: external-share and public-on-web event counts (30-day count window).
- **internal**: `events[]` slice over a 7-day window (time, file ID, sharer email,
  recipient domain only, target role). Capped; see Truncation.

### Admin audit log (`admin_audit_log`) and Login audit log (`login_audit_log`)

- **trust**: omitted.
- **audit**: `counts_by_category` (admin) and suspicious / failed-login and
  password-leak counts (login) over a 7-day window.
- **internal**: `events[]` slices (time, actor email, event name, category; login
  events add IP address). Capped; see Truncation.

### OAuth tokens (`oauth_tokens`)

- **trust**: omitted.
- **audit**: tokens-issued and apps-with-new-tokens counts, counts by app and by
  scope sensitivity (7-day window).
- **internal**: `tokens[]` per-grant rows (user email, client ID, display name,
  scopes, granted-at). Capped; see Truncation.

## Truncation

Internal-level inventories are capped for very large tenants to keep artifacts
within the per-collector size limit:

| Surface | Cap | Sort (most-significant kept) |
|---|---|---|
| Users | 50,000 | ACTIVE first, then email ascending |
| Groups | 10,000 groups | member count descending |
| Group memberships | 200,000 total member rows | largest groups first |
| Endpoint devices | 5,000 | last sync descending |
| Audit / Drive / OAuth events | 5,000 each | most recent first |

When a cap fires, the surface sets a `truncated_*` flag and a dropped count.

## Never emitted, at any level

Message, calendar, Drive, and chat contents; file names (Drive events carry the
file ID, not the name); device serial numbers and IMEIs; password hashes and
recovery-question answers; OAuth token values and client secrets; and SAML
signing certificates are never collected. External-share recipients appear as
their email domain only.
