# Setting up the Google Workspace collector

Follow these steps once. Steps 1 to 3 and 5 to 6 are the same whichever
authentication mode you use; step 4 is where they differ.

## Step 1: Create a Cloud project

1. Open the [Google Cloud console](https://console.cloud.google.com/).
2. Create or select a project for the collector.
3. Go to **APIs & Services > Enabled APIs** and enable the APIs below.

| API | Enable it for |
|---|---|
| Admin SDK API | Every run |
| Cloud Identity API | Every run (password policy; SAML profiles at audit and above) |
| IAM Service Account Credentials API | `auth_mode: oidc` only |
| Groups Settings API | audit and internal |
| Google Vault API | audit and internal (also needs a Vault license) |
| Access Context Manager API | Optional `device_access` enrichment |

APIs are separate from OAuth scopes. If an API is off, its surface fails with a
`SERVICE_DISABLED` diagnostic even when the scope is granted, and the rest of
the run continues.

## Step 2: Create a service account

1. Go to **IAM & Admin > Service Accounts**.
2. Click **Create Service Account**.
3. Name it, for example `epack-collector`.
4. Click **Create and Continue**, then **Done**. It needs no project-level roles.

## Step 3: Enable domain-wide delegation

1. Open the service account you just created.
2. On the **Details** tab, under **Advanced settings**, click **Enable
   Domain-wide Delegation**.
3. Copy the **Client ID**. Step 5 needs it.

## Step 4: Set up authentication

Choose one. `oidc` creates no key and is preferred on CI.

### Option A: auth_mode oidc

Everything here is in the same Cloud project as the service account.

1. Create a workload identity pool.
2. Create a provider in that pool trusting your CI provider's OIDC issuer.
3. Add an attribute condition restricting the provider to your repository or
   organization. Without one, any repository on that issuer can assume the
   identity.
4. Grant the workload identity principal `roles/iam.workloadIdentityUser` on the
   service account. This lets the runner act as it.
5. Grant the service account `roles/iam.serviceAccountTokenCreator` on itself.
   This lets it sign delegation assertions with the Google-managed key.
6. In `epack.yaml`, set `auth_mode: oidc`, `workload_identity_provider`, and
   `service_account`, and list `ACTIONS_ID_TOKEN_REQUEST_URL` and
   `ACTIONS_ID_TOKEN_REQUEST_TOKEN` under `secrets:`.
7. In the workflow, grant the `id-token: write` permission.

Step 5 is easy to miss. The service account holds a role on itself, which looks
odd but is what allows signing without a downloaded key.

The collector builds the exchange and impersonation endpoints from the two
config keys, so no credential file is involved and no auth step is needed in the
workflow.

### Option B: auth_mode service_account_key

Skip this if you followed Option A. Some organizations block key creation with
the `iam.disableServiceAccountKeyCreation` policy.

1. Open the service account's **Keys** tab.
2. Click **Add Key > Create new key > JSON**.
3. Store the downloaded file securely and pass its contents as
   `GOOGLE_SERVICE_ACCOUNT_JSON`.

This key grants access to your tenant. Treat it as a credential.

## Step 5: Authorize scopes in Google Workspace

1. Open the [Google Workspace admin console](https://admin.google.com/).
2. Go to **Security > Access and data control > API controls > Domain-wide
   delegation**.
3. Click **Add new**.
4. Enter the **Client ID** from step 3.
5. Add the scopes for the levels you plan to collect, from the table below.
6. Click **Authorize**.

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

All scopes as one comma-separated list, for pasting into the admin console:

```
https://www.googleapis.com/auth/admin.directory.user.readonly,https://www.googleapis.com/auth/admin.directory.customer.readonly,https://www.googleapis.com/auth/admin.directory.rolemanagement.readonly,https://www.googleapis.com/auth/admin.directory.group.readonly,https://www.googleapis.com/auth/admin.directory.group.member.readonly,https://www.googleapis.com/auth/admin.directory.orgunit.readonly,https://www.googleapis.com/auth/admin.directory.device.mobile.readonly,https://www.googleapis.com/auth/admin.directory.device.chromeos.readonly,https://www.googleapis.com/auth/admin.directory.domain.readonly,https://www.googleapis.com/auth/admin.reports.usage.readonly,https://www.googleapis.com/auth/admin.reports.audit.readonly,https://www.googleapis.com/auth/apps.groups.settings,https://www.googleapis.com/auth/cloud-identity.inboundsso.readonly,https://www.googleapis.com/auth/cloud-identity.policies.readonly,https://www.googleapis.com/auth/ediscovery.readonly
```

Grants are not retroactive. If you add a scope later, re-grant it here.

## Step 6: Choose the admin user to impersonate

Set `admin_email` to a Workspace admin account. The service account impersonates
this user to read admin APIs.

A Super Admin covers every surface, and most customers create a dedicated
`epack-collector@<domain>` user with Super Admin. Narrower bundles work but
have not been mapped surface by surface:

| Role | Covers |
|---|---|
| Reports Admin + User Management Admin + Groups Admin | Users, admins, groups, org units, devices, domains, audit logs. |
| Vault Admin | The Vault surface. |

## Optional: Access Context Manager enrichment

Adds access-level config to the detailed artifact alongside Context-Aware Access
deny evidence.

1. Grant the service account `roles/accesscontextmanager.policyReader` on the
   Cloud organization.
2. Set one of:
   - `organization_id`, to discover the policy under `organizations/{id}`.
   - `access_policy`, an explicit policy resource such as
     `accessPolicies/123456789` or its numeric ID. Takes precedence.

The normalized artifact stays conservative either way, because Workspace-side
app assignment and monitor-mode details are not fully exposed by API.

## Config options

| Option | Required | Description |
|---|---|---|
| `admin_email` | Yes | Workspace admin account to impersonate |
| `auth_mode` | No | `oidc`, or `service_account_key` when omitted |
| `workload_identity_provider` | With `oidc` | Full provider resource path |
| `service_account` | With `oidc` | Account to impersonate and sign as |
| `customer` | No | Google customer key. Defaults to `my_customer` |
| `organization_id` | No | Cloud organization ID for `device_access` enrichment |
| `access_policy` | No | Explicit Access Context Manager policy. Takes precedence over `organization_id` |

## Environment variables

| Variable | Description |
|---|---|
| `GOOGLE_SERVICE_ACCOUNT_JSON` | Key file contents, not a path. Required for `service_account_key`, unused for `oidc` |
| `ACTIONS_ID_TOKEN_REQUEST_URL` | Set by GitHub Actions when the workflow grants `id-token: write`. Required for `oidc` |
| `ACTIONS_ID_TOKEN_REQUEST_TOKEN` | Set alongside the URL. Authorizes fetching one identity token per run. Required for `oidc` |

## Troubleshooting

A missing scope, API, or role never fails the run. The affected surface is
omitted and a diagnostic says which of the three is missing, because each is
fixed in a different console.

### The run fails to start

| Message | Fix |
|---|---|
| `authentication required: provide GOOGLE_SERVICE_ACCOUNT_JSON` | Pass the key contents, or set `auth_mode: oidc` |
| `invalid auth_mode` | Use `oidc` or `service_account_key` |
| `workload_identity_provider is not set` | `auth_mode: oidc` needs it and `service_account` |
| `the runner exposes no OIDC identity` | Add `id-token: write` to the workflow, and list the two request variables under `secrets:` |
| `creating JWT config` | `GOOGLE_SERVICE_ACCOUNT_JSON` is not valid JSON. Copy-paste often truncates it |

### Authentication fails on the first API call

With `auth_mode: oidc`, the exchange and the signing are deferred until
something is collected, so setup mistakes appear here rather than at startup.

| Message mentions | Fix |
|---|---|
| `roles/iam.serviceAccountTokenCreator` | Grant that role to the service account on itself (step 4, item 5) |
| `iamcredentials.googleapis.com` | Enable the IAM Service Account Credentials API |
| `the workload identity exchange was rejected` | Check the pool, the provider's attribute condition, and `roles/iam.workloadIdentityUser` |
| 401 Unauthorized | Confirm `admin_email` is a real admin, delegation is enabled, and the Client ID matches |

### A surface is missing from the artifact

Check the diagnostics block. It names which of the three grants is missing.

| Diagnostic | Fix |
|---|---|
| scope denied | Add that scope in the admin console and re-grant |
| `SERVICE_DISABLED` | Enable that API in the Cloud project |
| admin role | Give the impersonated user a role that can read the surface |
| feature requires a license | The tenant's edition does not include it, for example Vault |

### The password policy is missing

`passwords.policy` is omitted rather than zeroed when it cannot be read, so an
absent policy never reads as a permissive one. The diagnostics distinguish a
missing scope, a disabled API, an insufficient role, an edition without the
Policy API, and a tenant that exposes no policy.

### Usage report data is empty

Usage reports cover the previous day, and very new tenants may have none yet.
The `usage_report_date` field shows which day the artifact covers.
