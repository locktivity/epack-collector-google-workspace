# Google Workspace Collector Configuration

## Authentication Setup

The collector uses a Google service account with domain-wide delegation. This is the standard pattern for automated access to Google Workspace admin data.

### Step 1: Create a Google Cloud Project

1. Go to [Google Cloud Console](https://console.cloud.google.com/)
2. Create or select a project for the collector
3. Go to **APIs & Services > Enabled APIs** and enable the **Admin SDK API**

### Step 2: Create a Service Account

1. Go to **IAM & Admin > Service Accounts**
2. Click **Create Service Account**
3. Name it (e.g., `epack-collector`)
4. Click **Create and Continue**, then **Done** (no roles needed at the project level)

### Step 3: Enable Domain-Wide Delegation

1. Click into the service account you just created
2. Go to the **Details** tab
3. Under **Advanced settings**, click **Enable Domain-wide Delegation**
4. Copy the **Client ID** — you'll need it in the next step

### Step 4: Create a JSON Key

1. Go to the **Keys** tab
2. Click **Add Key > Create new key > JSON**
3. Download the key file and store it securely
4. **Important**: This key grants access to your tenant. Treat it like a credential.

### Step 5: Authorize Scopes in Google Workspace

In the [Google Workspace Admin Console](https://admin.google.com/):

1. Go to **Security > Access and data control > API controls > Domain-wide delegation**
2. Click **Add new**
3. Enter the service account **Client ID** from Step 3
4. Grant these scopes:

   - `https://www.googleapis.com/auth/admin.directory.user.readonly`
   - `https://www.googleapis.com/auth/admin.directory.customer.readonly`
   - `https://www.googleapis.com/auth/admin.reports.usage.readonly`
   - `https://www.googleapis.com/auth/admin.reports.audit.readonly` (recommended, enables `device_access` evidence from Context-Aware Access audit logs)

5. Click **Authorize**

### Step 6: Choose the Admin User to Impersonate

Set `admin_email` to a Google Workspace admin account. The service account impersonates this user to access admin APIs. The account needs permission to read users, customer metadata, usage reports, and optionally audit activity for Context-Aware Access.

### Optional Step 7: Enable Access Context Manager Enrichment

If you want the detailed artifact to include Access Context Manager access-level config alongside Context-Aware Access deny evidence:

1. Grant the service account the **Access Context Manager Reader** role (`roles/accesscontextmanager.policyReader`) on the relevant Google Cloud organization.
2. Set either:
   - `organization_id` to let the collector discover the access policy under `organizations/{id}`, or
   - `access_policy` to an explicit Access Context Manager policy resource like `accessPolicies/123456789` (or just the numeric ID).

This enrichment is optional. It improves the detailed `device_access` section, but the normalized artifact remains conservative because Workspace-side app assignment and monitor-mode details are not fully exposed by API.

## Configuration Options

| Option | Required | Description |
|--------|----------|-------------|
| `admin_email` | Yes | Google Workspace admin account to impersonate |
| `customer` | No | Google customer key (defaults to `my_customer`, which resolves to your tenant) |
| `organization_id` | No | Google Cloud organization ID used to discover an Access Context Manager policy for `device_access` config enrichment |
| `access_policy` | No | Explicit Access Context Manager policy resource or numeric ID. Takes precedence over `organization_id` |

## Environment Variables

| Variable | Description |
|----------|-------------|
| `GOOGLE_SERVICE_ACCOUNT_JSON` | Full JSON content of the service account key file |

## Troubleshooting

### "creating JWT config" error

- Verify the `GOOGLE_SERVICE_ACCOUNT_JSON` environment variable contains the full JSON key file content (not a file path)
- Ensure the JSON is valid — copy-paste errors can truncate the key

### 401 Unauthorized

- Verify the `admin_email` is a real Google Workspace admin account (not a regular user)
- Ensure domain-wide delegation is enabled on the service account
- Check that the Client ID in the Admin Console matches the service account

### 403 Forbidden

- Verify all required scopes are authorized in the Admin Console under domain-wide delegation
- Ensure the admin account has permission to access usage reports and user data
- Check that the Admin SDK API is enabled in the Google Cloud project
- If only the audit scope is missing, the collector still emits the core posture artifact but omits `device_access` evidence and adds a warning to diagnostics
- If Access Context Manager enrichment is configured, verify the service account has `roles/accesscontextmanager.policyReader` on the organization and that the `organization_id` or `access_policy` value is correct

### Empty or missing usage report data

- Usage reports are typically available for the previous day. Very new tenants may not have report data yet.
- The `usage_report_date` field in the output shows which day the report covers.
