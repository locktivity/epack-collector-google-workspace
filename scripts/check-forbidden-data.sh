#!/usr/bin/env bash
#
# Fails the build if the collector source references Google Workspace data that
# must never enter an artifact. The collector emits posture metadata only:
# never message/file/calendar/chat content, never user profile attributes beyond
# primary email, never device serials/IMEIs, never OAuth token values, never SSO
# signing material, never Vault hold contents, never the org unit / group /
# CEL query attached to a Policy API policy. See google-workspace-fields.md
# "Out of scope" and implementation-plan D10/D13/D15.
#
# Escape hatch: prefix the call site with `// LINT-ALLOW: <reason>` if a future
# change has a legitimate, reviewed reason to mention the symbol.

set -euo pipefail

cd "$(dirname "$0")/.."

violations=$(
  grep -rn -E '\.RawPayload|\.Body|\.Snippet|gmail\.messages\.get|calendar\.events\.get|drive\.files\.get.*alt=media|\.RecoveryEmail|\.RecoveryPhone|\.CustomSchemas|\.SerialNumber|\.Imei|\.Meid|SearchQuery|HoldContent|PolicyQuery' \
    internal/collector/ \
    --include='*.go' \
    | grep -v '_test.go' \
    | grep -v '// LINT-ALLOW:' \
    || true
)

if [ -n "$violations" ]; then
  echo "FORBIDDEN GOOGLE WORKSPACE DATA EMISSION DETECTED:"
  echo "These reference content/PII that must never enter a posture artifact:"
  echo "$violations"
  exit 1
fi

echo "forbidden-data check: OK"
