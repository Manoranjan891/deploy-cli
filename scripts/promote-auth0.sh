#!/usr/bin/env bash
# =============================================================================
# promote-auth0.sh
# Exports Auth0 configuration from Sandbox and imports it into Dev.
# Designed to run inside GitHub Actions or locally for testing.
#
# Required environment variables:
#   SANDBOX_AUTH0_DOMAIN
#   SANDBOX_AUTH0_CLIENT_ID
#   SANDBOX_AUTH0_CLIENT_SECRET
#   DEV_AUTH0_DOMAIN
#   DEV_AUTH0_CLIENT_ID
#   DEV_AUTH0_CLIENT_SECRET
# =============================================================================
set -euo pipefail

# -----------------------------------------------------------------------------
# Configuration
# -----------------------------------------------------------------------------
EXPORT_DIR="auth0/exported"
TENANT_FILE="${EXPORT_DIR}/tenant.yaml"

# Auth0 Deploy CLI delete mode — ENABLED
# Resources in Dev that don't exist in Sandbox export WILL be removed.
# This ensures Dev is an exact mirror of Sandbox.
AUTH0_ALLOW_DELETE="${AUTH0_ALLOW_DELETE:-true}"

# -----------------------------------------------------------------------------
# Helper functions
# -----------------------------------------------------------------------------
log_info()  { echo "▶ [INFO]  $*"; }
log_ok()    { echo "✓ [OK]    $*"; }
log_error() { echo "✗ [ERROR] $*" >&2; }

check_env_var() {
  local var_name="$1"
  if [ -z "${!var_name:-}" ]; then
    log_error "Required environment variable ${var_name} is not set."
    exit 1
  fi
}

# -----------------------------------------------------------------------------
# Preflight: Validate environment variables
# -----------------------------------------------------------------------------
log_info "Validating required environment variables..."

check_env_var "SANDBOX_AUTH0_DOMAIN"
check_env_var "SANDBOX_AUTH0_CLIENT_ID"
check_env_var "SANDBOX_AUTH0_CLIENT_SECRET"
check_env_var "DEV_AUTH0_DOMAIN"
check_env_var "DEV_AUTH0_CLIENT_ID"
check_env_var "DEV_AUTH0_CLIENT_SECRET"

log_ok "All required environment variables are set."

# -----------------------------------------------------------------------------
# Cleanup function to remove temp config files (contains secrets)
# -----------------------------------------------------------------------------
cleanup() {
  rm -f "${SANDBOX_CONFIG:-}" "${DEV_CONFIG:-}" /tmp/vault-conn-map.*.json /tmp/flow-map.*.json
}
trap cleanup EXIT

# -----------------------------------------------------------------------------
# Step 1: Export from Sandbox
# -----------------------------------------------------------------------------
log_info "Exporting Auth0 config from Sandbox (${SANDBOX_AUTH0_DOMAIN})..."

# Clean previous export to avoid stale data
rm -rf "${EXPORT_DIR}"
mkdir -p "${EXPORT_DIR}"

# Write config to a temp file (a0deploy doesn't reliably read from stdin)
SANDBOX_CONFIG=$(mktemp /tmp/auth0-sandbox-config.XXXXXX.json)
cat > "${SANDBOX_CONFIG}" <<EOF
{
  "AUTH0_DOMAIN": "${SANDBOX_AUTH0_DOMAIN}",
  "AUTH0_CLIENT_ID": "${SANDBOX_AUTH0_CLIENT_ID}",
  "AUTH0_CLIENT_SECRET": "${SANDBOX_AUTH0_CLIENT_SECRET}",
  "AUTH0_EXCLUDED": [
    "guardianFactors",
    "guardianFactorProviders",
    "guardianFactorTemplates",
    "guardianPhoneFactorMessageTypes",
    "guardianPhoneFactorSelectedProvider",
    "guardianPolicies",
    "logStreams",
    "attackProtection",
    "organizations"
  ]
}
EOF

log_info "Config file contents (secrets masked):"
echo "  AUTH0_DOMAIN: ${SANDBOX_AUTH0_DOMAIN}"
echo "  AUTH0_CLIENT_ID: ${SANDBOX_AUTH0_CLIENT_ID:0:8}..."
echo "  Config path: ${SANDBOX_CONFIG}"

log_info "Running: a0deploy export --format yaml --output_folder ${EXPORT_DIR}"

a0deploy export \
  --format yaml \
  --output_folder "${EXPORT_DIR}" \
  --config_file "${SANDBOX_CONFIG}" || {
    log_error "a0deploy export failed with exit code $?"
    log_error "Listing export directory contents:"
    ls -la "${EXPORT_DIR}" 2>/dev/null || echo "  (directory does not exist)"
    exit 1
  }

# Verify export produced the tenant file
if [ ! -f "${TENANT_FILE}" ]; then
  log_error "Export failed — expected file not found: ${TENANT_FILE}"
  log_error "Check Sandbox credentials and Auth0 Deploy CLI M2M app permissions."
  exit 1
fi

log_ok "Export completed. Tenant config written to: ${TENANT_FILE}"

# -----------------------------------------------------------------------------
# Step 1b: Transform exported config for Dev tenant
# -----------------------------------------------------------------------------
log_info "Transforming exported config for Dev tenant..."

# Replace Sandbox Management API audience with Dev audience in tenant.yaml
# This fixes clientGrants that reference the Sandbox Management API
SANDBOX_API_AUDIENCE="https://${SANDBOX_AUTH0_DOMAIN}/api/v2/"
DEV_API_AUDIENCE="https://${DEV_AUTH0_DOMAIN}/api/v2/"

log_info "Replacing audience: ${SANDBOX_API_AUDIENCE} → ${DEV_API_AUDIENCE}"
find "${EXPORT_DIR}" -type f \( -name "*.yaml" -o -name "*.json" \) \
  -exec sed -i "s|${SANDBOX_API_AUDIENCE}|${DEV_API_AUDIENCE}|g" {} +

# Remove custom login page incompatibility from database connections
if [ -f "${EXPORT_DIR}/tenant.yaml" ]; then
  sed -i 's/requires_username: true/requires_username: false/g' "${EXPORT_DIR}/tenant.yaml"
fi

log_ok "Transformation complete."

# -----------------------------------------------------------------------------
# Step 2: Import into Dev
# -----------------------------------------------------------------------------
log_info "Importing Auth0 config into Dev (${DEV_AUTH0_DOMAIN})..."

# IMPORTANT NOTES FOR REVIEWERS:
# ─────────────────────────────────────────────────────────────────────────────
# • Some resources may contain tenant-specific values (e.g., callback URLs,
#   allowed origins, custom domain references). Review the exported YAML before
#   promoting to ensure no Sandbox-specific URLs leak into Dev.
#
# • Resources that commonly need exclusions or environment-specific placeholders:
#     - Applications → callback URLs, allowed logout URLs
#     - Email templates → from address, redirect URLs
#     - Custom domains
#     - Log streams (Datadog/Splunk endpoints)
#     - Attack Protection settings (may differ per environment)
#
# • To exclude specific resources from import, use the AUTH0_EXCLUDED_RULES,
#   AUTH0_EXCLUDED_CLIENTS, etc. options in the config or add an
#   auth0/excluded.json file.
# ─────────────────────────────────────────────────────────────────────────────

# Write Dev config to a temp file
DEV_CONFIG=$(mktemp /tmp/auth0-dev-config.XXXXXX.json)
cat > "${DEV_CONFIG}" <<EOF
{
  "AUTH0_DOMAIN": "${DEV_AUTH0_DOMAIN}",
  "AUTH0_CLIENT_ID": "${DEV_AUTH0_CLIENT_ID}",
  "AUTH0_CLIENT_SECRET": "${DEV_AUTH0_CLIENT_SECRET}",
  "AUTH0_ALLOW_DELETE": ${AUTH0_ALLOW_DELETE},
  "AUTH0_EXCLUDED": [
    "guardianFactors",
    "guardianFactorProviders",
    "guardianFactorTemplates",
    "guardianPhoneFactorMessageTypes",
    "guardianPhoneFactorSelectedProvider",
    "guardianPolicies",
    "logStreams",
    "attackProtection",
    "organizations",
    "flows",
    "flowVaultConnections",
    "forms"
  ]
}
EOF

IMPORT_ARGS=(
  --format yaml
  --input_file "${EXPORT_DIR}/tenant.yaml"
  --config_file "${DEV_CONFIG}"
)

# Only add --env AUTH0_ALLOW_DELETE if explicitly enabled
if [ "${AUTH0_ALLOW_DELETE}" = "true" ]; then
  log_info "WARNING: Delete mode is ENABLED. Resources not in export will be removed from Dev."
fi

log_info "Running: a0deploy import --format yaml --input_file ${EXPORT_DIR}"
log_info "Listing exported files for verification:"
find "${EXPORT_DIR}" -type f | head -50

IMPORT_EXIT_CODE=0
a0deploy import "${IMPORT_ARGS[@]}" || IMPORT_EXIT_CODE=$?

if [ "${IMPORT_EXIT_CODE}" -eq 0 ]; then
  log_ok "Import completed successfully via Deploy CLI."
else
  log_error "Deploy CLI import exited with code ${IMPORT_EXIT_CODE} (some resources may have failed)."
  log_info "Continuing with Management API sync..."
fi

# -----------------------------------------------------------------------------
# Step 3: Sync resources excluded from Deploy CLI via Management API
# (These fail in Deploy CLI due to the 'paginate' parameter bug)
# -----------------------------------------------------------------------------
log_info "Syncing additional resources via Auth0 Management API..."

# Get access tokens for both tenants
SANDBOX_TOKEN=$(curl -s --request POST \
  --url "https://${SANDBOX_AUTH0_DOMAIN}/oauth/token" \
  --header 'content-type: application/json' \
  --data "{
    \"client_id\": \"${SANDBOX_AUTH0_CLIENT_ID}\",
    \"client_secret\": \"${SANDBOX_AUTH0_CLIENT_SECRET}\",
    \"audience\": \"https://${SANDBOX_AUTH0_DOMAIN}/api/v2/\",
    \"grant_type\": \"client_credentials\"
  }" | jq -r '.access_token')

DEV_TOKEN=$(curl -s --request POST \
  --url "https://${DEV_AUTH0_DOMAIN}/oauth/token" \
  --header 'content-type: application/json' \
  --data "{
    \"client_id\": \"${DEV_AUTH0_CLIENT_ID}\",
    \"client_secret\": \"${DEV_AUTH0_CLIENT_SECRET}\",
    \"audience\": \"https://${DEV_AUTH0_DOMAIN}/api/v2/\",
    \"grant_type\": \"client_credentials\"
  }" | jq -r '.access_token')

if [ -z "${SANDBOX_TOKEN}" ] || [ "${SANDBOX_TOKEN}" = "null" ]; then
  log_error "Failed to get Sandbox access token"
  exit 1
fi
if [ -z "${DEV_TOKEN}" ] || [ "${DEV_TOKEN}" = "null" ]; then
  log_error "Failed to get Dev access token"
  exit 1
fi
log_ok "Access tokens obtained for both tenants."

# --- Guardian Factors ---
log_info "Syncing Guardian factors..."
GUARDIAN_FACTORS=$(curl -s --request GET \
  --url "https://${SANDBOX_AUTH0_DOMAIN}/api/v2/guardian/factors" \
  --header "authorization: Bearer ${SANDBOX_TOKEN}" \
  --header 'content-type: application/json')

if echo "${GUARDIAN_FACTORS}" | jq -e '.' >/dev/null 2>&1; then
  echo "${GUARDIAN_FACTORS}" | jq -c '.[]' | while read -r factor; do
    FACTOR_NAME=$(echo "${factor}" | jq -r '.name')
    FACTOR_ENABLED=$(echo "${factor}" | jq -r '.enabled')
    curl -s --request PUT \
      --url "https://${DEV_AUTH0_DOMAIN}/api/v2/guardian/factors/${FACTOR_NAME}" \
      --header "authorization: Bearer ${DEV_TOKEN}" \
      --header 'content-type: application/json' \
      --data "{\"enabled\": ${FACTOR_ENABLED}}" > /dev/null
    echo "  ✓ Guardian factor '${FACTOR_NAME}' → enabled=${FACTOR_ENABLED}"
  done
  log_ok "Guardian factors synced."
else
  log_info "Skipping Guardian factors (unable to retrieve from Sandbox)."
fi

# --- Attack Protection (Brute Force, Breached Password, Suspicious IP) ---
log_info "Syncing Attack Protection settings..."

# Brute Force Protection
BFP=$(curl -s --request GET \
  --url "https://${SANDBOX_AUTH0_DOMAIN}/api/v2/attack-protection/brute-force-protection" \
  --header "authorization: Bearer ${SANDBOX_TOKEN}")
if echo "${BFP}" | jq -e '.enabled' >/dev/null 2>&1; then
  curl -s --request PATCH \
    --url "https://${DEV_AUTH0_DOMAIN}/api/v2/attack-protection/brute-force-protection" \
    --header "authorization: Bearer ${DEV_TOKEN}" \
    --header 'content-type: application/json' \
    --data "${BFP}" > /dev/null
  echo "  ✓ Brute Force Protection synced"
fi

# Breached Password Detection
BPD=$(curl -s --request GET \
  --url "https://${SANDBOX_AUTH0_DOMAIN}/api/v2/attack-protection/breached-password-detection" \
  --header "authorization: Bearer ${SANDBOX_TOKEN}")
if echo "${BPD}" | jq -e '.enabled' >/dev/null 2>&1; then
  curl -s --request PATCH \
    --url "https://${DEV_AUTH0_DOMAIN}/api/v2/attack-protection/breached-password-detection" \
    --header "authorization: Bearer ${DEV_TOKEN}" \
    --header 'content-type: application/json' \
    --data "${BPD}" > /dev/null
  echo "  ✓ Breached Password Detection synced"
fi

# Suspicious IP Throttling
SIP=$(curl -s --request GET \
  --url "https://${SANDBOX_AUTH0_DOMAIN}/api/v2/attack-protection/suspicious-ip-throttling" \
  --header "authorization: Bearer ${SANDBOX_TOKEN}")
if echo "${SIP}" | jq -e '.enabled' >/dev/null 2>&1; then
  curl -s --request PATCH \
    --url "https://${DEV_AUTH0_DOMAIN}/api/v2/attack-protection/suspicious-ip-throttling" \
    --header "authorization: Bearer ${DEV_TOKEN}" \
    --header 'content-type: application/json' \
    --data "${SIP}" > /dev/null
  echo "  ✓ Suspicious IP Throttling synced"
fi
log_ok "Attack Protection settings synced."

# --- Log Streams ---
log_info "Syncing Log Streams..."
LOG_STREAMS=$(curl -s --request GET \
  --url "https://${SANDBOX_AUTH0_DOMAIN}/api/v2/log-streams" \
  --header "authorization: Bearer ${SANDBOX_TOKEN}")

if echo "${LOG_STREAMS}" | jq -e '.[]' >/dev/null 2>&1; then
  # Get existing log streams in Dev
  DEV_LOG_STREAMS=$(curl -s --request GET \
    --url "https://${DEV_AUTH0_DOMAIN}/api/v2/log-streams" \
    --header "authorization: Bearer ${DEV_TOKEN}")

  echo "${LOG_STREAMS}" | jq -c '.[]' | while read -r stream; do
    STREAM_NAME=$(echo "${stream}" | jq -r '.name')
    STREAM_TYPE=$(echo "${stream}" | jq -r '.type')
    # Check if already exists in Dev (by name)
    EXISTS=$(echo "${DEV_LOG_STREAMS}" | jq -r --arg name "${STREAM_NAME}" '.[] | select(.name == $name) | .id')
    if [ -n "${EXISTS}" ]; then
      echo "  ⟳ Log stream '${STREAM_NAME}' already exists in Dev, skipping"
    else
      echo "  ℹ Log stream '${STREAM_NAME}' (type: ${STREAM_TYPE}) — skipping creation (may require environment-specific sink config)"
    fi
  done
  log_ok "Log Streams reviewed."
else
  log_info "No log streams found in Sandbox."
fi

# --- Organizations ---
log_info "Syncing Organizations..."
ORGS_RAW=$(curl -s -w "\nHTTP_STATUS:%{http_code}" --request GET \
  --url "https://${SANDBOX_AUTH0_DOMAIN}/api/v2/organizations?per_page=100&include_totals=true" \
  --header "authorization: Bearer ${SANDBOX_TOKEN}")

ORGS_HTTP_STATUS=$(echo "${ORGS_RAW}" | grep "HTTP_STATUS:" | sed 's/HTTP_STATUS://')
ORGS_BODY=$(echo "${ORGS_RAW}" | sed '/HTTP_STATUS:/d')

log_info "Organizations API response status: ${ORGS_HTTP_STATUS}"
log_info "Organizations API raw response (first 500 chars): ${ORGS_BODY:0:500}"

if [ "${ORGS_HTTP_STATUS}" != "200" ]; then
  log_error "Failed to fetch organizations from Sandbox (HTTP ${ORGS_HTTP_STATUS})"
  log_error "Ensure M2M app has 'read:organizations' scope granted."
  log_info "Response: ${ORGS_BODY}"
else
  # Auth0 with include_totals returns { organizations: [...], total: N }
  # Without include_totals it returns array directly
  ORGS=$(echo "${ORGS_BODY}" | jq -c 'if type == "array" then . elif .organizations then .organizations else [] end' 2>/dev/null || echo "[]")
  ORG_COUNT=$(echo "${ORGS}" | jq 'length')
  log_info "Organizations parsed: ${ORG_COUNT}"

  if [ "${ORG_COUNT}" -gt 0 ]; then
    echo "${ORGS}" | jq -c '.[]' | while read -r org; do
      ORG_NAME=$(echo "${org}" | jq -r '.name')
      ORG_DISPLAY=$(echo "${org}" | jq -r '.display_name')
      log_info "Processing organization: '${ORG_NAME}' (display: '${ORG_DISPLAY}')"
      # Check if org exists in Dev
      DEV_ORG=$(curl -s --request GET \
        --url "https://${DEV_AUTH0_DOMAIN}/api/v2/organizations/name/${ORG_NAME}" \
        --header "authorization: Bearer ${DEV_TOKEN}")
      if echo "${DEV_ORG}" | jq -e '.id' >/dev/null 2>&1; then
        echo "  ⟳ Organization '${ORG_NAME}' already exists in Dev"
      else
        # Create org in Dev
        CREATE_PAYLOAD=$(echo "${org}" | jq '{name, display_name, branding, metadata}')
        log_info "  Creating with payload: ${CREATE_PAYLOAD}"
        RESULT=$(curl -s --request POST \
          --url "https://${DEV_AUTH0_DOMAIN}/api/v2/organizations" \
          --header "authorization: Bearer ${DEV_TOKEN}" \
          --header 'content-type: application/json' \
          --data "${CREATE_PAYLOAD}")
        if echo "${RESULT}" | jq -e '.id' >/dev/null 2>&1; then
          echo "  ✓ Created organization '${ORG_NAME}' (display: ${ORG_DISPLAY})"
        else
          echo "  ⚠ Failed to create org '${ORG_NAME}': $(echo "${RESULT}" | jq -c '.')"
        fi
      fi
    done
    log_ok "Organizations synced."
  else
    log_info "No organizations found in Sandbox (count=0)."
    log_info "If you expect organizations, ensure M2M app has 'read:organizations' scope."
  fi
fi

# --- Flow Vault Connections ---
# NOTE: Auth0 NEVER exports vault connection secrets. We sync the connection
# metadata (name, app_id, environment, setup_type) so that connections exist in
# Dev. Secrets must be configured manually in Dev on first-time setup.
log_info "Syncing Flow Vault Connections..."
VAULT_CONNS_RAW=$(curl -s -w "\nHTTP_STATUS:%{http_code}" --request GET \
  --url "https://${SANDBOX_AUTH0_DOMAIN}/api/v2/flows/vault/connections" \
  --header "authorization: Bearer ${SANDBOX_TOKEN}")

VAULT_HTTP=$(echo "${VAULT_CONNS_RAW}" | grep "HTTP_STATUS:" | sed 's/HTTP_STATUS://')
VAULT_BODY=$(echo "${VAULT_CONNS_RAW}" | sed '/HTTP_STATUS:/d')

# Build a mapping file: sandbox_id → dev_id (needed for flow remapping)
VAULT_MAP_FILE=$(mktemp /tmp/vault-conn-map.XXXXXX.json)
echo "{}" > "${VAULT_MAP_FILE}"

if [ "${VAULT_HTTP}" = "200" ]; then
  # Response may be { connections: [...] } or just [...]
  VAULT_CONNS=$(echo "${VAULT_BODY}" | jq -c 'if type == "array" then . elif .connections then .connections else [] end' 2>/dev/null || echo "[]")
  VAULT_COUNT=$(echo "${VAULT_CONNS}" | jq 'length')
  log_info "Vault connections found in Sandbox: ${VAULT_COUNT}"

  if [ "${VAULT_COUNT}" -gt 0 ]; then
    # Get existing vault connections in Dev
    DEV_VAULT_RAW=$(curl -s --request GET \
      --url "https://${DEV_AUTH0_DOMAIN}/api/v2/flows/vault/connections" \
      --header "authorization: Bearer ${DEV_TOKEN}")
    DEV_VAULT_CONNS=$(echo "${DEV_VAULT_RAW}" | jq -c 'if type == "array" then . elif .connections then .connections else [] end' 2>/dev/null || echo "[]")

    echo "${VAULT_CONNS}" | jq -c '.[]' | while read -r conn; do
      CONN_ID=$(echo "${conn}" | jq -r '.id')
      CONN_NAME=$(echo "${conn}" | jq -r '.name')
      CONN_APP_ID=$(echo "${conn}" | jq -r '.app_id // empty')
      CONN_ENVIRONMENT=$(echo "${conn}" | jq -r '.environment // "production"')
      CONN_SETUP=$(echo "${conn}" | jq -r '.setup_type // empty')

      # Check if exists in Dev by name
      DEV_CONN_ID=$(echo "${DEV_VAULT_CONNS}" | jq -r --arg name "${CONN_NAME}" '.[] | select(.name == $name) | .id')

      if [ -n "${DEV_CONN_ID}" ]; then
        echo "  ⟳ Vault connection '${CONN_NAME}' exists in Dev (id: ${DEV_CONN_ID})"
        # Add to mapping
        echo "$(cat "${VAULT_MAP_FILE}")" | jq --arg sid "${CONN_ID}" --arg did "${DEV_CONN_ID}" '. + {($sid): $did}' > "${VAULT_MAP_FILE}"
      else
        # Create in Dev — secrets will be empty/placeholder
        CREATE_VC_PAYLOAD=$(echo "${conn}" | jq 'del(.id, .created_at, .updated_at, .fingerprint)')
        RESULT=$(curl -s --request POST \
          --url "https://${DEV_AUTH0_DOMAIN}/api/v2/flows/vault/connections" \
          --header "authorization: Bearer ${DEV_TOKEN}" \
          --header 'content-type: application/json' \
          --data "${CREATE_VC_PAYLOAD}")
        NEW_ID=$(echo "${RESULT}" | jq -r '.id // empty')
        if [ -n "${NEW_ID}" ]; then
          echo "  ✓ Created vault connection '${CONN_NAME}' in Dev (id: ${NEW_ID})"
          echo "    ⚠ SECRET VALUES NEED MANUAL CONFIGURATION in Dev tenant!"
          echo "$(cat "${VAULT_MAP_FILE}")" | jq --arg sid "${CONN_ID}" --arg did "${NEW_ID}" '. + {($sid): $did}' > "${VAULT_MAP_FILE}"
        else
          echo "  ⚠ Failed to create vault connection '${CONN_NAME}': $(echo "${RESULT}" | jq -c '.')"
        fi
      fi
    done
    log_ok "Vault connections synced (secrets need manual setup in Dev)."
  else
    log_info "No vault connections found in Sandbox."
  fi
else
  log_error "Failed to fetch vault connections (HTTP ${VAULT_HTTP}). Ensure M2M app has 'read:flows' scope."
  log_info "Response: ${VAULT_BODY:0:300}"
fi

# --- Flows ---
log_info "Syncing Flows..."
FLOWS_RAW=$(curl -s -w "\nHTTP_STATUS:%{http_code}" --request GET \
  --url "https://${SANDBOX_AUTH0_DOMAIN}/api/v2/flows" \
  --header "authorization: Bearer ${SANDBOX_TOKEN}")

FLOWS_HTTP=$(echo "${FLOWS_RAW}" | grep "HTTP_STATUS:" | sed 's/HTTP_STATUS://')
FLOWS_BODY=$(echo "${FLOWS_RAW}" | sed '/HTTP_STATUS:/d')

# Build flow ID mapping for forms
FLOW_MAP_FILE=$(mktemp /tmp/flow-map.XXXXXX.json)
echo "{}" > "${FLOW_MAP_FILE}"

if [ "${FLOWS_HTTP}" = "200" ]; then
  FLOWS=$(echo "${FLOWS_BODY}" | jq -c 'if type == "array" then . elif .flows then .flows else [] end' 2>/dev/null || echo "[]")
  FLOW_COUNT=$(echo "${FLOWS}" | jq 'length')
  log_info "Flows found in Sandbox: ${FLOW_COUNT}"

  if [ "${FLOW_COUNT}" -gt 0 ]; then
    # Get existing flows in Dev
    DEV_FLOWS_RAW=$(curl -s --request GET \
      --url "https://${DEV_AUTH0_DOMAIN}/api/v2/flows" \
      --header "authorization: Bearer ${DEV_TOKEN}")
    DEV_FLOWS=$(echo "${DEV_FLOWS_RAW}" | jq -c 'if type == "array" then . elif .flows then .flows else [] end' 2>/dev/null || echo "[]")

    echo "${FLOWS}" | jq -c '.[]' | while read -r flow; do
      FLOW_ID=$(echo "${flow}" | jq -r '.id')
      FLOW_NAME=$(echo "${flow}" | jq -r '.name')

      log_info "Processing flow: '${FLOW_NAME}' (id: ${FLOW_ID})"

      # Get full flow definition (with DAG/nodes)
      FLOW_DETAIL=$(curl -s --request GET \
        --url "https://${SANDBOX_AUTH0_DOMAIN}/api/v2/flows/${FLOW_ID}" \
        --header "authorization: Bearer ${SANDBOX_TOKEN}")

      # Remap vault connection IDs in the flow definition
      FLOW_DEF=$(echo "${FLOW_DETAIL}" | jq 'del(.id, .created_at, .updated_at, .executed_at)')

      # Replace Sandbox vault connection IDs with Dev IDs
      VAULT_MAP=$(cat "${VAULT_MAP_FILE}")
      for SB_VC_ID in $(echo "${VAULT_MAP}" | jq -r 'keys[]'); do
        DEV_VC_ID=$(echo "${VAULT_MAP}" | jq -r --arg k "${SB_VC_ID}" '.[$k]')
        FLOW_DEF=$(echo "${FLOW_DEF}" | sed "s/${SB_VC_ID}/${DEV_VC_ID}/g")
      done

      # Check if flow exists in Dev by name
      DEV_FLOW_ID=$(echo "${DEV_FLOWS}" | jq -r --arg name "${FLOW_NAME}" '.[] | select(.name == $name) | .id')

      if [ -n "${DEV_FLOW_ID}" ]; then
        # Update existing flow
        UPDATE_PAYLOAD=$(echo "${FLOW_DEF}" | jq '{name, actions}')
        RESULT=$(curl -s --request PATCH \
          --url "https://${DEV_AUTH0_DOMAIN}/api/v2/flows/${DEV_FLOW_ID}" \
          --header "authorization: Bearer ${DEV_TOKEN}" \
          --header 'content-type: application/json' \
          --data "${UPDATE_PAYLOAD}")
        if echo "${RESULT}" | jq -e '.id' >/dev/null 2>&1; then
          echo "  ✓ Updated flow '${FLOW_NAME}' in Dev"
          echo "$(cat "${FLOW_MAP_FILE}")" | jq --arg sid "${FLOW_ID}" --arg did "${DEV_FLOW_ID}" '. + {($sid): $did}' > "${FLOW_MAP_FILE}"
        else
          echo "  ⚠ Failed to update flow '${FLOW_NAME}': $(echo "${RESULT}" | jq -r '.message // .error // "unknown"')"
        fi
      else
        # Create new flow
        CREATE_PAYLOAD=$(echo "${FLOW_DEF}" | jq '{name, actions}')
        RESULT=$(curl -s --request POST \
          --url "https://${DEV_AUTH0_DOMAIN}/api/v2/flows" \
          --header "authorization: Bearer ${DEV_TOKEN}" \
          --header 'content-type: application/json' \
          --data "${CREATE_PAYLOAD}")
        NEW_FLOW_ID=$(echo "${RESULT}" | jq -r '.id // empty')
        if [ -n "${NEW_FLOW_ID}" ]; then
          echo "  ✓ Created flow '${FLOW_NAME}' in Dev (id: ${NEW_FLOW_ID})"
          echo "$(cat "${FLOW_MAP_FILE}")" | jq --arg sid "${FLOW_ID}" --arg did "${NEW_FLOW_ID}" '. + {($sid): $did}' > "${FLOW_MAP_FILE}"
        else
          echo "  ⚠ Failed to create flow '${FLOW_NAME}': $(echo "${RESULT}" | jq -r '.message // .error // "unknown"')"
        fi
      fi
    done
    log_ok "Flows synced."
  else
    log_info "No flows found in Sandbox."
  fi
else
  log_error "Failed to fetch flows (HTTP ${FLOWS_HTTP}). Ensure M2M app has 'read:flows' scope."
  log_info "Response: ${FLOWS_BODY:0:300}"
fi

# --- Forms ---
log_info "Syncing Forms..."
FORMS_RAW=$(curl -s -w "\nHTTP_STATUS:%{http_code}" --request GET \
  --url "https://${SANDBOX_AUTH0_DOMAIN}/api/v2/forms" \
  --header "authorization: Bearer ${SANDBOX_TOKEN}")

FORMS_HTTP=$(echo "${FORMS_RAW}" | grep "HTTP_STATUS:" | sed 's/HTTP_STATUS://')
FORMS_BODY=$(echo "${FORMS_RAW}" | sed '/HTTP_STATUS:/d')

if [ "${FORMS_HTTP}" = "200" ]; then
  FORMS=$(echo "${FORMS_BODY}" | jq -c 'if type == "array" then . elif .forms then .forms else [] end' 2>/dev/null || echo "[]")
  FORM_COUNT=$(echo "${FORMS}" | jq 'length')
  log_info "Forms found in Sandbox: ${FORM_COUNT}"

  if [ "${FORM_COUNT}" -gt 0 ]; then
    # Get existing forms in Dev
    DEV_FORMS_RAW=$(curl -s --request GET \
      --url "https://${DEV_AUTH0_DOMAIN}/api/v2/forms" \
      --header "authorization: Bearer ${DEV_TOKEN}")
    DEV_FORMS=$(echo "${DEV_FORMS_RAW}" | jq -c 'if type == "array" then . elif .forms then .forms else [] end' 2>/dev/null || echo "[]")

    echo "${FORMS}" | jq -c '.[]' | while read -r form; do
      FORM_ID=$(echo "${form}" | jq -r '.id')
      FORM_NAME=$(echo "${form}" | jq -r '.name')

      log_info "Processing form: '${FORM_NAME}' (id: ${FORM_ID})"

      # Get full form definition
      FORM_DETAIL=$(curl -s --request GET \
        --url "https://${SANDBOX_AUTH0_DOMAIN}/api/v2/forms/${FORM_ID}" \
        --header "authorization: Bearer ${SANDBOX_TOKEN}")

      # Clean up non-transferable fields
      FORM_DEF=$(echo "${FORM_DETAIL}" | jq 'del(.id, .created_at, .updated_at)')

      # Remap flow IDs in form (forms can embed flow references)
      FLOW_MAP=$(cat "${FLOW_MAP_FILE}")
      for SB_FLOW_ID in $(echo "${FLOW_MAP}" | jq -r 'keys[]'); do
        DEV_FLOW_ID=$(echo "${FLOW_MAP}" | jq -r --arg k "${SB_FLOW_ID}" '.[$k]')
        FORM_DEF=$(echo "${FORM_DEF}" | sed "s/${SB_FLOW_ID}/${DEV_FLOW_ID}/g")
      done

      # Also remap vault connection IDs in forms
      VAULT_MAP=$(cat "${VAULT_MAP_FILE}")
      for SB_VC_ID in $(echo "${VAULT_MAP}" | jq -r 'keys[]'); do
        DEV_VC_ID=$(echo "${VAULT_MAP}" | jq -r --arg k "${SB_VC_ID}" '.[$k]')
        FORM_DEF=$(echo "${FORM_DEF}" | sed "s/${SB_VC_ID}/${DEV_VC_ID}/g")
      done

      # Check if form exists in Dev by name
      DEV_FORM_ID=$(echo "${DEV_FORMS}" | jq -r --arg name "${FORM_NAME}" '.[] | select(.name == $name) | .id')

      if [ -n "${DEV_FORM_ID}" ]; then
        # Update existing form
        UPDATE_PAYLOAD=$(echo "${FORM_DEF}" | jq 'del(.id)')
        RESULT=$(curl -s --request PATCH \
          --url "https://${DEV_AUTH0_DOMAIN}/api/v2/forms/${DEV_FORM_ID}" \
          --header "authorization: Bearer ${DEV_TOKEN}" \
          --header 'content-type: application/json' \
          --data "${UPDATE_PAYLOAD}")
        if echo "${RESULT}" | jq -e '.id' >/dev/null 2>&1; then
          echo "  ✓ Updated form '${FORM_NAME}' in Dev"
        else
          echo "  ⚠ Failed to update form '${FORM_NAME}': $(echo "${RESULT}" | jq -r '.message // .error // "unknown"')"
        fi
      else
        # Create new form
        RESULT=$(curl -s --request POST \
          --url "https://${DEV_AUTH0_DOMAIN}/api/v2/forms" \
          --header "authorization: Bearer ${DEV_TOKEN}" \
          --header 'content-type: application/json' \
          --data "${FORM_DEF}")
        if echo "${RESULT}" | jq -e '.id' >/dev/null 2>&1; then
          echo "  ✓ Created form '${FORM_NAME}' in Dev"
        else
          echo "  ⚠ Failed to create form '${FORM_NAME}': $(echo "${RESULT}" | jq -r '.message // .error // "unknown"')"
        fi
      fi
    done
    log_ok "Forms synced."
  else
    log_info "No forms found in Sandbox."
  fi
else
  log_error "Failed to fetch forms (HTTP ${FORMS_HTTP}). Ensure M2M app has 'read:forms' scope."
  log_info "Response: ${FORMS_BODY:0:300}"
fi

# Clean up mapping files
rm -f "${VAULT_MAP_FILE}" "${FLOW_MAP_FILE}"

# -----------------------------------------------------------------------------
# Summary
# -----------------------------------------------------------------------------
echo ""
echo "═══════════════════════════════════════════════════════════════════════════"
echo " Auth0 Promotion Complete"
echo " Source:      ${SANDBOX_AUTH0_DOMAIN} (Sandbox)"
echo " Destination: ${DEV_AUTH0_DOMAIN} (Dev)"
echo " Delete mode: ${AUTH0_ALLOW_DELETE}"
echo ""
echo " Deploy CLI imported: pages, clients, actions, connections, roles,"
echo "   resource servers, email, branding, prompts, triggers"
echo " API synced: guardian, attack protection, log streams, organizations,"
echo "   flows, forms, vault connections"
echo ""
echo " NOTE: Vault connection SECRETS are never exported by Auth0."
echo " If new vault connections were created, configure their secrets"
echo " manually in the Dev tenant (one-time setup)."
echo "═══════════════════════════════════════════════════════════════════════════"

# Exit with failure if Deploy CLI import had errors
if [ "${IMPORT_EXIT_CODE}" -ne 0 ]; then
  log_error "Pipeline completed with warnings — Deploy CLI import had errors (exit code ${IMPORT_EXIT_CODE})."
  log_info "API-synced resources (guardian, attack protection, organizations, flows, forms) were still applied."
  exit 1
fi
