#!/usr/bin/env bash
# =============================================================================
# promote-auth0.sh
# Exports Auth0 configuration from Lower Region and imports it into Upper Region.
# Designed to run inside GitHub Actions or locally for testing.
#
# Required environment variables:
#   LOWER_REGION_AUTH0_DOMAIN
#   LOWER_REGION_AUTH0_CLIENT_ID
#   LOWER_REGION_AUTH0_CLIENT_SECRET
#   UPPER_REGION_AUTH0_DOMAIN
#   UPPER_REGION_AUTH0_CLIENT_ID
#   UPPER_REGION_AUTH0_CLIENT_SECRET
# =============================================================================
set -euo pipefail

# -----------------------------------------------------------------------------
# Configuration
# -----------------------------------------------------------------------------
EXPORT_DIR="auth0/exported"
TENANT_FILE="${EXPORT_DIR}/tenant.yaml"

# Auth0 Deploy CLI delete mode — ENABLED
# Resources in Upper Region that don't exist in Lower Region export WILL be removed.
# This ensures Upper Region is an exact mirror of Lower Region.
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

check_env_var "LOWER_REGION_AUTH0_DOMAIN"
check_env_var "LOWER_REGION_AUTH0_CLIENT_ID"
check_env_var "LOWER_REGION_AUTH0_CLIENT_SECRET"
check_env_var "UPPER_REGION_AUTH0_DOMAIN"
check_env_var "UPPER_REGION_AUTH0_CLIENT_ID"
check_env_var "UPPER_REGION_AUTH0_CLIENT_SECRET"

log_ok "All required environment variables are set."

# -----------------------------------------------------------------------------
# Cleanup function to remove temp config files (contains secrets)
# -----------------------------------------------------------------------------
cleanup() {
  rm -f "${LOWER_REGION_CONFIG:-}" "${UPPER_REGION_CONFIG:-}" /tmp/vault-conn-map.*.json /tmp/flow-map.*.json
}
trap cleanup EXIT

# -----------------------------------------------------------------------------
# Step 1: Export from Lower Region
# -----------------------------------------------------------------------------
log_info "Exporting Auth0 config from Lower Region (${LOWER_REGION_AUTH0_DOMAIN})..."

# Clean previous export to avoid stale data
rm -rf "${EXPORT_DIR}"
mkdir -p "${EXPORT_DIR}"

# Write config to a temp file (a0deploy doesn't reliably read from stdin)
LOWER_REGION_CONFIG=$(mktemp /tmp/auth0-lower-region-config.XXXXXX.json)
cat > "${LOWER_REGION_CONFIG}" <<EOF
{
  "AUTH0_DOMAIN": "${LOWER_REGION_AUTH0_DOMAIN}",
  "AUTH0_CLIENT_ID": "${LOWER_REGION_AUTH0_CLIENT_ID}",
  "AUTH0_CLIENT_SECRET": "${LOWER_REGION_AUTH0_CLIENT_SECRET}",
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
echo "  AUTH0_DOMAIN: ${LOWER_REGION_AUTH0_DOMAIN}"
echo "  AUTH0_CLIENT_ID: ${LOWER_REGION_AUTH0_CLIENT_ID:0:8}..."
echo "  Config path: ${LOWER_REGION_CONFIG}"

log_info "Running: a0deploy export --format yaml --output_folder ${EXPORT_DIR}"

a0deploy export \
  --format yaml \
  --output_folder "${EXPORT_DIR}" \
  --config_file "${LOWER_REGION_CONFIG}" || {
    log_error "a0deploy export failed with exit code $?"
    log_error "Listing export directory contents:"
    ls -la "${EXPORT_DIR}" 2>/dev/null || echo "  (directory does not exist)"
    exit 1
  }

# Verify export produced the tenant file
if [ ! -f "${TENANT_FILE}" ]; then
  log_error "Export failed — expected file not found: ${TENANT_FILE}"
  log_error "Check Lower Region credentials and Auth0 Deploy CLI M2M app permissions."
  exit 1
fi

log_ok "Export completed. Tenant config written to: ${TENANT_FILE}"

# -----------------------------------------------------------------------------
# Step 1b: Transform exported config for Upper Region tenant
# -----------------------------------------------------------------------------
log_info "Transforming exported config for Upper Region tenant..."

# Replace Lower Region Management API audience with Upper Region audience in tenant.yaml
# This fixes clientGrants that reference the Lower Region Management API
LOWER_REGION_API_AUDIENCE="https://${LOWER_REGION_AUTH0_DOMAIN}/api/v2/"
UPPER_REGION_API_AUDIENCE="https://${UPPER_REGION_AUTH0_DOMAIN}/api/v2/"

log_info "Replacing audience: ${LOWER_REGION_API_AUDIENCE} → ${UPPER_REGION_API_AUDIENCE}"
find "${EXPORT_DIR}" -type f \( -name "*.yaml" -o -name "*.json" \) \
  -exec sed -i "s|${LOWER_REGION_API_AUDIENCE}|${UPPER_REGION_API_AUDIENCE}|g" {} +

# Remove custom login page incompatibility from database connections
if [ -f "${EXPORT_DIR}/tenant.yaml" ]; then
  sed -i 's/requires_username: true/requires_username: false/g' "${EXPORT_DIR}/tenant.yaml"
fi

log_ok "Transformation complete."

# -----------------------------------------------------------------------------
# Step 2: Import into Upper Region
# -----------------------------------------------------------------------------
log_info "Importing Auth0 config into Upper Region (${UPPER_REGION_AUTH0_DOMAIN})..."

# IMPORTANT NOTES FOR REVIEWERS:
# ─────────────────────────────────────────────────────────────────────────────
# • Some resources may contain tenant-specific values (e.g., callback URLs,
#   allowed origins, custom domain references). Review the exported YAML before
#   promoting to ensure no Lower Region-specific URLs leak into Upper Region.
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
UPPER_REGION_CONFIG=$(mktemp /tmp/auth0-dev-config.XXXXXX.json)
cat > "${UPPER_REGION_CONFIG}" <<EOF
{
  "AUTH0_DOMAIN": "${UPPER_REGION_AUTH0_DOMAIN}",
  "AUTH0_CLIENT_ID": "${UPPER_REGION_AUTH0_CLIENT_ID}",
  "AUTH0_CLIENT_SECRET": "${UPPER_REGION_AUTH0_CLIENT_SECRET}",
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
  --config_file "${UPPER_REGION_CONFIG}"
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
LOWER_REGION_TOKEN=$(curl -s --request POST \
  --url "https://${LOWER_REGION_AUTH0_DOMAIN}/oauth/token" \
  --header 'content-type: application/json' \
  --data "{
    \"client_id\": \"${LOWER_REGION_AUTH0_CLIENT_ID}\",
    \"client_secret\": \"${LOWER_REGION_AUTH0_CLIENT_SECRET}\",
    \"audience\": \"https://${LOWER_REGION_AUTH0_DOMAIN}/api/v2/\",
    \"grant_type\": \"client_credentials\"
  }" | jq -r '.access_token')

UPPER_REGION_TOKEN=$(curl -s --request POST \
  --url "https://${UPPER_REGION_AUTH0_DOMAIN}/oauth/token" \
  --header 'content-type: application/json' \
  --data "{
    \"client_id\": \"${UPPER_REGION_AUTH0_CLIENT_ID}\",
    \"client_secret\": \"${UPPER_REGION_AUTH0_CLIENT_SECRET}\",
    \"audience\": \"https://${UPPER_REGION_AUTH0_DOMAIN}/api/v2/\",
    \"grant_type\": \"client_credentials\"
  }" | jq -r '.access_token')

if [ -z "${LOWER_REGION_TOKEN}" ] || [ "${LOWER_REGION_TOKEN}" = "null" ]; then
  log_error "Failed to get Lower Region access token"
  exit 1
fi
if [ -z "${UPPER_REGION_TOKEN}" ] || [ "${UPPER_REGION_TOKEN}" = "null" ]; then
  log_error "Failed to get Dev access token"
  exit 1
fi
log_ok "Access tokens obtained for both tenants."

# --- Guardian Factors ---
log_info "Syncing Guardian factors..."
GUARDIAN_FACTORS=$(curl -s --request GET \
  --url "https://${LOWER_REGION_AUTH0_DOMAIN}/api/v2/guardian/factors" \
  --header "authorization: Bearer ${LOWER_REGION_TOKEN}" \
  --header 'content-type: application/json')

# Validate response is a JSON array of objects (not an error or unexpected shape)
if echo "${GUARDIAN_FACTORS}" | jq -e 'type == "array"' >/dev/null 2>&1; then
  # Filter to only objects that have both .name (string) and .enabled (boolean)
  echo "${GUARDIAN_FACTORS}" | jq -c '.[] | select(type == "object" and .name != null and .enabled != null)' | while read -r factor; do
    FACTOR_NAME=$(echo "${factor}" | jq -r '.name')
    FACTOR_ENABLED=$(echo "${factor}" | jq -r '.enabled')

    # Skip if name or enabled couldn't be extracted
    if [ -z "${FACTOR_NAME}" ] || [ "${FACTOR_NAME}" = "null" ]; then
      echo "  ⚠ Skipping guardian factor with missing name"
      continue
    fi

    curl -s --request PUT \
      --url "https://${UPPER_REGION_AUTH0_DOMAIN}/api/v2/guardian/factors/${FACTOR_NAME}" \
      --header "authorization: Bearer ${UPPER_REGION_TOKEN}" \
      --header 'content-type: application/json' \
      --data "{\"enabled\": ${FACTOR_ENABLED}}" > /dev/null
    sleep 1  # Rate limit protection
    echo "  ✓ Guardian factor '${FACTOR_NAME}' → enabled=${FACTOR_ENABLED}"
  done
  log_ok "Guardian factors synced."
else
  log_info "Skipping Guardian factors (unable to retrieve from Lower Region or unexpected response)."
  log_info "Response (first 300 chars): ${GUARDIAN_FACTORS:0:300}"
fi

# --- Attack Protection (Brute Force, Breached Password, Suspicious IP) ---
log_info "Syncing Attack Protection settings..."

# Brute Force Protection
BFP=$(curl -s --request GET \
  --url "https://${LOWER_REGION_AUTH0_DOMAIN}/api/v2/attack-protection/brute-force-protection" \
  --header "authorization: Bearer ${LOWER_REGION_TOKEN}")
if echo "${BFP}" | jq -e '.enabled' >/dev/null 2>&1; then
  curl -s --request PATCH \
    --url "https://${UPPER_REGION_AUTH0_DOMAIN}/api/v2/attack-protection/brute-force-protection" \
    --header "authorization: Bearer ${UPPER_REGION_TOKEN}" \
    --header 'content-type: application/json' \
    --data "${BFP}" > /dev/null
  echo "  ✓ Brute Force Protection synced"
fi

# Breached Password Detection
BPD=$(curl -s --request GET \
  --url "https://${LOWER_REGION_AUTH0_DOMAIN}/api/v2/attack-protection/breached-password-detection" \
  --header "authorization: Bearer ${LOWER_REGION_TOKEN}")
if echo "${BPD}" | jq -e '.enabled' >/dev/null 2>&1; then
  curl -s --request PATCH \
    --url "https://${UPPER_REGION_AUTH0_DOMAIN}/api/v2/attack-protection/breached-password-detection" \
    --header "authorization: Bearer ${UPPER_REGION_TOKEN}" \
    --header 'content-type: application/json' \
    --data "${BPD}" > /dev/null
  echo "  ✓ Breached Password Detection synced"
fi

# Suspicious IP Throttling
SIP=$(curl -s --request GET \
  --url "https://${LOWER_REGION_AUTH0_DOMAIN}/api/v2/attack-protection/suspicious-ip-throttling" \
  --header "authorization: Bearer ${LOWER_REGION_TOKEN}")
if echo "${SIP}" | jq -e '.enabled' >/dev/null 2>&1; then
  curl -s --request PATCH \
    --url "https://${UPPER_REGION_AUTH0_DOMAIN}/api/v2/attack-protection/suspicious-ip-throttling" \
    --header "authorization: Bearer ${UPPER_REGION_TOKEN}" \
    --header 'content-type: application/json' \
    --data "${SIP}" > /dev/null
  echo "  ✓ Suspicious IP Throttling synced"
fi
log_ok "Attack Protection settings synced."

# --- Log Streams ---
log_info "Syncing Log Streams..."
LOG_STREAMS=$(curl -s --request GET \
  --url "https://${LOWER_REGION_AUTH0_DOMAIN}/api/v2/log-streams" \
  --header "authorization: Bearer ${LOWER_REGION_TOKEN}")

if echo "${LOG_STREAMS}" | jq -e '.[]' >/dev/null 2>&1; then
  # Get existing log streams in Upper Region
  UPPER_REGION_LOG_STREAMS=$(curl -s --request GET \
    --url "https://${UPPER_REGION_AUTH0_DOMAIN}/api/v2/log-streams" \
    --header "authorization: Bearer ${UPPER_REGION_TOKEN}")

  echo "${LOG_STREAMS}" | jq -c '.[]' | while read -r stream; do
    STREAM_NAME=$(echo "${stream}" | jq -r '.name')
    STREAM_TYPE=$(echo "${stream}" | jq -r '.type')
    # Check if already exists in Upper Region (by name)
    EXISTS=$(echo "${UPPER_REGION_LOG_STREAMS}" | jq -r --arg name "${STREAM_NAME}" '.[] | select(.name == $name) | .id')
    if [ -n "${EXISTS}" ]; then
      echo "  ⟳ Log stream '${STREAM_NAME}' already exists in Upper Region, skipping"
    else
      echo "  ℹ Log stream '${STREAM_NAME}' (type: ${STREAM_TYPE}) — skipping creation (may require environment-specific sink config)"
    fi
  done
  log_ok "Log Streams reviewed."
else
  log_info "No log streams found in Lower Region."
fi

# --- Organizations ---
log_info "Syncing Organizations..."
ORGS_RAW=$(curl -s -w "\nHTTP_STATUS:%{http_code}" --request GET \
  --url "https://${LOWER_REGION_AUTH0_DOMAIN}/api/v2/organizations?per_page=100&include_totals=true" \
  --header "authorization: Bearer ${LOWER_REGION_TOKEN}")

ORGS_HTTP_STATUS=$(echo "${ORGS_RAW}" | grep "HTTP_STATUS:" | sed 's/HTTP_STATUS://')
ORGS_BODY=$(echo "${ORGS_RAW}" | sed '/HTTP_STATUS:/d')

log_info "Organizations API response status: ${ORGS_HTTP_STATUS}"
log_info "Organizations API raw response (first 500 chars): ${ORGS_BODY:0:500}"

if [ "${ORGS_HTTP_STATUS}" != "200" ]; then
  log_error "Failed to fetch organizations from Lower Region (HTTP ${ORGS_HTTP_STATUS})"
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
      # Check if org exists in Upper Region
      UPPER_REGION_ORG=$(curl -s --request GET \
        --url "https://${UPPER_REGION_AUTH0_DOMAIN}/api/v2/organizations/name/${ORG_NAME}" \
        --header "authorization: Bearer ${UPPER_REGION_TOKEN}")
      sleep 1  # Rate limit protection
      if echo "${UPPER_REGION_ORG}" | jq -e '.id' >/dev/null 2>&1; then
        echo "  ⟳ Organization '${ORG_NAME}' already exists in Upper Region"
      else
        # Create org in Upper Region — remove null fields (Auth0 rejects null for branding/metadata)
        CREATE_PAYLOAD=$(echo "${org}" | jq '{name, display_name} + (if .branding != null then {branding} else {} end) + (if .metadata != null then {metadata} else {} end)')
        log_info "  Creating with payload: ${CREATE_PAYLOAD}"
        RESULT=$(curl -s --request POST \
          --url "https://${UPPER_REGION_AUTH0_DOMAIN}/api/v2/organizations" \
          --header "authorization: Bearer ${UPPER_REGION_TOKEN}" \
          --header 'content-type: application/json' \
          --data "${CREATE_PAYLOAD}")
        sleep 2  # Rate limit protection
        if echo "${RESULT}" | jq -e '.id' >/dev/null 2>&1; then
          echo "  ✓ Created organization '${ORG_NAME}' (display: ${ORG_DISPLAY})"
        else
          echo "  ⚠ Failed to create org '${ORG_NAME}': $(echo "${RESULT}" | jq -c '.')"
        fi
      fi
    done
    log_ok "Organizations synced."
  else
    log_info "No organizations found in Lower Region (count=0)."
    log_info "If you expect organizations, ensure M2M app has 'read:organizations' scope."
  fi
fi

# --- Flow Vault Connections ---
# NOTE: Auth0 NEVER exports vault connection secrets. We sync the connection
# metadata (name, app_id, environment, setup_type) so that connections exist in
# Dev. Secrets must be configured manually in Upper Region on first-time setup.
log_info "Syncing Flow Vault Connections..."
VAULT_CONNS_RAW=$(curl -s -w "\nHTTP_STATUS:%{http_code}" --request GET \
  --url "https://${LOWER_REGION_AUTH0_DOMAIN}/api/v2/flows/vault/connections" \
  --header "authorization: Bearer ${LOWER_REGION_TOKEN}")

VAULT_HTTP=$(echo "${VAULT_CONNS_RAW}" | grep "HTTP_STATUS:" | sed 's/HTTP_STATUS://')
VAULT_BODY=$(echo "${VAULT_CONNS_RAW}" | sed '/HTTP_STATUS:/d')

# Build a mapping file: Lower Region_id → Upper Region_id (needed for flow remapping)
VAULT_MAP_FILE=$(mktemp /tmp/vault-conn-map.XXXXXX.json)
echo "{}" > "${VAULT_MAP_FILE}"

if [ "${VAULT_HTTP}" = "200" ]; then
  # Response may be { connections: [...] } or just [...]
  VAULT_CONNS=$(echo "${VAULT_BODY}" | jq -c 'if type == "array" then . elif .connections then .connections else [] end' 2>/dev/null || echo "[]")
  VAULT_COUNT=$(echo "${VAULT_CONNS}" | jq 'length')
  log_info "Vault connections found in Lower Region: ${VAULT_COUNT}"

  if [ "${VAULT_COUNT}" -gt 0 ]; then
    # Get existing vault connections in Upper Region
    UPPER_REGION_VAULT_RAW=$(curl -s --request GET \
      --url "https://${UPPER_REGION_AUTH0_DOMAIN}/api/v2/flows/vault/connections" \
      --header "authorization: Bearer ${UPPER_REGION_TOKEN}")
    UPPER_REGION_VAULT_CONNS=$(echo "${UPPER_REGION_VAULT_RAW}" | jq -c 'if type == "array" then . elif .connections then .connections else [] end' 2>/dev/null || echo "[]")

    echo "${VAULT_CONNS}" | jq -c '.[]' | while read -r conn; do
      CONN_ID=$(echo "${conn}" | jq -r '.id')
      CONN_NAME=$(echo "${conn}" | jq -r '.name')
      CONN_APP_ID=$(echo "${conn}" | jq -r '.app_id // empty')

      # Check if exists in Upper Region by name
      UPPER_REGION_CONN_ID=$(echo "${UPPER_REGION_VAULT_CONNS}" | jq -r --arg name "${CONN_NAME}" '.[] | select(.name == $name) | .id')

      if [ -n "${UPPER_REGION_CONN_ID}" ]; then
        echo "  ⟳ Vault connection '${CONN_NAME}' exists in Upper Region (id: ${UPPER_REGION_CONN_ID})"
        # Add to mapping
        echo "$(cat "${VAULT_MAP_FILE}")" | jq --arg sid "${CONN_ID}" --arg did "${UPPER_REGION_CONN_ID}" '. + {($sid): $did}' > "${VAULT_MAP_FILE}"
      else
        # Create in Upper Region — AUTH0 type connections need valid setup credentials
        # Auth0 NEVER exports setup/secrets, so we must provide Upper Region M2M creds
        if [ "${CONN_APP_ID}" = "AUTH0" ]; then
          # AUTH0 vault connections use M2M credentials to connect
          CREATE_VC_PAYLOAD=$(jq -n \
            --arg name "${CONN_NAME}" \
            --arg app_id "AUTH0" \
            --arg client_id "${UPPER_REGION_AUTH0_CLIENT_ID}" \
            --arg client_secret "${UPPER_REGION_AUTH0_CLIENT_SECRET}" \
            --arg domain "${UPPER_REGION_AUTH0_DOMAIN}" \
            '{
              name: $name,
              app_id: $app_id,
              setup: {
                type: "INSTALL",
                client_id: $client_id,
                client_secret: $client_secret,
                domain: $domain
              }
            }')
        else
          # Non-AUTH0 connections (HTTP, custom) — create with minimal payload
          CREATE_VC_PAYLOAD=$(echo "${conn}" | jq '{
            name,
            app_id
          } | with_entries(select(.value != null and .value != ""))')
          log_info "    (Non-AUTH0 type: '${CONN_APP_ID}' — may need manual setup)"
        fi
        log_info "  Creating vault connection '${CONN_NAME}' (app_id: ${CONN_APP_ID})"
        RESULT=$(curl -s --request POST \
          --url "https://${UPPER_REGION_AUTH0_DOMAIN}/api/v2/flows/vault/connections" \
          --header "authorization: Bearer ${UPPER_REGION_TOKEN}" \
          --header 'content-type: application/json' \
          --data "${CREATE_VC_PAYLOAD}")
        sleep 2  # Rate limit protection
        NEW_ID=$(echo "${RESULT}" | jq -r '.id // empty')
        if [ -n "${NEW_ID}" ]; then
          echo "  ✓ Created vault connection '${CONN_NAME}' in Upper Region (id: ${NEW_ID})"
          echo "$(cat "${VAULT_MAP_FILE}")" | jq --arg sid "${CONN_ID}" --arg did "${NEW_ID}" '. + {($sid): $did}' > "${VAULT_MAP_FILE}"
        else
          echo "  ⚠ Failed to create vault connection '${CONN_NAME}': $(echo "${RESULT}" | jq -c '.')"
        fi
      fi
    done || true
    log_ok "Vault connections synced (secrets need manual setup in Upper Region)."
  else
    log_info "No vault connections found in Lower Region."
  fi
else
  log_error "Failed to fetch vault connections (HTTP ${VAULT_HTTP}). Ensure M2M app has 'read:flows' scope."
  log_info "Response: ${VAULT_BODY:0:300}"
fi

# --- Flows ---
log_info "Syncing Flows..."
FLOWS_RAW=$(curl -s -w "\nHTTP_STATUS:%{http_code}" --request GET \
  --url "https://${LOWER_REGION_AUTH0_DOMAIN}/api/v2/flows" \
  --header "authorization: Bearer ${LOWER_REGION_TOKEN}")

FLOWS_HTTP=$(echo "${FLOWS_RAW}" | grep "HTTP_STATUS:" | sed 's/HTTP_STATUS://')
FLOWS_BODY=$(echo "${FLOWS_RAW}" | sed '/HTTP_STATUS:/d')

# Build flow ID mapping for forms
FLOW_MAP_FILE=$(mktemp /tmp/flow-map.XXXXXX.json)
echo "{}" > "${FLOW_MAP_FILE}"

if [ "${FLOWS_HTTP}" = "200" ]; then
  FLOWS=$(echo "${FLOWS_BODY}" | jq -c 'if type == "array" then . elif .flows then .flows else [] end' 2>/dev/null || echo "[]")
  FLOW_COUNT=$(echo "${FLOWS}" | jq 'length')
  log_info "Flows found in Lower Region: ${FLOW_COUNT}"

  if [ "${FLOW_COUNT}" -gt 0 ]; then
    # Get existing flows in Upper Region
    UPPER_REGION_FLOWS_RAW=$(curl -s --request GET \
      --url "https://${UPPER_REGION_AUTH0_DOMAIN}/api/v2/flows" \
      --header "authorization: Bearer ${UPPER_REGION_TOKEN}")
    UPPER_REGION_FLOWS=$(echo "${UPPER_REGION_FLOWS_RAW}" | jq -c 'if type == "array" then . elif .flows then .flows else [] end' 2>/dev/null || echo "[]")

    echo "${FLOWS}" | jq -c '.[]' | while read -r flow; do
      FLOW_ID=$(echo "${flow}" | jq -r '.id')
      FLOW_NAME=$(echo "${flow}" | jq -r '.name')

      log_info "Processing flow: '${FLOW_NAME}' (id: ${FLOW_ID})"
      sleep 1  # Rate limit protection

      # Get full flow definition (with DAG/nodes)
      FLOW_DETAIL=$(curl -s --request GET \
        --url "https://${LOWER_REGION_AUTH0_DOMAIN}/api/v2/flows/${FLOW_ID}" \
        --header "authorization: Bearer ${LOWER_REGION_TOKEN}")

      # Remap vault connection IDs in the flow definition
      FLOW_DEF=$(echo "${FLOW_DETAIL}" | jq 'del(.id, .created_at, .updated_at, .executed_at)')

      # Check if actions is null or missing — skip if empty flow
      ACTIONS_CHECK=$(echo "${FLOW_DEF}" | jq '.actions')
      if [ "${ACTIONS_CHECK}" = "null" ] || [ -z "${ACTIONS_CHECK}" ]; then
        echo "  ⟳ Flow '${FLOW_NAME}' has no actions, creating with empty actions array"
        FLOW_DEF=$(echo "${FLOW_DEF}" | jq '.actions = []')
      fi

      # Replace Lower Region vault connection IDs with Upper Region IDs
      VAULT_MAP=$(cat "${VAULT_MAP_FILE}")
      for SB_VC_ID in $(echo "${VAULT_MAP}" | jq -r 'keys[]'); do
        UPPER_REGION_VC_ID=$(echo "${VAULT_MAP}" | jq -r --arg k "${SB_VC_ID}" '.[$k]')
        FLOW_DEF=$(echo "${FLOW_DEF}" | sed "s/${SB_VC_ID}/${UPPER_REGION_VC_ID}/g")
      done

      # Check if flow exists in Upper Region by name
      UPPER_REGION_FLOW_ID=$(echo "${UPPER_REGION_FLOWS}" | jq -r --arg name "${FLOW_NAME}" '.[] | select(.name == $name) | .id')

      if [ -n "${UPPER_REGION_FLOW_ID}" ]; then
        # Update existing flow
        UPDATE_PAYLOAD=$(echo "${FLOW_DEF}" | jq '{name, actions}')
        RESULT=$(curl -s --request PATCH \
          --url "https://${UPPER_REGION_AUTH0_DOMAIN}/api/v2/flows/${UPPER_REGION_FLOW_ID}" \
          --header "authorization: Bearer ${UPPER_REGION_TOKEN}" \
          --header 'content-type: application/json' \
          --data "${UPDATE_PAYLOAD}")
        sleep 2  # Rate limit protection
        if echo "${RESULT}" | jq -e '.id' >/dev/null 2>&1; then
          echo "  ✓ Updated flow '${FLOW_NAME}' in Upper Region"
          echo "$(cat "${FLOW_MAP_FILE}")" | jq --arg sid "${FLOW_ID}" --arg did "${UPPER_REGION_FLOW_ID}" '. + {($sid): $did}' > "${FLOW_MAP_FILE}"
        else
          echo "  ⚠ Failed to update flow '${FLOW_NAME}': $(echo "${RESULT}" | jq -r '.message // .error // "unknown"')"
        fi
      else
        # Create new flow
        CREATE_PAYLOAD=$(echo "${FLOW_DEF}" | jq '{name, actions}')
        RESULT=$(curl -s --request POST \
          --url "https://${UPPER_REGION_AUTH0_DOMAIN}/api/v2/flows" \
          --header "authorization: Bearer ${UPPER_REGION_TOKEN}" \
          --header 'content-type: application/json' \
          --data "${CREATE_PAYLOAD}")
        sleep 2  # Rate limit protection
        NEW_FLOW_ID=$(echo "${RESULT}" | jq -r '.id // empty')
        if [ -n "${NEW_FLOW_ID}" ]; then
          echo "  ✓ Created flow '${FLOW_NAME}' in Upper Region (id: ${NEW_FLOW_ID})"
          echo "$(cat "${FLOW_MAP_FILE}")" | jq --arg sid "${FLOW_ID}" --arg did "${NEW_FLOW_ID}" '. + {($sid): $did}' > "${FLOW_MAP_FILE}"
        else
          echo "  ⚠ Failed to create flow '${FLOW_NAME}': $(echo "${RESULT}" | jq -r '.message // .error // "unknown"')"
        fi
      fi
    done || true
    log_ok "Flows synced."
  else
    log_info "No flows found in Lower Region."
  fi
else
  log_error "Failed to fetch flows (HTTP ${FLOWS_HTTP}). Ensure M2M app has 'read:flows' scope."
  log_info "Response: ${FLOWS_BODY:0:300}"
fi

# --- Forms ---
log_info "Syncing Forms..."
FORMS_RAW=$(curl -s -w "\nHTTP_STATUS:%{http_code}" --request GET \
  --url "https://${LOWER_REGION_AUTH0_DOMAIN}/api/v2/forms" \
  --header "authorization: Bearer ${LOWER_REGION_TOKEN}")

FORMS_HTTP=$(echo "${FORMS_RAW}" | grep "HTTP_STATUS:" | sed 's/HTTP_STATUS://')
FORMS_BODY=$(echo "${FORMS_RAW}" | sed '/HTTP_STATUS:/d')

if [ "${FORMS_HTTP}" = "200" ]; then
  FORMS=$(echo "${FORMS_BODY}" | jq -c 'if type == "array" then . elif .forms then .forms else [] end' 2>/dev/null || echo "[]")
  FORM_COUNT=$(echo "${FORMS}" | jq 'length')
  log_info "Forms found in Lower Region: ${FORM_COUNT}"

  if [ "${FORM_COUNT}" -gt 0 ]; then
    # Get existing forms in Upper Region
    UPPER_REGION_FORMS_RAW=$(curl -s --request GET \
      --url "https://${UPPER_REGION_AUTH0_DOMAIN}/api/v2/forms" \
      --header "authorization: Bearer ${UPPER_REGION_TOKEN}")
    UPPER_REGION_FORMS=$(echo "${UPPER_REGION_FORMS_RAW}" | jq -c 'if type == "array" then . elif .forms then .forms else [] end' 2>/dev/null || echo "[]")

    echo "${FORMS}" | jq -c '.[]' 2>/dev/null | while read -r form || [ -n "${form}" ]; do
      FORM_ID=$(echo "${form}" | jq -r '.id' 2>/dev/null || echo "")
      FORM_NAME=$(echo "${form}" | jq -r '.name' 2>/dev/null || echo "unknown")

      if [ -z "${FORM_ID}" ] || [ "${FORM_ID}" = "null" ]; then
        continue
      fi

      log_info "Processing form: '${FORM_NAME}' (id: ${FORM_ID})"
      sleep 1  # Rate limit protection

      # Get full form definition
      FORM_DETAIL=$(curl -s --request GET \
        --url "https://${LOWER_REGION_AUTH0_DOMAIN}/api/v2/forms/${FORM_ID}" \
        --header "authorization: Bearer ${LOWER_REGION_TOKEN}")

      # Validate form detail was retrieved
      if ! echo "${FORM_DETAIL}" | jq -e '.name' >/dev/null 2>&1; then
        echo "  ⚠ Failed to fetch form detail for '${FORM_NAME}', skipping"
        continue
      fi

      # Clean up non-transferable fields
      FORM_DEF=$(echo "${FORM_DETAIL}" | jq 'del(.id, .created_at, .updated_at, .links)')

      # Remap flow IDs in form (forms can embed flow references)
      FLOW_MAP=$(cat "${FLOW_MAP_FILE}")
      for SB_FLOW_ID in $(echo "${FLOW_MAP}" | jq -r 'keys[]'); do
        UPPER_REGION_FLOW_ID=$(echo "${FLOW_MAP}" | jq -r --arg k "${SB_FLOW_ID}" '.[$k]')
        FORM_DEF=$(echo "${FORM_DEF}" | sed "s/${SB_FLOW_ID}/${UPPER_REGION_FLOW_ID}/g")
      done

      # Also remap vault connection IDs in forms
      VAULT_MAP=$(cat "${VAULT_MAP_FILE}")
      for SB_VC_ID in $(echo "${VAULT_MAP}" | jq -r 'keys[]'); do
        UPPER_REGION_VC_ID=$(echo "${VAULT_MAP}" | jq -r --arg k "${SB_VC_ID}" '.[$k]')
        FORM_DEF=$(echo "${FORM_DEF}" | sed "s/${SB_VC_ID}/${UPPER_REGION_VC_ID}/g")
      done

      # Check if form exists in Upper Region by name
      UPPER_REGION_FORM_ID=$(echo "${UPPER_REGION_FORMS}" | jq -r --arg name "${FORM_NAME}" '.[] | select(.name == $name) | .id')

      if [ -n "${UPPER_REGION_FORM_ID}" ]; then
        # Update existing form
        UPDATE_PAYLOAD=$(echo "${FORM_DEF}" | jq 'del(.id)')
        RESULT=$(curl -s --request PATCH \
          --url "https://${UPPER_REGION_AUTH0_DOMAIN}/api/v2/forms/${UPPER_REGION_FORM_ID}" \
          --header "authorization: Bearer ${UPPER_REGION_TOKEN}" \
          --header 'content-type: application/json' \
          --data "${UPDATE_PAYLOAD}")
        sleep 2  # Rate limit protection
        if echo "${RESULT}" | jq -e '.id' >/dev/null 2>&1; then
          echo "  ✓ Updated form '${FORM_NAME}' in Upper Region"
        else
          echo "  ⚠ Failed to update form '${FORM_NAME}': $(echo "${RESULT}" | jq -r '.message // .error // "unknown"')"
        fi
      else
        # Create new form
        RESULT=$(curl -s --request POST \
          --url "https://${UPPER_REGION_AUTH0_DOMAIN}/api/v2/forms" \
          --header "authorization: Bearer ${UPPER_REGION_TOKEN}" \
          --header 'content-type: application/json' \
          --data "${FORM_DEF}")
        sleep 2  # Rate limit protection
        if echo "${RESULT}" | jq -e '.id' >/dev/null 2>&1; then
          echo "  ✓ Created form '${FORM_NAME}' in Upper Region"
        else
          echo "  ⚠ Failed to create form '${FORM_NAME}': $(echo "${RESULT}" | jq -r '.message // .error // "unknown"')"
        fi
      fi
    done || true
    log_ok "Forms synced."
  else
    log_info "No forms found in Lower Region."
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
echo " Source: ${LOWER_REGION_AUTH0_DOMAIN} (Lower Region)"
echo " Destination: ${UPPER_REGION_AUTH0_DOMAIN} (Upper Region)"
echo " Delete mode: ${AUTH0_ALLOW_DELETE}"
echo ""
echo " Deploy CLI imported: pages, clients, actions, connections, roles,"
echo "   resource servers, email, branding, prompts, triggers"
echo " API synced: guardian, attack protection, log streams, organizations,"
echo "   flows, forms, vault connections"
echo ""
echo " NOTE: Vault connection SECRETS are never exported by Auth0."
echo " If new vault connections were created, configure their secrets"
echo " manually in the Upper Region tenant (one-time setup)."
echo "═══════════════════════════════════════════════════════════════════════════"

# Exit with failure if Deploy CLI import had errors
if [ "${IMPORT_EXIT_CODE}" -ne 0 ]; then
  log_error "Pipeline completed with warnings — Deploy CLI import had errors (exit code ${IMPORT_EXIT_CODE})."
  log_info "API-synced resources (guardian, attack protection, organizations, flows, forms) were still applied."
  exit 1
fi
