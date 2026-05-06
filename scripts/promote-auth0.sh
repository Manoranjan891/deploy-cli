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

# NOTE: Auth0 Deploy CLI delete mode is DISABLED by default.
# Setting AUTH0_ALLOW_DELETE=true would remove resources in Dev that don't exist
# in the exported config. Only enable this if you fully understand the impact.
AUTH0_ALLOW_DELETE="${AUTH0_ALLOW_DELETE:-false}"

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
  rm -f "${SANDBOX_CONFIG:-}" "${DEV_CONFIG:-}"
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
# (Strips "strategy" attributes that conflict with custom login page in Dev)
if [ -f "${EXPORT_DIR}/tenant.yaml" ]; then
  # Remove the requires_username flag if set (causes issues with custom DB)
  sed -i 's/requires_username: true/requires_username: false/g' "${EXPORT_DIR}/tenant.yaml"
fi

# Remove Contoso-Users database (incompatible with Custom Login Page in Dev)
if [ -d "${EXPORT_DIR}/databases/Contoso-Users" ]; then
  log_info "Removing incompatible database folder: Contoso-Users"
  rm -rf "${EXPORT_DIR}/databases/Contoso-Users"
fi

# Remove Contoso-Users from tenant.yaml (multi-line YAML block)
# Uses awk to skip the entire block starting with "- name: Contoso-Users" until the next "- name:"
if grep -q "Contoso-Users" "${EXPORT_DIR}/tenant.yaml"; then
  log_info "Removing Contoso-Users block from tenant.yaml"
  awk '
    /^[[:space:]]*- name: Contoso-Users/ { skip=1; next }
    skip && /^[[:space:]]*- name:/ { skip=0 }
    !skip { print }
  ' "${EXPORT_DIR}/tenant.yaml" > "${EXPORT_DIR}/tenant.yaml.tmp"
  mv "${EXPORT_DIR}/tenant.yaml.tmp" "${EXPORT_DIR}/tenant.yaml"
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
ORGS_RAW=$(curl -s --request GET \
  --url "https://${SANDBOX_AUTH0_DOMAIN}/api/v2/organizations?per_page=100" \
  --header "authorization: Bearer ${SANDBOX_TOKEN}")

# Auth0 API may return array directly or wrapped — handle both
ORGS=$(echo "${ORGS_RAW}" | jq -c 'if type == "array" then . elif .organizations then .organizations else [] end' 2>/dev/null || echo "[]")

log_info "Organizations found in Sandbox: $(echo "${ORGS}" | jq 'length')"

if echo "${ORGS}" | jq -e '.[0]' >/dev/null 2>&1; then
  echo "${ORGS}" | jq -c '.[]' | while read -r org; do
    ORG_NAME=$(echo "${org}" | jq -r '.name')
    ORG_DISPLAY=$(echo "${org}" | jq -r '.display_name')
    # Check if org exists in Dev
    DEV_ORG=$(curl -s --request GET \
      --url "https://${DEV_AUTH0_DOMAIN}/api/v2/organizations/name/${ORG_NAME}" \
      --header "authorization: Bearer ${DEV_TOKEN}")
    if echo "${DEV_ORG}" | jq -e '.id' >/dev/null 2>&1; then
      echo "  ⟳ Organization '${ORG_NAME}' already exists in Dev"
    else
      # Create org in Dev
      CREATE_PAYLOAD=$(echo "${org}" | jq '{name, display_name, branding, metadata}')
      RESULT=$(curl -s --request POST \
        --url "https://${DEV_AUTH0_DOMAIN}/api/v2/organizations" \
        --header "authorization: Bearer ${DEV_TOKEN}" \
        --header 'content-type: application/json' \
        --data "${CREATE_PAYLOAD}")
      if echo "${RESULT}" | jq -e '.id' >/dev/null 2>&1; then
        echo "  ✓ Created organization '${ORG_NAME}' (display: ${ORG_DISPLAY})"
      else
        echo "  ⚠ Failed to create organization '${ORG_NAME}': $(echo "${RESULT}" | jq -r '.message // .error // "unknown error"')"
      fi
    fi
  done
  log_ok "Organizations synced."
else
  log_info "No organizations found in Sandbox (or empty list)."
fi

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
echo " API synced: guardian, attack protection, log streams, organizations"
echo " Manual setup needed: flows, forms, flow vault connections"
echo "═══════════════════════════════════════════════════════════════════════════"

# Exit with failure if Deploy CLI import had errors
if [ "${IMPORT_EXIT_CODE}" -ne 0 ]; then
  log_error "Pipeline completed with warnings — Deploy CLI import had errors (exit code ${IMPORT_EXIT_CODE})."
  log_info "API-synced resources (guardian, attack protection, organizations) were still applied."
  exit 1
fi
