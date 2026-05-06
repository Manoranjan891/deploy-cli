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

a0deploy import "${IMPORT_ARGS[@]}"

log_ok "Import completed successfully into Dev (${DEV_AUTH0_DOMAIN})."

# -----------------------------------------------------------------------------
# Summary
# -----------------------------------------------------------------------------
echo ""
echo "═══════════════════════════════════════════════════════════════════════════"
echo " Auth0 Promotion Complete"
echo " Source:      ${SANDBOX_AUTH0_DOMAIN} (Sandbox)"
echo " Destination: ${DEV_AUTH0_DOMAIN} (Dev)"
echo " Delete mode: ${AUTH0_ALLOW_DELETE}"
echo "═══════════════════════════════════════════════════════════════════════════"
