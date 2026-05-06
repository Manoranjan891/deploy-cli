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
# Step 1: Export from Sandbox
# -----------------------------------------------------------------------------
log_info "Exporting Auth0 config from Sandbox (${SANDBOX_AUTH0_DOMAIN})..."

# Clean previous export to avoid stale data
rm -rf "${EXPORT_DIR}"
mkdir -p "${EXPORT_DIR}"

a0deploy export \
  --format yaml \
  --output_folder "${EXPORT_DIR}" \
  --config_file /dev/stdin <<EOF
{
  "AUTH0_DOMAIN": "${SANDBOX_AUTH0_DOMAIN}",
  "AUTH0_CLIENT_ID": "${SANDBOX_AUTH0_CLIENT_ID}",
  "AUTH0_CLIENT_SECRET": "${SANDBOX_AUTH0_CLIENT_SECRET}"
}
EOF

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

IMPORT_ARGS=(
  --format yaml
  --input_file "${EXPORT_DIR}"
  --config_file /dev/stdin
)

# Only add --env AUTH0_ALLOW_DELETE if explicitly enabled
if [ "${AUTH0_ALLOW_DELETE}" = "true" ]; then
  log_info "WARNING: Delete mode is ENABLED. Resources not in export will be removed from Dev."
  IMPORT_ARGS+=(--env "AUTH0_ALLOW_DELETE=true")
fi

a0deploy import "${IMPORT_ARGS[@]}" <<EOF
{
  "AUTH0_DOMAIN": "${DEV_AUTH0_DOMAIN}",
  "AUTH0_CLIENT_ID": "${DEV_AUTH0_CLIENT_ID}",
  "AUTH0_CLIENT_SECRET": "${DEV_AUTH0_CLIENT_SECRET}",
  "AUTH0_ALLOW_DELETE": ${AUTH0_ALLOW_DELETE}
}
EOF

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
