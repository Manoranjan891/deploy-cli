# Auth0 Deploy CLI — Sandbox → Dev Promotion

Automated promotion of Auth0 configuration from Sandbox to Dev using [Auth0 Deploy CLI](https://github.com/auth0/auth0-deploy-cli).

---

## Repo Structure

```
deploy-cli/
├── .github/
│   └── workflows/
│       └── auth0-sandbox-to-dev.yml    # GitHub Actions workflow
├── auth0/
│   ├── exported/                        # Generated at runtime (git-ignored)
│   │   ├── tenant.yaml
│   │   ├── clients/
│   │   ├── rules/
│   │   ├── ...
│   └── README.md                        # This file
├── scripts/
│   └── promote-auth0.sh                 # Export/import shell script
├── .gitignore
└── README.md (optional root readme)
```

---

## Prerequisites

| Requirement | Details |
|-------------|---------|
| **Auth0 M2M Application (Sandbox)** | Must have `read:*` scopes (or at minimum scopes for every resource you want to export). Grant the Auth0 Management API. |
| **Auth0 M2M Application (Dev)** | Must have `create:*`, `update:*`, `read:*` scopes. Grant the Auth0 Management API. |
| **Node.js** | v20+ |
| **auth0-deploy-cli** | v7+ (`npm install -g auth0-deploy-cli`) |

---

## GitHub Secrets

Configure these in **Settings → Secrets and variables → Actions**:

| Secret Name | Description |
|-------------|-------------|
| `SANDBOX_AUTH0_DOMAIN` | Sandbox tenant domain (e.g., `my-sandbox.us.auth0.com`) |
| `SANDBOX_AUTH0_CLIENT_ID` | Sandbox M2M app Client ID |
| `SANDBOX_AUTH0_CLIENT_SECRET` | Sandbox M2M app Client Secret |
| `DEV_AUTH0_DOMAIN` | Dev tenant domain (e.g., `my-dev.us.auth0.com`) |
| `DEV_AUTH0_CLIENT_ID` | Dev M2M app Client ID |
| `DEV_AUTH0_CLIENT_SECRET` | Dev M2M app Client Secret |

---

## How It Works

1. **Trigger** — Push to `main` (if files under `auth0/` or `.github/workflows/` changed), or manual dispatch.
2. **Export** — Runs `a0deploy export` against Sandbox, producing YAML files in `auth0/exported/`.
3. **Validate** — Confirms `tenant.yaml` was created.
4. **Import** — Runs `a0deploy import` against Dev using the exported YAML.
5. **Artifact** — Uploads the exported config as a GitHub Actions artifact (retained 14 days).

---

## Local Testing

Before pushing to GitHub, test the script locally:

```bash
# 1. Install Auth0 Deploy CLI
npm install -g auth0-deploy-cli@7

# 2. Set environment variables (use a .env file or export directly)
export SANDBOX_AUTH0_DOMAIN="my-sandbox.us.auth0.com"
export SANDBOX_AUTH0_CLIENT_ID="xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"
export SANDBOX_AUTH0_CLIENT_SECRET="xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"
export DEV_AUTH0_DOMAIN="my-dev.us.auth0.com"
export DEV_AUTH0_CLIENT_ID="xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"
export DEV_AUTH0_CLIENT_SECRET="xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"

# 3. Run the script
chmod +x scripts/promote-auth0.sh
./scripts/promote-auth0.sh

# 4. Inspect the exported config
ls -la auth0/exported/
cat auth0/exported/tenant.yaml
```

### Dry-run (export only, no import)

To test just the export without affecting Dev, comment out the import section in the script or run:

```bash
a0deploy export \
  --format yaml \
  --output_folder auth0/exported \
  --config_file <(echo '{
    "AUTH0_DOMAIN": "'"${SANDBOX_AUTH0_DOMAIN}"'",
    "AUTH0_CLIENT_ID": "'"${SANDBOX_AUTH0_CLIENT_ID}"'",
    "AUTH0_CLIENT_SECRET": "'"${SANDBOX_AUTH0_CLIENT_SECRET}"'"
  }')
```

---

## Safety Notes

| Concern | Mitigation |
|---------|-----------|
| **Delete mode** | Disabled by default. Resources in Dev that aren't in the export will NOT be removed. |
| **Tenant-specific values** | Callback URLs, allowed origins, email from addresses, and custom domains may contain Sandbox-specific values. Review exported YAML before promoting. |
| **Exclusions** | Use `AUTH0_EXCLUDED_CLIENTS`, `AUTH0_EXCLUDED_RULES`, etc. in the config to skip resources that shouldn't transfer between tenants. |
| **Secrets in config** | Never commit client secrets. The script reads them from environment variables only. |

---

## Common Resources to Review Before Promotion

These often contain environment-specific values:

- **Applications** — Callback URLs, Allowed Logout URLs, Allowed Web Origins
- **Email Templates** — From address, redirect URLs
- **Connections** — Social provider client IDs/secrets (these differ per tenant)
- **Custom Domains** — Tenant-specific CNAME
- **Log Streams** — Datadog/Splunk/AWS endpoints
- **Attack Protection** — Thresholds may differ between environments

---

## Troubleshooting

| Issue | Fix |
|-------|-----|
| `tenant.yaml not found` | Check that the Sandbox M2M app has the correct scopes and is authorized for the Management API. |
| `401 Unauthorized` | Verify domain, client ID, and client secret are correct for the target tenant. |
| `403 Forbidden` | The M2M app is missing required scopes — grant all `read:*` (export) or `create:*`/`update:*` (import) scopes. |
| Import partially fails | Some resources may have dependencies. Check the Deploy CLI output for specific error messages. |

---

## Assumptions

1. Both tenants are on the same Auth0 region (if not, adjust domains accordingly).
2. The M2M apps in both tenants are pre-configured with appropriate Management API scopes.
3. YAML format is used (Deploy CLI also supports directory format — this workflow uses YAML for simplicity).
4. The `auth0/exported/` directory is git-ignored to avoid committing runtime data.
