# Architecture: Auth0 Sandbox → Dev Promotion Pipeline

## High-Level Flow

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                          GITHUB ACTIONS PIPELINE                             │
│                                                                             │
│  Trigger: push to main (auth0/**, scripts/**, .github/workflows/**)        │
│           OR manual workflow_dispatch                                        │
└─────────────────────────────────────────────────────────────────────────────┘
                                    │
                                    ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│  STEP 1: EXPORT FROM SANDBOX                                                │
│                                                                             │
│  ┌──────────────┐     a0deploy export      ┌─────────────────────────┐     │
│  │   Sandbox    │ ──────────────────────── │  auth0/exported/        │     │
│  │   Tenant     │   (Auth0 Deploy CLI)     │  ├── tenant.yaml        │     │
│  │              │                          │  ├── actions/            │     │
│  │  Domain:     │   Uses M2M credentials   │  ├── clients/           │     │
│  │  Secrets:    │   from GitHub Secrets     │  ├── connections/       │     │
│  │  - CLIENT_ID │                          │  ├── databases/          │     │
│  │  - SECRET    │                          │  ├── emailTemplates/     │     │
│  └──────────────┘                          │  ├── pages/             │     │
│                                            │  ├── roles/             │     │
│                                            │  └── ...                │     │
│                                            └─────────────────────────┘     │
└─────────────────────────────────────────────────────────────────────────────┘
                                    │
                                    ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│  STEP 2: TRANSFORM                                                          │
│                                                                             │
│  • Replace Sandbox API audience URL → Dev API audience URL                  │
│  • Remove Contoso-Users database (incompatible)                             │
│  • Strip incompatible tenant flags                                          │
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘
                                    │
                                    ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│  STEP 3: IMPORT INTO DEV (Deploy CLI)                                       │
│                                                                             │
│  ┌─────────────────────────┐    a0deploy import    ┌──────────────┐        │
│  │  auth0/exported/        │ ─────────────────── │    Dev       │        │
│  │  tenant.yaml            │  (Auth0 Deploy CLI)  │    Tenant    │        │
│  └─────────────────────────┘                      │              │        │
│                                                   │  Creates/    │        │
│  Resources imported:                              │  Updates:    │        │
│  ✅ Applications (Clients)                        │  - Apps      │        │
│  ✅ Actions (created + deployed)                  │  - Actions   │        │
│  ✅ Resource Servers (APIs)                       │  - APIs      │        │
│  ✅ Connections                                   │  - Roles     │        │
│  ✅ Client Grants                                 │  - etc.      │        │
│  ✅ Databases (except Contoso-Users)              └──────────────┘        │
│  ✅ Pages (login, password reset)                                          │
│  ✅ Email Provider + Templates                                             │
│  ✅ Roles                                                                  │
│  ✅ Triggers                                                               │
│  ✅ Branding + Themes                                                      │
│  ✅ Prompts                                                                │
│  ✅ Custom Domains                                                         │
│  ✅ Risk Assessment                                                        │
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘
                                    │
                                    ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│  STEP 4: API SYNC (Direct Management API calls)                             │
│                                                                             │
│  Bypasses Deploy CLI's broken 'paginate' parameter                          │
│                                                                             │
│  ┌────────────────┐  curl GET   ┌────────────────┐  curl PUT/POST          │
│  │    Sandbox     │ ──────────> │   Transform    │ ──────────────>  Dev    │
│  │    API v2      │             │   & Compare    │                          │
│  └────────────────┘             └────────────────┘                          │
│                                                                             │
│  Resources synced:                                                          │
│  ✅ Guardian Factors (enabled/disabled per factor)                          │
│  ✅ Attack Protection (brute force, breached password, suspicious IP)       │
│  ✅ Organizations (create if missing)                                       │
│  ⚠️  Log Streams (detected, not auto-created — env-specific sinks)          │
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘
                                    │
                                    ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│  STEP 5: ARTIFACT UPLOAD                                                    │
│                                                                             │
│  • Exported config uploaded as GitHub Actions artifact                       │
│  • Retained for 14 days (audit/debugging)                                   │
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘


## Repository Structure

deploy-cli/
├── .github/
│   └── workflows/
│       └── auth0-sandbox-to-dev.yml   ← GitHub Actions workflow definition
├── auth0/
│   ├── exported/                      ← Generated at runtime (git-ignored)
│   └── README.md                      ← Setup documentation
├── scripts/
│   └── promote-auth0.sh              ← Main promotion script
├── .gitignore
├── ARCHITECTURE.md                    ← This file
└── README.md


## Secrets Configuration

┌─────────────────────────────────────────────────────────────────┐
│              GitHub Repository Secrets                           │
├─────────────────────────────────┬───────────────────────────────┤
│  SANDBOX_AUTH0_DOMAIN           │  Sandbox tenant domain        │
│  SANDBOX_AUTH0_CLIENT_ID        │  Sandbox M2M app Client ID    │
│  SANDBOX_AUTH0_CLIENT_SECRET    │  Sandbox M2M app Secret       │
├─────────────────────────────────┼───────────────────────────────┤
│  DEV_AUTH0_DOMAIN               │  Dev tenant domain            │
│  DEV_AUTH0_CLIENT_ID            │  Dev M2M app Client ID        │
│  DEV_AUTH0_CLIENT_SECRET        │  Dev M2M app Secret           │
└─────────────────────────────────┴───────────────────────────────┘


## Auth0 M2M App Permissions

┌───────────────────────────────────────────────────────────────────┐
│  SANDBOX M2M App (read-only)                                      │
│  Scopes: read:clients, read:connections, read:roles,              │
│          read:actions, read:organizations, read:resource_servers,  │
│          read:client_grants, read:tenant_settings, ...            │
├───────────────────────────────────────────────────────────────────┤
│  DEV M2M App (read + write)                                       │
│  Scopes: read:*, create:*, update:*                               │
│          (All Management API scopes recommended)                  │
└───────────────────────────────────────────────────────────────────┘


## What Is NOT Automated (Manual One-Time Setup)

┌─────────────────────────┬───────────────────────────────────────────────┐
│  Resource               │  Reason                                       │
├─────────────────────────┼───────────────────────────────────────────────┤
│  Flow Vault Connections │  Hold secrets Auth0 never exports             │
│  Flows                  │  Depend on vault connections                  │
│  Forms                  │  Depend on flows                              │
│  Contoso-Users DB       │  Incompatible with Custom Login Page in Dev   │
│  Users                  │  Runtime data, not configuration              │
│  Log Stream Sinks       │  Endpoints differ per environment             │
└─────────────────────────┴───────────────────────────────────────────────┘


## Trigger Methods

1. AUTOMATIC: Push to main branch (changes in auth0/, scripts/, .github/workflows/)
2. MANUAL: GitHub Actions UI → "Run workflow"
3. API: POST to GitHub Actions dispatch endpoint
