# Architecture: Auth0 Lower Region → Upper Region Promotion Pipeline

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
│  STEP 1: EXPORT from Lower Region                                                │
│                                                                             │
│  ┌──────────────┐     a0deploy export      ┌─────────────────────────┐     │
│  │   Lower Region    │ ──────────────────────── │  auth0/exported/        │     │
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
│  • Replace Lower Region API audience URL → Upper Region API audience URL                  │
│  • Strip incompatible tenant flags                                          │
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘
                                    │
                                    ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│  STEP 3: IMPORT into Upper Region (Deploy CLI)                                       │
│                                                                             │
│  ┌─────────────────────────┐    a0deploy import    ┌──────────────┐        │
│  │  auth0/exported/        │ ─────────────────── │    Upper Region       │        │
│  │  tenant.yaml            │  (Auth0 Deploy CLI)  │    Tenant    │        │
│  └─────────────────────────┘                      │              │        │
│                                                   │  Creates/    │        │
│  Resources imported:                              │  Updates:    │        │
│  ✅ Applications (Clients)                        │  - Apps      │        │
│  ✅ Actions (created + deployed)                  │  - Actions   │        │
│  ✅ Resource Servers (APIs)                       │  - APIs      │        │
│  ✅ Connections                                   │  - Roles     │        │
│  ✅ Client Grants                                 │  - etc.      │        │
│  ✅ Databases                                     └──────────────┘        │
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
│  │    Lower Region     │ ──────────> │   Transform    │ ──────────────>  Upper Region    │
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
│       └── auth0-lower-region-to-upper-region.yml   ← GitHub Actions workflow definition
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
│  LOWER_REGION_AUTH0_DOMAIN           │  Lower Region tenant domain        │
│  LOWER_REGION_AUTH0_CLIENT_ID        │  Lower Region M2M app Client ID    │
│  LOWER_REGION_AUTH0_CLIENT_SECRET    │  Lower Region M2M app Secret       │
├─────────────────────────────────┼───────────────────────────────┤
│  UPPER_REGION_AUTH0_DOMAIN               │  Upper Region tenant domain            │
│  UPPER_REGION_AUTH0_CLIENT_ID            │  Upper Region M2M app Client ID        │
│  UPPER_REGION_AUTH0_CLIENT_SECRET        │  Upper Region M2M app Secret           │
└─────────────────────────────────┴───────────────────────────────┘


## Auth0 M2M App Permissions

┌───────────────────────────────────────────────────────────────────┐
│  Lower Region M2M App (read-only)                                      │
│  Scopes: read:clients, read:connections, read:roles,              │
│          read:actions, read:organizations, read:resource_servers,  │
│          read:client_grants, read:tenant_settings, ...            │
├───────────────────────────────────────────────────────────────────┤
│  Upper Region M2M App (read + write)                                       │
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
│  Users                  │  Runtime data, not configuration              │
│  Log Stream Sinks       │  Endpoints differ per environment             │
└─────────────────────────┴───────────────────────────────────────────────┘


## Trigger Methods

1. AUTOMATIC: Push to main branch (changes in auth0/, scripts/, .github/workflows/)
2. MANUAL: GitHub Actions UI → "Run workflow"
3. API: POST to GitHub Actions dispatch endpoint
