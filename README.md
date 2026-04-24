# watermilldigital/ops

Shared GitHub Actions reusable workflows for watermilldigital's WordPress
sites hosted on Cloudways.

## What's here

| Path | Purpose |
|---|---|
| `.github/workflows/wp-vulnerability-check.yml` | Weekly reusable workflow: reads Cloudways' Patchstack-powered vulnerability scanner, auto-bumps Composer-managed plugins via PR, files a GitHub issue for anything un-auto-fixable (WP core, themes, manually-installed plugins, private-mirror packages awaiting upstream) |
| `scripts/fetch-vulns.sh` | OAuths to Cloudways API v2, fetches vulnerability scan, normalises to a flat JSON schema |
| `scripts/bump-plugins.sh` | Matches vulns to Composer packages, runs `composer update` / `composer require`, per-iteration snapshot/restore on failure |
| `scripts/open-security-pr.sh` | Branch / commit / push / open or update rollup PR, closes stale `security/weekly-*` PRs |
| `scripts/track-skipped-issue.sh` | Opens / updates / closes a single GitHub issue for vulns we can't auto-fix |

## Caller setup

Drop this into each site-repo's `.github/workflows/vulnerability-check.yml`:

```yaml
name: Weekly vulnerability check

on:
  schedule: [{ cron: '0 8 * * 1' }]   # Mon 08:00 UTC
  workflow_dispatch:
    inputs:
      refresh_scan:
        description: "Force Cloudways to re-poll Patchstack before reading"
        type: boolean
        default: false

concurrency:
  group: vulnerability-check
  cancel-in-progress: false

jobs:
  check:
    uses: watermilldigital/ops/.github/workflows/wp-vulnerability-check.yml@v1
    secrets: inherit
    with:
      base_path: ${{ vars.BASE_PATH }}
      refresh_scan: ${{ inputs.refresh_scan || false }}
```

That's the whole caller file.

### Required in the caller repo

**Secrets** (repo-level, or org-level scoped to the repo):

| Name | Where from |
|---|---|
| `CLOUDWAYS_EMAIL` | Cloudways account email |
| `CLOUDWAYS_API_KEY` | Cloudways dashboard → **Account → API** |
| `SSH_PRIVATE_KEY` | Base64-encoded SSH deploy key with access to any private Composer repos (e.g. `watermilldigital/*` on Bitbucket) |

**Variable** — must be **repo-level**, not environment-scoped:

| Name | Example value |
|---|---|
| `BASE_PATH` | `/home/1526500.cloudwaysapps.com/bfumkbzcue/public_html/current` — the Cloudways app path; we parse the server ID out of the numeric prefix and look up the app ID from Cloudways API |

**Why repo-level:** the caller stub reads `${{ vars.BASE_PATH }}` in the
caller's own context, where the `with:` block is evaluated *before* the
reusable workflow starts and applies its `environment:` scope. Env-scoped
vars are invisible at that point. Put BASE_PATH at **Settings → Secrets
and variables → Actions → Variables** (repo-level).

**Environment** (default `production`):

The reusable workflow declares `environment: ${{ inputs.environment }}`
(default `production`). The environment must exist in the caller repo
even if it's empty — GitHub rejects workflows that reference a non-existent
environment. Create it once at **Settings → Environments → New environment**.

This environment scope applies to SECRETS (via `secrets: inherit`), so
env-scoped `SSH_PRIVATE_KEY` or `CLOUDWAYS_*` will flow through correctly
when the caller's environment name matches the `environment` input. For a
different environment name, pass it as `environment: <name>`.

**Workflow permissions** — caller repo **must** allow write-mode default token:

Go to **Settings → Actions → General → Workflow permissions** and ensure
"Read and write permissions" is selected (or the narrower "Read repository
contents and packages permissions" will cap the callee's `contents: write`
/ `pull-requests: write` / `issues: write` requests, causing silent 403s
on push / PR create / issue create). The checkbox "Allow GitHub Actions
to create and approve pull requests" must also be ticked.

### Optional inputs

| Input | Default | Use case |
|---|---|---|
| `assignee` | `${{ github.repository_owner }}` | Someone other than the repo owner should own PRs + tracking issues |
| `php_version` | `8.3` | Project runs on a different PHP |
| `base_branch` | `main` | PR targets a branch other than `main` (e.g. `develop`) |
| `environment` | `production` | Different environment name |
| `refresh_scan` | `false` | On manual triggers, force Cloudways to re-poll Patchstack first |

## Versioning

Callers should pin to a major tag:

```yaml
uses: watermilldigital/ops/.github/workflows/wp-vulnerability-check.yml@v1
```

- `@v1` — latest v1.x.y. Auto-pulls patch + minor updates.
- `@v1.2.3` — exact version. Pin this in high-stakes repos.
- `@<sha>` — full commit SHA. Most paranoid; never unpin.

Tag convention: `v<major>.<minor>.<patch>` following semver. Breaking
changes to inputs or secret names bump major.

## Flow in one picture

```
cron / manual
     │
     ▼
┌─────────────────────────────────────────────────────┐
│ fetch-vulns.sh                                      │
│   OAuth → GET /app/vulnerabilities/{id}             │
│   normalise Cloudways/Patchstack response           │
│   → vulns.json                                      │
└─────────────────────────────────────────────────────┘
     │
     ▼
┌─────────────────────────────────────────────────────┐
│ bump-plugins.sh                                     │
│   match slug → composer package                     │
│   composer update (with per-iteration snapshot)     │
│   → vuln-report.json { updates: [...], skipped: [] }│
└─────────────────────────────────────────────────────┘
     │
     ├───────────────────────┬─────────────────────────┐
     ▼                       ▼                         ▼
┌──────────────┐    ┌──────────────────┐     ┌────────────────┐
│ open-        │    │ track-skipped-   │     │ (step logs)    │
│ security-pr  │    │ issue            │     │                │
│   PR per wk  │    │   1 issue, auto- │     │                │
│   assigns to │    │   closes clean   │     │                │
│   owner      │    │   assigns to own │     │                │
└──────────────┘    └──────────────────┘     └────────────────┘
```

## Local testing

Each script is independently runnable. Set env vars, then:

```bash
export CW_EMAIL=...
export CW_API_KEY=...
export BASE_PATH=...
# resolve server/app IDs manually (or copy the block from the workflow)
export CW_SERVER_ID=...
export CW_APP_ID=...

scripts/fetch-vulns.sh > vulns.json
scripts/bump-plugins.sh vulns.json
# inspect .github/vuln-report.json
# (skip open-security-pr.sh locally — it pushes branches and opens PRs)
ASSIGNEE="" scripts/track-skipped-issue.sh   # empty = no assignment
```

## Contributing

PRs welcome. Run `bash -n scripts/*.sh` before committing. Major changes
should bump the version tag.
