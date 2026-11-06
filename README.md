# SEO Machine

SEO Machine is a lightweight SEO audit workspace built for Cloudflare Pages and Workers.

## Current architecture

- **Pages:** serves the static dashboard from `index.html`.
- **Worker API:** `worker/index.js`, deployed as `seo-machine-api`.
- **KV:** `AUDITS` stores audit reports, projects, and monitoring history.
- **Durable Objects:** `AUTH` uses the SQLite-backed `AuthDirectory` class for accounts, sessions, and activity.
- **Cron:** `*/15 * * * *` checks due website-monitoring projects.

**A D1 database is not required by the current implementation.** The `schema.sql` file is a legacy schema reference and is not used by the current Worker. Do not create or bind a new D1 database just to deploy this version.

## Cloudflare bindings

The existing `wrangler.toml` expects these resources:

| Binding | Type | Purpose |
| --- | --- | --- |
| `AUDITS` | KV namespace | Audit/project persistence |
| `AUTH` | SQLite Durable Object namespace | Accounts, sessions, activity |
| `APP_ORIGIN` | Text variable | Pages origin |

Keep the existing Durable Object migration `v1-auth-directory` when deploying. Do not rename the class or remove its migration.

## Deploy

### Pages

The `seo-machine` Pages project is connected to this repository's `main` branch. A push to `main` publishes the dashboard automatically.

### Worker

The repository includes a GitHub Actions workflow at `.github/workflows/deploy-worker.yml`.

1. Create a Cloudflare API token scoped to this account with **Workers Scripts: Edit** permission.
2. In GitHub, open **Settings → Secrets and variables → Actions** for this repository.
3. Add a repository secret named `CLOUDFLARE_API_TOKEN`.
4. Push a change to `worker/**` or `wrangler.toml`, or manually run **Deploy SEO Machine Worker** from the Actions tab.

The workflow runs `wrangler deploy --config wrangler.toml`. Wrangler applies the configured bindings, keeps the existing Durable Object migration, and registers the Cron trigger. Never paste the API token into source files or chat.

For a manual deployment, use Wrangler with the same config:

```sh
npx wrangler deploy --config wrangler.toml
```

## First-time account setup

Open the Pages app. If no account exists, create the initial Super Admin account from the setup screen. After bootstrap, sign in with that account. Member accounts can then be created from the admin area.

## API endpoints

- `GET /api/health` — API health and persistence status.
- `GET /api/auth/status` — whether initial setup is required.
- `POST /api/auth/bootstrap` — create the first Super Admin only.
- `POST /api/auth/login`, `GET /api/auth/me`, `POST /api/auth/logout` — session management.
- `POST /api/audit`, `GET /api/audits` — run and retrieve SEO audits.
- `GET/POST /api/projects` — list and create projects.
- `PATCH/DELETE /api/projects/:id` — update or delete a project.
- `GET /api/projects/:id/monitor-history` — retrieve uptime history.
- `GET/POST /api/admin/users`, `GET /api/admin/activity` — Super Admin operations.

## Audit safeguards

The audit endpoint accepts HTTP/HTTPS public website URLs, rejects local/private host targets, follows at most one same-host redirect, times out requests after 12 seconds, and limits downloaded HTML to 1 MB. Only audit sites you own or have permission to test.

## Monitoring

Enable monitoring inside a project. The Worker Cron handler runs every 15 minutes and checks projects whose next check is due. Each project's configured interval is 6, 12, or 24 hours. History records expire after 30 days.

Monitoring is not active until the updated Worker is deployed and the Cron trigger is visible in Cloudflare.
