# SEO Machine

Premium SEO audit workspace for Cloudflare Pages, Workers and D1.

## Included in this starter
- Responsive dark admin workspace.
- Live website audit form and report.
- Technical and on-page checks: HTTP status, title, meta description, canonical, H1, heading structure, viewport, image alt attributes, robots noindex, HTTPS and content type.
- Severity filters, browser audit history and CSV export.
- Worker endpoints: GET /api/health and POST /api/audit.
- D1 schema for users, sessions, websites, audits, findings and admin activity.

## Deploy
1. Create a D1 database and run schema.sql.
2. Put the database ID into wrangler.toml and deploy the Worker.
3. Set APP_ORIGIN in wrangler.toml to your Pages domain and redeploy.
4. Deploy this repository to Cloudflare Pages.
5. Open Settings in the app and enter the Worker URL.

## Important
The first release is an admin workspace preview. Authentication, account bootstrap, user management and D1 persistence are not yet wired into the UI. Audit history currently lives in the browser. Do not present this preview as a production multi-user service until authentication, rate limiting and persistent audit storage are implemented.

The audit API rejects local/private IP targets, limits page downloads to 1 MB, limits redirects and uses a timeout. Only audit websites you own or have permission to test.
