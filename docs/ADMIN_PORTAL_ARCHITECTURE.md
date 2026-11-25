# Wesla Admin Portal architecture

## Single source of truth
The independent admin website is a presentation layer. It does not store a second copy of users, products, orders, commissions, or contracts. It forwards same-origin `/api/*` requests to the existing FastAPI application, which enforces the admin role and reads/writes the shared PostgreSQL database. This avoids duplicate business logic.

## Runtime configuration
- `WESLA_API_BASE`: HTTPS origin of the main Wesla API, without a path. A Railway private HTTP hostname ending in `.railway.internal` is also accepted.
- `WESLA_PUBLIC_URL`: public website origin for the return link.
- `ADMIN_PORTAL_URL`: admin origin, used to prevent recursive proxy configuration.
- `DATABASE_URL`: set only on the main API service. The admin portal must not receive the database password.

Never commit database URLs, passwords, service-role keys, or Railway tokens.

## Diagnostics
- `GET /health` checks the upstream API, PostgreSQL readiness, and all required admin routes.
- `GET /api/_portal/diagnostics` returns safe status flags and route availability only; it does not return secrets or database rows.
- `/api/{path}` forwards methods, query strings, request bodies, session cookies, response status, and content type.

Required upstream routes:
- `/api/admin/password-login`
- `/api/admin/overview`
- `/api/admin/contracts`
- `/api/admin/contract-requests`
- `/api/admin/negotiations`
- `/api/admin/termination-requests`

## Existing Supabase database
The existing Supabase project is `ojxvcusprpnzooqfkojt` in EU West. Its current schema already contains the admin domains: users, applications, products, orders, payouts, contracts, acceptances, contract events, termination requests, contract requests, negotiations, notifications, and announcements. The admin portal must reuse those tables through the main API; do not create duplicate admin tables.

The main backend uses SQLAlchemy and `DATABASE_URL`. Keep that value in the host's secret/environment settings. Migration history remains in `supabase/migrations`.

## Security
- Browser calls stay on the admin portal origin.
- The portal forwards the session cookie to the main API.
- The main API enforces the `admin` role.
- Database credentials remain server-side.
- RLS is enabled on public tables and direct grants to `anon`/`authenticated` are revoked. Do not expose a direct browser database connection or add broad Data API grants to work around API failures.
- Supabase currently reports RLS-enabled tables without policies. Revisit this before exposing any table through the Data API; current app reads/writes happen through the trusted backend and its server-side role checks.

## Read-only database verification SQL
See `docs/admin_database_verification.sql`. It only checks the connection, expected tables, and indexes; it does not modify production data.

## Deployment order
1. Deploy the main API from the same commit.
2. Verify `/health` returns HTTP 200 and `database: "ok"`.
3. Verify every required admin route appears in `/openapi.json`.
4. Deploy the independent admin portal from that same commit.
5. Open the portal and run “اختبار اتصال الخادم”.
6. Test password login and the contract/request/termination workflows.
