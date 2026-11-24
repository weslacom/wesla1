# وِصلة — منصة التسويق بالعمولة

This is a working full-stack MVP, not a static mockup. It includes a FastAPI backend, persistent SQL database (SQLite by default), cookie-based sessions, PBKDF2 password hashing, role-gated APIs, merchant/affiliate applications, product catalog, affiliate links and 30-day referral cookie, customer orders, frozen commission rates per order, merchant order status management, payout requests and admin review.

## Run locally

1. Install Python 3.11+.
2. `python -m venv .venv` then activate it.
3. `pip install -r requirements.txt`
4. Set `ADMIN_EMAIL` and a strong `ADMIN_PASSWORD` in the environment before the first run. The first admin is bootstrapped once.
5. `uvicorn app.main:app --host 0.0.0.0 --port 8000`
6. Open http://localhost:8000. API docs: http://localhost:8000/docs.

The application package is stored under `app/`. Configure `DATABASE_URL` for PostgreSQL in production. Set `COOKIE_SECURE=1` behind HTTPS. Set `COOKIE_SECURE=1` behind HTTPS.

## Important business constraints

- Merchants receive customer orders directly and remain responsible for fulfillment, delivery, collection, returns and customer service.
- A commission is created only for orders attributed through a Wesla referral link. External purchases on merchant websites/WhatsApp cannot be automatically confirmed without a verified integration; do not promise automatic tracking for them.
- The MVP records commissions at order creation and preserves the rates used. Cancelled/returned orders zero those commissions. Payouts are manually reviewed by the admin.
- Before real public use, add transactional email/phone verification, rate limiting, CSRF/origin protections, audit/ledger accounting, stronger fraud controls, privacy/terms pages, backups, monitoring, and a proper deployment review. Use HTTPS and PostgreSQL in production.
- Admin credentials are created from environment variables only on first startup. Never commit secrets.
