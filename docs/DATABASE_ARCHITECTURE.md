# Wesla database architecture

## Production source of truth
- Supabase project: `ojxvcusprpnzooqfkojt` (PostgreSQL 17).
- The live database currently contains 21 relational tables in `public`.
- Keep existing production tables and records. Schema changes must be additive unless a separately reviewed data migration is approved.
- FastAPI uses SQLAlchemy and its own `users` / `auth_sessions` authentication model; it does not currently use Supabase Auth identities as the app user primary key.
- Never expose the database connection string, service-role key, or password hashes to browser code.

## Functional domains (separate modules, shared relational database)
| Domain | Tables | Main relationships |
|---|---|---|
| Identity and access | `users`, `auth_sessions`, `applications` | sessions and applications belong to users |
| Merchant catalog | `products`, `product_images`, `product_variants`, `product_size_guides` | products belong to merchants; images, variants and guides belong to products |
| Affiliate tracking | `affiliate_links`, `affiliate_product_exclusions` | links join affiliates to products; exclusions join affiliates and products |
| Orders and commissions | `orders` | orders reference products and merchants, optionally affiliates and variants; rates are snapshotted |
| Contracts and legal workflows | `contracts`, `contract_acceptances`, `contract_events`, `contract_termination_requests`, `contract_requests`, `contract_negotiations`, `commission_change_requests` | parties, acceptances, event history, negotiation threads and change requests are related by foreign keys |
| Payouts | `payouts` | payout requests belong to affiliates |
| Notifications and configuration | `notifications`, `site_settings` | notifications belong to users; settings are platform-scoped |
| Product audit | `product_audit_events` | audit events reference products and optional actor users |

## Integrity rules
- Keep foreign keys and unique constraints as the source of relational integrity.
- Keep order commission rates and money values as immutable order-time snapshots.
- Never overwrite signed contract text; create a new version or addendum and retain acceptance hashes and event history.
- Prefer soft deletion for products referenced by orders or affiliate links.
- Product/variant stock and order creation must occur in one database transaction to prevent overselling.
- Use fixed-precision `numeric` for prices, balances and commissions.

## Security model
- RLS is enabled on all 21 current public tables. Inspection found no RLS policies. This is deny-by-default for clients subject to RLS; it is not proof of application-level authorization.
- The current app authenticates through its FastAPI session cookie and performs role checks in the backend. Do not add broad `anon` or `authenticated` policies until identity mapping and per-table permissions are explicitly designed and tested.
- Keep direct browser access to sensitive tables disabled. If Supabase Auth/Data API is adopted later, add per-table owner/party policies and tests before granting access.
- Views exposed through the Data API should use `security_invoker = true`.

## Migration workflow
1. Inspect live schema and records.
2. Add timestamped, additive, idempotent SQL migrations.
3. Test against a development database/branch when available.
4. Apply production migrations only after reviewing exact SQL and expected effects.
5. Verify foreign keys, indexes, row counts, application health and Supabase advisors.
6. Commit identical migration files to GitLab and GitHub. GitHub `main` is the Railway deployment source; do not overwrite newer GitHub application code with an older GitLab copy.

## Applied migration
`20261124174042_wesla_foreign_key_indexes_v1.sql` adds indexes for the 18 foreign keys reported as unindexed. It does not change or delete data.
