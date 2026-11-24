# Wesla database architecture

## Production source of truth
- Supabase project: `ojxvcusprpnzooqfkojt` (PostgreSQL 17).
- The live database currently contains 21 relational tables in `public`.
- Keep the existing production tables and records. Schema changes must be additive migrations unless a separately reviewed data migration is approved.
- The FastAPI application uses SQLAlchemy and its own `users` / `auth_sessions` authentication model. It is not currently using Supabase Auth identities as the application user primary key.
- Never expose the database connection string, service-role key, or password hashes to browser code.

## Functional domains (separate modules, shared relational database)

| Domain | Tables | Main relationships |
|---|---|---|
| Identity and access | `users`, `auth_sessions`, `applications` | sessions and applications belong to users |
| Merchant catalog | `products`, `product_images`, `product_variants`, `product_size_guides` | products belong to merchants; images, variants and size guides belong to products |
| Affiliate tracking | `affiliate_links`, `affiliate_product_exclusions` | links join affiliates to products; exclusions join affiliates and products |
| Orders and commissions | `orders` | each order references a product and merchant, optionally an affiliate and product variant; commission rates are snapshots |
| Contracts and legal workflows | `contracts`, `contract_acceptances`, `contract_events`, `contract_termination_requests`, `contract_requests`, `contract_negotiations`, `commission_change_requests` | contract parties, acceptance records, event history, negotiation threads and change requests are linked by foreign keys |
| Payouts | `payouts` | payout requests belong to affiliates |
| Notifications and configuration | `notifications`, `site_settings` | notifications belong to users; settings are platform-scoped |
| Product audit | `product_audit_events` | audit events reference products and optional actor users |

## Integrity rules
- Keep foreign keys and unique constraints as the source of relational integrity.
- Keep order commission percentages and monetary values as immutable order-time snapshots; later rate changes must not rewrite historical orders.
- Keep signed contract snapshots, acceptance hashes and event history. Do not overwrite signed contract text; create a new version or addendum.
- Prefer soft deletion for catalog products where historical orders or affiliate links refer to them.
- Product/variant stock and order creation must be updated in one database transaction to prevent overselling.
- Use fixed-precision `numeric` for prices, balances and commissions; do not use floating-point arithmetic for accounting.

## Security model
- RLS is enabled on the current 21 public tables. The current database inspection found no RLS policies. This is deny-by-default for clients subject to RLS, not proof of user-level authorization.
- The current app authenticates through its FastAPI session cookie and performs role checks in the backend. Do not add broad `anon` or `authenticated` policies until the app identity model and every table's read/write rules are explicitly mapped.
- Keep direct browser access to sensitive tables disabled. If the app later adopts Supabase Auth/Data API, add per-table owner/party policies and tests before granting access.
- Views exposed through the Data API must use `security_invoker = true` unless there is a reviewed reason otherwise.

## Migration workflow
1. Inspect the live schema and existing records.
2. Add a timestamped SQL migration; prefer additive, idempotent DDL.
3. Apply to a development database/branch first when available.
4. Apply to production only after reviewing the exact SQL and expected effects.
5. Verify foreign keys, indexes, row counts, application health and Supabase security/performance advisors.
6. Commit the exact same migration to GitLab and GitHub. GitHub `main` is the Railway deployment source; do not overwrite newer GitHub application code with an older GitLab copy.

## Current migration note
`20261124194000_wesla_foreign_key_indexes_v1.sql` adds indexes for the 18 foreign keys reported as unindexed by the Supabase performance advisor. It does not change or delete data.
