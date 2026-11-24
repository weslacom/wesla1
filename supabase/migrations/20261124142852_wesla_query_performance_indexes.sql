-- Query-path indexes for catalogue, account dashboards, and workflow queues.
-- All statements are idempotent and preserve existing rows.
CREATE INDEX IF NOT EXISTS idx_products_status_created_id
    ON products (status, created_at DESC, id DESC);

CREATE INDEX IF NOT EXISTS idx_products_merchant_created_id
    ON products (merchant_id, created_at DESC, id DESC);

CREATE INDEX IF NOT EXISTS idx_orders_merchant_created_id
    ON orders (merchant_id, created_at DESC, id DESC);

CREATE INDEX IF NOT EXISTS idx_orders_affiliate_created_id
    ON orders (affiliate_id, created_at DESC, id DESC);

CREATE INDEX IF NOT EXISTS idx_affiliate_links_affiliate_created_id
    ON affiliate_links (affiliate_id, created_at DESC, id DESC);

CREATE INDEX IF NOT EXISTS idx_applications_status_created_id
    ON applications (status, created_at DESC, id DESC);

CREATE INDEX IF NOT EXISTS idx_payouts_affiliate_status
    ON payouts (affiliate_id, status);

CREATE INDEX IF NOT EXISTS idx_contract_termination_status_created_id
    ON contract_termination_requests (status, created_at DESC, id DESC);

CREATE INDEX IF NOT EXISTS idx_contract_events_contract_created_id
    ON contract_events (contract_id, created_at, id);
