ALTER TABLE users
    ADD COLUMN IF NOT EXISTS contact_phone varchar(40),
    ADD COLUMN IF NOT EXISTS contact_whatsapp varchar(40),
    ADD COLUMN IF NOT EXISTS contact_public boolean NOT NULL DEFAULT false;

ALTER TABLE products
    ADD COLUMN IF NOT EXISTS deleted_at timestamptz,
    ADD COLUMN IF NOT EXISTS deleted_by bigint REFERENCES users(id),
    ADD COLUMN IF NOT EXISTS deleted_by_role varchar(20),
    ADD COLUMN IF NOT EXISTS deleted_reason text NOT NULL DEFAULT '';

CREATE TABLE IF NOT EXISTS affiliate_product_exclusions (
    id bigserial PRIMARY KEY,
    affiliate_id bigint NOT NULL REFERENCES users(id),
    product_id bigint NOT NULL REFERENCES products(id) ON DELETE CASCADE,
    created_at timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT uq_affiliate_product_exclusion UNIQUE (affiliate_id, product_id)
);

CREATE TABLE IF NOT EXISTS product_audit_events (
    id bigserial PRIMARY KEY,
    product_id bigint NOT NULL REFERENCES products(id),
    actor_user_id bigint REFERENCES users(id),
    action varchar(40) NOT NULL,
    details jsonb NOT NULL DEFAULT '{}'::jsonb,
    created_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS contract_requests (
    id bigserial PRIMARY KEY,
    user_id bigint NOT NULL REFERENCES users(id),
    requested_type varchar(32) NOT NULL,
    title varchar(180) NOT NULL,
    details text NOT NULL,
    desired_commission numeric(5,2),
    status varchar(20) NOT NULL DEFAULT 'pending',
    admin_note text NOT NULL DEFAULT '',
    reviewed_by bigint REFERENCES users(id),
    reviewed_at timestamptz,
    created_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS contract_negotiations (
    id bigserial PRIMARY KEY,
    contract_id bigint NOT NULL REFERENCES contracts(id),
    proposer_id bigint NOT NULL REFERENCES users(id),
    recipient_id bigint NOT NULL REFERENCES users(id),
    parent_id bigint REFERENCES contract_negotiations(id),
    proposal_text text NOT NULL,
    reason text NOT NULL DEFAULT '',
    response_text text NOT NULL DEFAULT '',
    status varchar(20) NOT NULL DEFAULT 'pending',
    responded_at timestamptz,
    created_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS notifications (
    id bigserial PRIMARY KEY,
    user_id bigint NOT NULL REFERENCES users(id),
    title varchar(180) NOT NULL,
    body text NOT NULL DEFAULT '',
    target_url varchar(500) NOT NULL DEFAULT '',
    read_at timestamptz,
    created_at timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_products_deleted_at ON products (deleted_at);
CREATE INDEX IF NOT EXISTS idx_product_audit_events_product_created ON product_audit_events (product_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_contract_requests_status_created ON contract_requests (status, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_contract_negotiations_contract_created ON contract_negotiations (contract_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_contract_negotiations_recipient_status ON contract_negotiations (recipient_id, status);
CREATE INDEX IF NOT EXISTS idx_notifications_user_created ON notifications (user_id, created_at DESC);
