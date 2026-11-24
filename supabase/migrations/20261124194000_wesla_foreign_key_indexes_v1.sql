-- Wesla: cover every currently unindexed foreign key.
-- Additive and idempotent: no rows, columns, constraints, or existing indexes are removed.
CREATE INDEX IF NOT EXISTS idx_affiliate_product_exclusions_product_id ON public.affiliate_product_exclusions (product_id);
CREATE INDEX IF NOT EXISTS idx_commission_change_requests_affected_user_id ON public.commission_change_requests (affected_user_id);
CREATE INDEX IF NOT EXISTS idx_commission_change_requests_affiliate_id ON public.commission_change_requests (affiliate_id);
CREATE INDEX IF NOT EXISTS idx_commission_change_requests_contract_id ON public.commission_change_requests (contract_id);
CREATE INDEX IF NOT EXISTS idx_commission_change_requests_merchant_id ON public.commission_change_requests (merchant_id);
CREATE INDEX IF NOT EXISTS idx_commission_change_requests_product_id ON public.commission_change_requests (product_id);
CREATE INDEX IF NOT EXISTS idx_commission_change_requests_proposed_by ON public.commission_change_requests (proposed_by);
CREATE INDEX IF NOT EXISTS idx_contract_events_actor_user_id ON public.contract_events (actor_user_id);
CREATE INDEX IF NOT EXISTS idx_contract_negotiations_parent_id ON public.contract_negotiations (parent_id);
CREATE INDEX IF NOT EXISTS idx_contract_negotiations_proposer_id ON public.contract_negotiations (proposer_id);
CREATE INDEX IF NOT EXISTS idx_contract_requests_reviewed_by ON public.contract_requests (reviewed_by);
CREATE INDEX IF NOT EXISTS idx_contract_requests_user_id ON public.contract_requests (user_id);
CREATE INDEX IF NOT EXISTS idx_contract_termination_requests_contract_id ON public.contract_termination_requests (contract_id);
CREATE INDEX IF NOT EXISTS idx_contract_termination_requests_decided_by ON public.contract_termination_requests (decided_by);
CREATE INDEX IF NOT EXISTS idx_contract_termination_requests_requester_user_id ON public.contract_termination_requests (requester_user_id);
CREATE INDEX IF NOT EXISTS idx_product_audit_events_actor_user_id ON public.product_audit_events (actor_user_id);
CREATE INDEX IF NOT EXISTS idx_product_images_product_id ON public.product_images (product_id);
CREATE INDEX IF NOT EXISTS idx_products_deleted_by ON public.products (deleted_by);
