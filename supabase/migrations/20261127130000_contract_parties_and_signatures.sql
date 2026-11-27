-- Contract refresh: dynamic parties and actual handwritten signature images.
-- Additive only; existing contracts and acceptance records remain unchanged.
alter table public.contracts
  add column if not exists participant_ids jsonb not null default '[]'::jsonb;
alter table public.contract_acceptances
  add column if not exists signature_data_url text;
