-- Keep the contract termination evidence column aligned with the SQLAlchemy JSON model.
-- Existing production databases already use JSONB; this is a safe no-op there.
DO $$
DECLARE
    existing_type text;
BEGIN
    SELECT data_type INTO existing_type
    FROM information_schema.columns
    WHERE table_schema = 'public'
      AND table_name = 'contract_termination_requests'
      AND column_name = 'evidence_paths';

    IF existing_type IS NULL THEN
        RAISE EXCEPTION 'public.contract_termination_requests.evidence_paths is missing';
    ELSIF existing_type <> 'jsonb' THEN
        ALTER TABLE public.contract_termination_requests
          ALTER COLUMN evidence_paths TYPE jsonb
          USING CASE
            WHEN evidence_paths IS NULL OR btrim(evidence_paths::text) = '' THEN '[]'::jsonb
            ELSE evidence_paths::jsonb
          END;
    END IF;

    ALTER TABLE public.contract_termination_requests
      ALTER COLUMN evidence_paths SET DEFAULT '[]'::jsonb;
END $$;
