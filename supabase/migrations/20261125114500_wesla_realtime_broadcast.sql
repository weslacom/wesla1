-- Low-latency, privacy-safe change notifications for the Wesla website and admin portal.
-- Only table name and operation are broadcast; no customer or account row data is exposed.

CREATE OR REPLACE FUNCTION public.wesla_realtime_notify()
RETURNS trigger
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, public, realtime
AS $$
BEGIN
  PERFORM realtime.send(
    jsonb_build_object(
      'table', TG_TABLE_NAME,
      'operation', TG_OP,
      'changed_at', pg_catalog.clock_timestamp()
    ),
    'wesla_change',
    'wesla:updates',
    true
  );
  RETURN NULL;
END;
$$;

DO $policy$
BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM pg_policies
    WHERE schemaname = 'realtime'
      AND tablename = 'messages'
      AND policyname = 'wesla_updates_read'
  ) THEN
    EXECUTE 'CREATE POLICY "wesla_updates_read" ON realtime.messages FOR SELECT TO anon, authenticated USING (topic = ''wesla:updates'' AND extension = ''broadcast'' AND private IS TRUE)';
  END IF;
END
$policy$;

DO $triggers$
DECLARE
  item record;
BEGIN
  FOR item IN
    SELECT tablename FROM pg_tables WHERE schemaname = 'public'
  LOOP
    EXECUTE format('DROP TRIGGER IF EXISTS trg_wesla_realtime_notify ON public.%I', item.tablename);
    EXECUTE format(
      'CREATE TRIGGER trg_wesla_realtime_notify AFTER INSERT OR UPDATE OR DELETE ON public.%I FOR EACH STATEMENT EXECUTE FUNCTION public.wesla_realtime_notify()',
      item.tablename
    );
  END LOOP;
END
$triggers$;

REVOKE ALL ON FUNCTION public.wesla_realtime_notify() FROM PUBLIC;
REVOKE ALL ON FUNCTION public.wesla_realtime_notify() FROM anon, authenticated, service_role;
