-- Replace Supabase Realtime Broadcast with native PostgreSQL notifications.
-- This avoids dependency on realtime.messages daily partitions and sends no row data.

DO $cleanup$
DECLARE
  item record;
BEGIN
  FOR item IN SELECT tablename FROM pg_tables WHERE schemaname = 'public' LOOP
    EXECUTE format('DROP TRIGGER IF EXISTS trg_wesla_realtime_notify ON public.%I', item.tablename);
  END LOOP;
END
$cleanup$;

DROP FUNCTION IF EXISTS public.wesla_realtime_notify();
DROP POLICY IF EXISTS wesla_updates_read ON realtime.messages;

CREATE OR REPLACE FUNCTION public.wesla_notify_changes()
RETURNS trigger
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, public
AS $$
BEGIN
  PERFORM pg_catalog.pg_notify(
    'wesla_changes',
    json_build_object(
      'table', TG_TABLE_NAME,
      'operation', TG_OP,
      'changed_at', pg_catalog.clock_timestamp()
    )::text
  );
  RETURN NULL;
END;
$$;

DO $triggers$
DECLARE
  item record;
BEGIN
  FOR item IN SELECT tablename FROM pg_tables WHERE schemaname = 'public' LOOP
    EXECUTE format(
      'CREATE TRIGGER trg_wesla_notify_changes AFTER INSERT OR UPDATE OR DELETE ON public.%I FOR EACH STATEMENT EXECUTE FUNCTION public.wesla_notify_changes()',
      item.tablename
    );
  END LOOP;
END
$triggers$;

REVOKE ALL ON FUNCTION public.wesla_notify_changes() FROM PUBLIC;
REVOKE ALL ON FUNCTION public.wesla_notify_changes() FROM anon, authenticated, service_role;
