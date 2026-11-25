-- Read-only verification for the Wesla admin portal database connection.
-- Run in Supabase SQL Editor. This script does not modify production data.
select current_database() as database_name, current_user as connected_role, now() as checked_at;
select table_name from information_schema.tables where table_schema='public' and table_name in
('users','products','orders','payouts','contracts','contract_acceptances','contract_events','contract_requests','contract_negotiations','contract_termination_requests','notifications','announcements') order by table_name;
select tablename,indexname from pg_indexes where schemaname='public' and tablename in
('contracts','contract_requests','contract_negotiations','contract_termination_requests','contract_acceptances','contract_events','auth_sessions') order by tablename,indexname;
