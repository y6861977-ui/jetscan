-- jetscan fixture: RLS is enabled and no policy exists, so WEB-RLS-009 reports the table as closed (info).
create table if not exists public.notes (id bigint primary key, body text);
alter table public.notes enable row level security;
