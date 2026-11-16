-- jetscan fixture for WEB-RLS-009 (docs/rules/web/WEB-RLS-009.md). Not a real schema.
create schema if not exists private;

-- POSITIVE high/potential: RLS is never enabled on an exposed table.
create table public.profiles (
  id uuid primary key references auth.users on delete cascade,
  username text,
  email text
);

-- NEGATIVE: RLS on, policies scoped to auth.uid().
create table public.todos (
  id bigint generated always as identity primary key,
  user_id uuid not null references auth.users,
  task text
);
alter table public.todos enable row level security;
create policy "Users read own todos" on public.todos for select to authenticated
  using ((select auth.uid()) = user_id);
create policy "Users update own todos" on public.todos for update to authenticated
  using ((select auth.uid()) = user_id) with check ((select auth.uid()) = user_id);

-- POSITIVE high/potential: everyone can read every order.
create table public.orders (id bigint primary key, customer_email text, total numeric);
alter table public.orders enable row level security;
create policy "Anyone can read orders" on public.orders for select using (true);

-- POSITIVE low/needs_review: public content, probably intended.
create table public.posts (id bigint primary key, title text, body text);
alter table public.posts enable row level security;
create policy "Posts are public" on public.posts for select to anon, authenticated using (true);

-- POSITIVE info: RLS on, no policy, closed to the API (not a leak).
create table public.audit_log (id bigint primary key, event text);
alter table public.audit_log enable row level security;

-- NEGATIVE: schema is not exposed in config.toml.
create table private.internal_notes (id bigint primary key, body text);
