-- jetscan fixture for WEB-RLS-009, second migration (applied after the first).
create table public.messages (id bigint primary key, sender uuid, body text);
alter table public.messages enable row level security;

-- POSITIVE high/needs_review: any signed-in user deletes every row.
create policy "Signed-in users delete messages" on public.messages for delete to authenticated
  using (auth.role() = 'authenticated');

-- POSITIVE high/potential: user_metadata is editable by the user.
create policy "Admins edit messages" on public.messages for update
  using (((auth.jwt() -> 'user_metadata' ->> 'is_admin'))::boolean);

-- NEGATIVE: an open policy that a later statement drops.
create policy "tmp open" on public.messages for all using (true);
drop policy "tmp open" on public.messages;

-- POSITIVE medium/needs_review: SECURITY DEFINER without search_path, callable by RPC.
create function public.search_orders(q text) returns setof public.orders
  language sql security definer
  as $$ select * from public.orders where customer_email = q $$;

-- NEGATIVE: SECURITY DEFINER with a fixed search_path.
create function public.handle_new_user() returns trigger
  language plpgsql security definer set search_path = ''
  as $$ begin insert into public.profiles (id) values (new.id); return new; end; $$;

-- POSITIVE medium/needs_review: a view runs with its owner's rights.
create view public.order_totals as
  select customer_email, sum(total) as total from public.orders group by 1;

-- POSITIVE info/needs_review: public bucket; medium/needs_review: anonymous uploads.
insert into storage.buckets (id, name, public) values ('avatars', 'avatars', true);
create policy "Anyone uploads avatars" on storage.objects for insert
  with check (bucket_id = 'avatars');

-- NEGATIVE: suppressed with the inline marker.
create table public.ignored_demo (id int); -- jetscan:ignore

-- Not understood by jetscan: reported in limitations, not silently skipped.
create rule no_delete as on delete to public.audit_log do instead nothing;
