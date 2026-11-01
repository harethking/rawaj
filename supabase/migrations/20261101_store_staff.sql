-- Rawaj: staff accounts (run once in Supabase → SQL Editor).
-- Staff join a store through the owner's private link and work inside it with a role.
create table if not exists public.store_members (
  user_id uuid primary key references auth.users(id) on delete cascade,
  store_id uuid not null references public.stores(id) on delete cascade,
  role text not null default 'orders' check (role in ('manager', 'orders', 'inventory')),
  created_at timestamptz not null default now()
);
create index if not exists store_members_store_idx on public.store_members(store_id);
alter table public.store_members enable row level security;

create table if not exists public.store_invites (
  store_id uuid primary key references public.stores(id) on delete cascade,
  token text not null unique,
  created_at timestamptz not null default now()
);
alter table public.store_invites enable row level security;
revoke all on public.store_invites from anon, authenticated;

create or replace function public.rw_member_store() returns uuid
language sql stable security definer set search_path = '' as $$
  select m.store_id from public.store_members m where m.user_id = auth.uid()
$$;

drop policy if exists store_members_select on public.store_members;
create policy store_members_select on public.store_members for select to authenticated
  using (user_id = (select auth.uid())
         or store_id in (select s.id from public.stores s where s.owner_id = (select auth.uid()))
         or (select public.is_admin()));

drop policy if exists stores_select on public.stores;
create policy stores_select on public.stores for select to authenticated
  using (owner_id = (select auth.uid()) or id = (select public.rw_member_store()) or (select public.is_admin()));
drop policy if exists stores_update on public.stores;
create policy stores_update on public.stores for update to authenticated
  using (owner_id = (select auth.uid()) or id = (select public.rw_member_store()) or (select public.is_admin()))
  with check (owner_id = (select auth.uid()) or id = (select public.rw_member_store()) or (select public.is_admin()));

drop policy if exists store_images_select on storage.objects;
drop policy if exists store_images_insert on storage.objects;
drop policy if exists store_images_update on storage.objects;
drop policy if exists store_images_delete on storage.objects;
create policy store_images_select on storage.objects for select to authenticated
  using (bucket_id = 'store-images' and ((storage.foldername(name))[1] in (select s.id::text from public.stores s where s.owner_id = (select auth.uid()))
         or (storage.foldername(name))[1] = (select public.rw_member_store())::text or (select public.is_admin())));
create policy store_images_insert on storage.objects for insert to authenticated
  with check (bucket_id = 'store-images' and ((storage.foldername(name))[1] in (select s.id::text from public.stores s where s.owner_id = (select auth.uid()))
         or (storage.foldername(name))[1] = (select public.rw_member_store())::text or (select public.is_admin())));
create policy store_images_update on storage.objects for update to authenticated
  using (bucket_id = 'store-images' and ((storage.foldername(name))[1] in (select s.id::text from public.stores s where s.owner_id = (select auth.uid()))
         or (storage.foldername(name))[1] = (select public.rw_member_store())::text or (select public.is_admin())));
create policy store_images_delete on storage.objects for delete to authenticated
  using (bucket_id = 'store-images' and ((storage.foldername(name))[1] in (select s.id::text from public.stores s where s.owner_id = (select auth.uid()))
         or (storage.foldername(name))[1] = (select public.rw_member_store())::text or (select public.is_admin())));

create or replace function public.staff_link(p_reset boolean default false) returns jsonb
language plpgsql security definer set search_path = '' as $$
declare st public.stores%rowtype; t text;
begin
  select * into st from public.stores where owner_id = auth.uid();
  if not found then return jsonb_build_object('ok', false, 'error', 'NO_STORE'); end if;
  select token into t from public.store_invites where store_id = st.id;
  if t is null or p_reset then
    t := lower(public.rw_rand(16));
    insert into public.store_invites (store_id, token) values (st.id, t)
      on conflict (store_id) do update set token = excluded.token, created_at = now();
  end if;
  return jsonb_build_object('ok', true, 'token', t);
end $$;

create or replace function public.staff_link_info(p_token text) returns jsonb
language sql stable security definer set search_path = '' as $$
  select jsonb_build_object('name', coalesce(s.data->>'name', ''))
    from public.store_invites i join public.stores s on s.id = i.store_id
   where i.token = lower(btrim(coalesce(p_token, '')))
$$;

create or replace function public.join_store(p_token text) returns jsonb
language plpgsql security definer set search_path = '' as $$
declare uid uuid := auth.uid(); sid uuid; cur uuid; n int; nm text;
begin
  if uid is null then return jsonb_build_object('ok', false, 'error', 'NOT_SIGNED_IN'); end if;
  select i.store_id into sid from public.store_invites i where i.token = lower(btrim(coalesce(p_token, '')));
  if sid is null then return jsonb_build_object('ok', false, 'error', 'BAD_LINK'); end if;
  select s.data->>'name' into nm from public.stores s where s.id = sid;
  if exists (select 1 from public.stores s where s.owner_id = uid) then
    return jsonb_build_object('ok', false, 'error', case when exists (select 1 from public.stores s where s.owner_id = uid and s.id = sid) then 'OWNER' else 'HAS_STORE' end);
  end if;
  select m.store_id into cur from public.store_members m where m.user_id = uid;
  if cur = sid then return jsonb_build_object('ok', true, 'store_id', sid, 'store_name', nm); end if;
  if cur is not null then return jsonb_build_object('ok', false, 'error', 'OTHER_STORE'); end if;
  select count(*) into n from public.store_members m where m.store_id = sid;
  if n >= 20 then return jsonb_build_object('ok', false, 'error', 'FULL'); end if;
  insert into public.store_members (user_id, store_id) values (uid, sid);
  return jsonb_build_object('ok', true, 'store_id', sid, 'store_name', nm);
end $$;

create or replace function public.store_staff() returns jsonb
language sql stable security definer set search_path = '' as $$
  select coalesce(jsonb_agg(jsonb_build_object('user_id', m.user_id, 'role', m.role, 'name', coalesce(p.name, ''), 'email', coalesce(p.email, ''), 'at', m.created_at) order by m.created_at), '[]'::jsonb)
    from public.store_members m
    join public.stores s on s.id = m.store_id and s.owner_id = auth.uid()
    left join public.profiles p on p.id = m.user_id
$$;

create or replace function public.set_staff_role(p_user uuid, p_role text) returns jsonb
language plpgsql security definer set search_path = '' as $$
begin
  if p_role not in ('manager', 'orders', 'inventory') then return jsonb_build_object('ok', false, 'error', 'BAD_ROLE'); end if;
  update public.store_members m set role = p_role
   where m.user_id = p_user and m.store_id in (select s.id from public.stores s where s.owner_id = auth.uid());
  return jsonb_build_object('ok', found);
end $$;

create or replace function public.remove_staff(p_user uuid) returns jsonb
language plpgsql security definer set search_path = '' as $$
begin
  delete from public.store_members m
   where m.user_id = p_user
     and (m.user_id = auth.uid() or m.store_id in (select s.id from public.stores s where s.owner_id = auth.uid()));
  return jsonb_build_object('ok', found);
end $$;

revoke all on function public.staff_link(boolean), public.join_store(text), public.store_staff(), public.set_staff_role(uuid, text), public.remove_staff(uuid) from public, anon;
grant execute on function public.staff_link(boolean), public.join_store(text), public.store_staff(), public.set_staff_role(uuid, text), public.remove_staff(uuid) to authenticated;
grant execute on function public.staff_link_info(text) to anon, authenticated;
grant execute on function public.rw_member_store() to authenticated;
