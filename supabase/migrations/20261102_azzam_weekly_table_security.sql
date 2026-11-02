-- Azzam weekly company table + role-aware security hardening.
-- Run this in Supabase SQL Editor after the existing base schema.

alter table public.companies
  add column if not exists group_name text not null default 'شركات الجرشين';

create table if not exists public.weekly_attendance (
  id uuid primary key default gen_random_uuid(),
  company_id uuid not null references public.companies(id) on delete restrict,
  attendance_date date not null,
  kind text not null check (kind in ('warehouse','excel')),
  confirmed_by uuid not null references auth.users(id) on delete restrict,
  confirmed_at timestamptz not null default now(),
  unique(company_id, attendance_date, kind)
);
alter table public.weekly_attendance add column if not exists kind text not null default 'warehouse' check (kind in ('warehouse','excel'));
alter table public.weekly_attendance drop constraint if exists weekly_attendance_company_id_attendance_date_key;
create unique index if not exists weekly_attendance_company_date_kind_uidx on public.weekly_attendance(company_id, attendance_date, kind);
create index if not exists weekly_attendance_date_idx on public.weekly_attendance(attendance_date);
create index if not exists weekly_attendance_company_idx on public.weekly_attendance(company_id);
alter table public.weekly_attendance enable row level security;

create table if not exists public.audit_events (
  id uuid primary key default gen_random_uuid(),
  action text not null check (action in ('company_added','company_deleted')),
  details text not null,
  actor_id uuid not null references auth.users(id) on delete restrict,
  actor_name text not null,
  created_at timestamptz not null default now()
);
create index if not exists audit_events_created_idx on public.audit_events(created_at desc);
alter table public.audit_events enable row level security;

-- Role lookup is performed inside the database, never trusted from the browser.
create or replace function public.current_user_is_admin()
returns boolean
language sql
stable
security definer
set search_path = public
as $$
  select exists (
    select 1 from public.profiles p
    where p.id = auth.uid() and p.role = 'admin'
  );
$$;
revoke all on function public.current_user_is_admin() from public;
grant execute on function public.current_user_is_admin() to authenticated;

-- Remove permissive starter policies so they cannot bypass the stricter rules below.
drop policy if exists "authenticated read profiles" on public.profiles;
drop policy if exists "users update own profile" on public.profiles;
drop policy if exists "authenticated read companies" on public.companies;
drop policy if exists "authenticated add companies" on public.companies;
drop policy if exists "authenticated update companies" on public.companies;
drop policy if exists "authenticated read confirmations" on public.confirmations;
drop policy if exists "authenticated add confirmations" on public.confirmations;

-- Profiles: a user can read/update only their own profile; role changes are not allowed here.
drop policy if exists "profiles_select_own" on public.profiles;
create policy "profiles_select_own" on public.profiles for select to authenticated using (id = auth.uid());
drop policy if exists "profiles_update_own_name_avatar" on public.profiles;
create policy "profiles_update_own_name_avatar" on public.profiles for update to authenticated
using (id = auth.uid()) with check (id = auth.uid());
create or replace function public.prevent_profile_role_change()
returns trigger language plpgsql security definer set search_path = public
as $$ begin
  if auth.role() = 'authenticated' and new.role is distinct from old.role then
    raise exception 'Profile role cannot be changed from the client';
  end if;
  return new;
end; $$;
drop trigger if exists protect_profile_role on public.profiles;
create trigger protect_profile_role before update on public.profiles
for each row execute procedure public.prevent_profile_role_change();

-- Companies: all signed-in team members can view; only admins can add/archive.
drop policy if exists "companies_read_authenticated" on public.companies;
create policy "companies_read_authenticated" on public.companies for select to authenticated using (true);
drop policy if exists "companies_admin_insert" on public.companies;
create policy "companies_admin_insert" on public.companies for insert to authenticated with check (public.current_user_is_admin() and created_by = auth.uid());
drop policy if exists "companies_admin_update" on public.companies;
create policy "companies_admin_update" on public.companies for update to authenticated using (public.current_user_is_admin()) with check (public.current_user_is_admin());

-- Weekly check marks: staff can record and undo daily attendance; user identity is enforced.
drop policy if exists "weekly_attendance_read_team" on public.weekly_attendance;
create policy "weekly_attendance_read_team" on public.weekly_attendance for select to authenticated using (true);
drop policy if exists "weekly_attendance_insert_self" on public.weekly_attendance;
create policy "weekly_attendance_insert_self" on public.weekly_attendance for insert to authenticated with check (confirmed_by = auth.uid());
drop policy if exists "weekly_attendance_delete_self_or_admin" on public.weekly_attendance;
create policy "weekly_attendance_delete_self_or_admin" on public.weekly_attendance for delete to authenticated using (confirmed_by = auth.uid() or public.current_user_is_admin());

-- Audit events are visible to the team; only admins can write them.
drop policy if exists "audit_events_read_team" on public.audit_events;
create policy "audit_events_read_team" on public.audit_events for select to authenticated using (true);
drop policy if exists "audit_events_admin_insert" on public.audit_events;
create policy "audit_events_admin_insert" on public.audit_events for insert to authenticated with check (public.current_user_is_admin() and actor_id = auth.uid());

-- Existing confirmation table is kept for the two original operation types only.
-- Tighten it without adding a third kind.
drop policy if exists "confirmations_read_team" on public.confirmations;
create policy "confirmations_read_team" on public.confirmations for select to authenticated using (true);
drop policy if exists "confirmations_insert_self" on public.confirmations;
create policy "confirmations_insert_self" on public.confirmations for insert to authenticated with check (confirmed_by = auth.uid() and kind in ('warehouse','excel'));

-- Public avatars are non-sensitive profile images; uploads are restricted to each user's folder.
insert into storage.buckets (id, name, public, file_size_limit, allowed_mime_types)
values ('avatars','avatars',true,2097152,array['image/jpeg','image/png','image/webp'])
on conflict (id) do update set public = true, file_size_limit = 2097152, allowed_mime_types = array['image/jpeg','image/png','image/webp'];
drop policy if exists "avatar_public_read" on storage.objects;
create policy "avatar_public_read" on storage.objects for select using (bucket_id = 'avatars');
drop policy if exists "avatar_owner_insert" on storage.objects;
create policy "avatar_owner_insert" on storage.objects for insert to authenticated with check (bucket_id = 'avatars' and (storage.foldername(name))[1] = auth.uid()::text);
drop policy if exists "avatar_owner_update" on storage.objects;
create policy "avatar_owner_update" on storage.objects for update to authenticated using (bucket_id = 'avatars' and (storage.foldername(name))[1] = auth.uid()::text) with check (bucket_id = 'avatars' and (storage.foldername(name))[1] = auth.uid()::text);
