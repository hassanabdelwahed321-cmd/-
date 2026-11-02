-- FastShip attendance portal schema
-- Run in Supabase SQL Editor. Only two confirmation types are supported:
-- warehouse = company entered the warehouse; excel = Excel file received from group.

create extension if not exists pgcrypto;

create table if not exists public.profiles (
  id uuid primary key references auth.users(id) on delete cascade,
  full_name text not null default 'موظف',
  role text not null default 'staff' check (role in ('admin','staff')),
  avatar_url text,
  created_at timestamptz not null default now()
);

create table if not exists public.companies (
  id uuid primary key default gen_random_uuid(),
  name text not null,
  code text unique,
  contact_name text,
  phone text,
  is_active boolean not null default true,
  created_by uuid references auth.users(id),
  created_at timestamptz not null default now()
);

create table if not exists public.confirmations (
  id uuid primary key default gen_random_uuid(),
  company_id uuid not null references public.companies(id),
  kind text not null check (kind in ('warehouse','excel')),
  confirmed_by uuid not null references auth.users(id),
  confirmed_at timestamptz not null default now(),
  notes text
);

create index if not exists confirmations_company_idx on public.confirmations(company_id);
create index if not exists confirmations_time_idx on public.confirmations(confirmed_at desc);
create index if not exists confirmations_kind_idx on public.confirmations(kind);

alter table public.profiles enable row level security;
alter table public.companies enable row level security;
alter table public.confirmations enable row level security;

-- Authenticated team members can read profiles, companies and confirmations.
create policy "authenticated read profiles" on public.profiles for select to authenticated using (true);
create policy "users update own profile" on public.profiles for update to authenticated using (auth.uid() = id) with check (auth.uid() = id);

create policy "authenticated read companies" on public.companies for select to authenticated using (true);
create policy "authenticated add companies" on public.companies for insert to authenticated with check (true);
create policy "authenticated update companies" on public.companies for update to authenticated using (true) with check (true);

create policy "authenticated read confirmations" on public.confirmations for select to authenticated using (true);
create policy "authenticated add confirmations" on public.confirmations for insert to authenticated with check (auth.uid() = confirmed_by);

-- Automatically create a staff profile for each newly registered auth user.
create or replace function public.handle_new_user()
returns trigger language plpgsql security definer set search_path = public
as $$
begin
  insert into public.profiles (id, full_name, role)
  values (new.id, coalesce(new.raw_user_meta_data->>'full_name','موظف'), 'staff')
  on conflict (id) do nothing;
  return new;
end;
$$;

drop trigger if exists on_auth_user_created on auth.users;
create trigger on_auth_user_created after insert on auth.users
for each row execute procedure public.handle_new_user();

-- Promote the first account to admin manually after creating it:
-- update public.profiles set role = 'admin' where id = 'AUTH_USER_UUID';
-- For production, tighten company insert/update policies to admin only and
-- add role-aware policies before inviting staff.
