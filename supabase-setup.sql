create extension if not exists pgcrypto;

create table if not exists public.profiles (
    id uuid primary key default gen_random_uuid(),
    auth_user_id uuid unique references auth.users (id) on delete set null,
    email text not null unique,
    name text not null,
    role text not null default 'employee' check (role in ('admin', 'employee')),
    access_token_hash text unique,
    access_token_created_at timestamptz,
    access_last_used_at timestamptz,
    access_revoked_at timestamptz,
    access_device_hash text,
    created_at timestamptz not null default timezone('utc', now())
);

create table if not exists public.app_settings (
    id integer primary key check (id = 1),
    center_lat double precision not null,
    center_lng double precision not null,
    radius_m double precision not null,
    time_in time not null,
    time_out time not null,
    updated_at timestamptz not null default timezone('utc', now())
);

create table if not exists public.attendance_logs (
    id bigint generated always as identity primary key,
    user_id uuid not null references public.profiles (id) on delete cascade,
    type text not null check (type in ('CHECK_IN', 'CHECK_OUT')),
    at_iso timestamptz not null default timezone('utc', now()),
    lat double precision not null,
    lng double precision not null,
    distance_m double precision not null,
    inside boolean not null,
    verified_at timestamptz,
    verified_by uuid references public.profiles (id) on delete set null
);

alter table public.attendance_logs
    add column if not exists verified_at timestamptz;

alter table public.attendance_logs
    add column if not exists verified_by uuid references public.profiles (id) on delete set null;

create index if not exists profiles_auth_user_id_idx on public.profiles (auth_user_id);
create index if not exists profiles_role_idx on public.profiles (role);
create index if not exists profiles_access_token_hash_idx on public.profiles (access_token_hash);
create index if not exists attendance_logs_user_id_idx on public.attendance_logs (user_id);
create index if not exists attendance_logs_at_iso_idx on public.attendance_logs (at_iso desc);

create or replace function public.handle_new_admin_user()
returns trigger
language plpgsql
security definer
set search_path = public, extensions
as $$
declare
    assigned_role text := 'employee';
begin
    if not exists (
        select 1
        from public.profiles
        where role = 'admin'
    ) then
        assigned_role := 'admin';
    end if;

    insert into public.profiles (auth_user_id, email, name, role)
    values (
        new.id,
        new.email,
        coalesce(nullif(trim(new.raw_user_meta_data ->> 'name'), ''), split_part(coalesce(new.email, ''), '@', 1), 'Admin'),
        assigned_role
    );

    return new;
end;
$$;

drop trigger if exists on_auth_user_created on auth.users;
create trigger on_auth_user_created
after insert on auth.users
for each row execute procedure public.handle_new_admin_user();

create or replace function public.is_admin()
returns boolean
language sql
stable
security definer
set search_path = public, extensions
as $$
    select exists (
        select 1
        from public.profiles
        where auth_user_id = auth.uid()
          and role = 'admin'
    );
$$;

create or replace function public.consume_employee_access_token(p_token text, p_device_key text)
returns public.profiles
language plpgsql
security definer
set search_path = public, extensions
as $$
declare
    normalized_token text := nullif(trim(p_token), '');
    normalized_device text := nullif(trim(p_device_key), '');
    token_hash text;
    device_hash text;
    matched_profile public.profiles%rowtype;
begin
    if normalized_token is null then
        raise exception 'Attendance access token is required.';
    end if;

    if normalized_device is null then
        raise exception 'This device is missing its access key.';
    end if;

    token_hash := encode(digest(normalized_token, 'sha256'), 'hex');
    device_hash := encode(digest(normalized_device, 'sha256'), 'hex');

    select *
    into matched_profile
    from public.profiles
    where role = 'employee'
      and access_token_hash = token_hash
      and access_revoked_at is null
    limit 1;

    if not found then
        raise exception 'This attendance link is invalid or has been revoked.';
    end if;

    if matched_profile.access_device_hash is null then
        update public.profiles
        set access_device_hash = device_hash,
            access_last_used_at = timezone('utc', now())
        where id = matched_profile.id;
    elsif matched_profile.access_device_hash <> device_hash then
        raise exception 'This attendance link is already assigned to another device.';
    else
        update public.profiles
        set access_last_used_at = timezone('utc', now())
        where id = matched_profile.id;
    end if;

    select *
    into matched_profile
    from public.profiles
    where id = matched_profile.id;

    return matched_profile;
end;
$$;

create or replace function public.resolve_employee_access_token(p_token text, p_device_key text)
returns table (
    id uuid,
    email text,
    name text,
    role text,
    access_token_created_at timestamptz,
    access_last_used_at timestamptz
)
language plpgsql
security definer
set search_path = public, extensions
as $$
declare
    matched_profile public.profiles%rowtype;
begin
    select *
    into matched_profile
    from public.consume_employee_access_token(p_token, p_device_key);

    return query
    select
        matched_profile.id,
        matched_profile.email,
        matched_profile.name,
        matched_profile.role,
        matched_profile.access_token_created_at,
        matched_profile.access_last_used_at;
end;
$$;

create or replace function public.get_employee_logs_by_access_token(
    p_token text,
    p_device_key text,
    p_limit integer default 60,
    p_days integer default 30
)
returns table (
    id bigint,
    user_id uuid,
    user_email text,
    user_name text,
    type text,
    at_iso timestamptz,
    lat double precision,
    lng double precision,
    distance_m double precision,
    inside boolean
)
language plpgsql
security definer
set search_path = public, extensions
as $$
declare
    matched_profile public.profiles%rowtype;
    resolved_limit integer := greatest(1, least(coalesce(p_limit, 60), 365));
    resolved_days integer := greatest(1, least(coalesce(p_days, 30), 36500));
begin
    select *
    into matched_profile
    from public.consume_employee_access_token(p_token, p_device_key);

    return query
    select
        logs.id,
        matched_profile.id,
        matched_profile.email,
        matched_profile.name,
        logs.type,
        logs.at_iso,
        logs.lat,
        logs.lng,
        logs.distance_m,
        logs.inside
    from public.attendance_logs as logs
    where logs.user_id = matched_profile.id
      and logs.at_iso >= timezone('utc', now()) - make_interval(days => resolved_days)
    order by logs.at_iso asc
    limit resolved_limit;
end;
$$;

create or replace function public.record_attendance_by_access_token(
    p_token text,
    p_device_key text,
    p_type text,
    p_at_iso timestamptz,
    p_lat double precision,
    p_lng double precision,
    p_distance_m double precision,
    p_inside boolean
)
returns table (
    id bigint,
    user_id uuid,
    user_email text,
    user_name text,
    type text,
    at_iso timestamptz,
    lat double precision,
    lng double precision,
    distance_m double precision,
    inside boolean
)
language plpgsql
security definer
set search_path = public, extensions
as $$
declare
    matched_profile public.profiles%rowtype;
    normalized_type text := upper(trim(coalesce(p_type, '')));
begin
    if normalized_type not in ('CHECK_IN', 'CHECK_OUT') then
        raise exception 'Attendance type must be CHECK_IN or CHECK_OUT.';
    end if;

    select *
    into matched_profile
    from public.consume_employee_access_token(p_token, p_device_key);

    insert into public.attendance_logs (
        user_id,
        type,
        at_iso,
        lat,
        lng,
        distance_m,
        inside
    )
    values (
        matched_profile.id,
        normalized_type,
        coalesce(p_at_iso, timezone('utc', now())),
        p_lat,
        p_lng,
        p_distance_m,
        coalesce(p_inside, false)
    )
    returning
        attendance_logs.id,
        matched_profile.id,
        matched_profile.email,
        matched_profile.name,
        attendance_logs.type,
        attendance_logs.at_iso,
        attendance_logs.lat,
        attendance_logs.lng,
        attendance_logs.distance_m,
        attendance_logs.inside
    into id, user_id, user_email, user_name, type, at_iso, lat, lng, distance_m, inside;

    return next;
end;
$$;

create or replace function public.admin_generate_employee_access_token(p_profile_id uuid)
returns table (
    profile_id uuid,
    employee_name text,
    employee_email text,
    access_token text,
    access_token_created_at timestamptz
)
language plpgsql
security definer
set search_path = public, extensions
as $$
declare
    generated_token text := encode(gen_random_bytes(24), 'hex');
    generated_hash text := encode(digest(generated_token, 'sha256'), 'hex');
    matched_profile public.profiles%rowtype;
begin
    if not public.is_admin() then
        raise exception 'Admin access required.';
    end if;

    update public.profiles
    set access_token_hash = generated_hash,
        access_token_created_at = timezone('utc', now()),
        access_last_used_at = null,
        access_revoked_at = null,
        access_device_hash = null
    where id = p_profile_id
      and role = 'employee'
    returning *
    into matched_profile;

    if not found then
        raise exception 'Employee profile not found.';
    end if;

    return query
    select
        matched_profile.id,
        matched_profile.name,
        matched_profile.email,
        generated_token,
        matched_profile.access_token_created_at;
end;
$$;

create or replace function public.admin_revoke_employee_access_token(p_profile_id uuid)
returns table (
    profile_id uuid,
    employee_name text,
    employee_email text,
    access_revoked_at timestamptz
)
language plpgsql
security definer
set search_path = public, extensions
as $$
declare
    matched_profile public.profiles%rowtype;
begin
    if not public.is_admin() then
        raise exception 'Admin access required.';
    end if;

    update public.profiles
    set access_token_hash = null,
        access_last_used_at = null,
        access_revoked_at = timezone('utc', now()),
        access_device_hash = null
    where id = p_profile_id
      and role = 'employee'
    returning *
    into matched_profile;

    if not found then
        raise exception 'Employee profile not found.';
    end if;

    return query
    select
        matched_profile.id,
        matched_profile.name,
        matched_profile.email,
        matched_profile.access_revoked_at;
end;
$$;

create or replace function public.admin_update_profile_role(
    p_profile_id uuid,
    p_new_role text
)
returns table (
    profile_id uuid,
    previous_role text,
    new_role text
)
language plpgsql
security definer
set search_path = public, extensions
as $$
declare
    matched_profile public.profiles%rowtype;
    previous_role text;
    normalized_role text := lower(trim(coalesce(p_new_role, '')));
    admin_count integer;
begin
    if not public.is_admin() then
        raise exception 'Admin access required.';
    end if;

    if normalized_role not in ('admin', 'employee') then
        raise exception 'Role must be admin or employee.';
    end if;

    select *
    into matched_profile
    from public.profiles
    where id = p_profile_id;

    if not found then
        raise exception 'Profile not found.';
    end if;

    previous_role := matched_profile.role;

    if previous_role = 'admin' and normalized_role = 'employee' then
        select count(*)
        into admin_count
        from public.profiles
        where role = 'admin';

        if admin_count <= 1 then
            raise exception 'Cannot remove the last admin.';
        end if;
    end if;

    update public.profiles
    set role = normalized_role
    where id = p_profile_id
    returning *
    into matched_profile;

    return query
    select
        matched_profile.id,
        previous_role,
        matched_profile.role;
end;
$$;

create or replace function public.admin_reset_system()
returns text
language plpgsql
security definer
set search_path = public, extensions
as $$
begin
    delete from public.attendance_logs;
    delete
    from public.profiles;

    return 'system reset';
end;
$$;

create or replace function public.calculate_daily_duty_hours(
    p_profile_id uuid,
    p_day date
)
returns table (
    profile_id uuid,
    day date,
    expected_start timestamptz,
    actual_first_check timestamptz,
    counted_start timestamptz,
    actual_last_check timestamptz,
    counted_end timestamptz,
    duty_seconds integer,
    duty_hours numeric
)
language plpgsql
security definer
set search_path = public, extensions
as $$
declare
    settings record;
    day_start timestamptz := timezone('utc', p_day::timestamp);
    day_end timestamptz := day_start + interval '1 day';
    expected_start timestamptz;
    expected_end timestamptz;
    first_check timestamptz;
    last_check timestamptz;
    counted_start timestamptz;
    counted_end timestamptz;
    duty_secs numeric;
begin
    select time_in, time_out
    into settings
    from public.app_settings
    where id = 1;

    if not found then
        expected_start := day_start + interval '09:00';
        expected_end := day_start + interval '18:00';
    else
        expected_start := day_start + settings.time_in;
        expected_end := day_start + settings.time_out;
    end if;

    select
        min(at_iso) filter (where type = 'CHECK_IN'),
        max(at_iso) filter (where type = 'CHECK_OUT')
    into first_check, last_check
    from public.attendance_logs
    where user_id = p_profile_id
      and at_iso >= day_start
      and at_iso < day_end;

    if first_check is null then
        counted_start := expected_start;
    else
        counted_start := greatest(expected_start, first_check);
    end if;

    if last_check is null then
        counted_end := expected_end;
    else
        counted_end := last_check;
    end if;

    duty_secs := greatest(0, extract(epoch from (counted_end - counted_start)));

    return query
    select
        p_profile_id,
        p_day,
        expected_start,
        first_check,
        counted_start,
        last_check,
        counted_end,
        duty_secs::integer,
        duty_secs / 3600.0;
end;
$$;

alter table public.profiles enable row level security;
alter table public.app_settings enable row level security;
alter table public.attendance_logs enable row level security;

drop policy if exists "profiles_select_self_or_admin" on public.profiles;
create policy "profiles_select_self_or_admin"
on public.profiles
for select
to authenticated
using (auth_user_id = auth.uid() or public.is_admin());

drop policy if exists "profiles_insert_admin" on public.profiles;
create policy "profiles_insert_admin"
on public.profiles
for insert
to authenticated
with check (public.is_admin());

drop policy if exists "profiles_update_admin" on public.profiles;
create policy "profiles_update_admin"
on public.profiles
for update
to authenticated
using (public.is_admin())
with check (public.is_admin());

drop policy if exists "profiles_delete_admin" on public.profiles;
create policy "profiles_delete_admin"
on public.profiles
for delete
to authenticated
using (public.is_admin());

drop policy if exists "settings_select_public" on public.app_settings;
create policy "settings_select_public"
on public.app_settings
for select
to anon, authenticated
using (true);

drop policy if exists "settings_update_admin" on public.app_settings;
create policy "settings_update_admin"
on public.app_settings
for update
to authenticated
using (public.is_admin())
with check (public.is_admin());

drop policy if exists "settings_insert_admin" on public.app_settings;
create policy "settings_insert_admin"
on public.app_settings
for insert
to authenticated
with check (public.is_admin());

drop policy if exists "attendance_select_admin" on public.attendance_logs;
create policy "attendance_select_admin"
on public.attendance_logs
for select
to authenticated
using (public.is_admin());

drop policy if exists "attendance_insert_admin" on public.attendance_logs;
create policy "attendance_insert_admin"
on public.attendance_logs
for insert
to authenticated
with check (public.is_admin());

drop policy if exists "attendance_update_admin" on public.attendance_logs;
create policy "attendance_update_admin"
on public.attendance_logs
for update
to authenticated
using (public.is_admin())
with check (public.is_admin());

drop policy if exists "attendance_delete_admin" on public.attendance_logs;
create policy "attendance_delete_admin"
on public.attendance_logs
for delete
to authenticated
using (public.is_admin());

revoke all on function public.handle_new_admin_user() from public;
revoke all on function public.consume_employee_access_token(text, text) from public, anon, authenticated;
grant execute on function public.resolve_employee_access_token(text, text) to anon, authenticated;
grant execute on function public.get_employee_logs_by_access_token(text, text, integer, integer) to anon, authenticated;
grant execute on function public.record_attendance_by_access_token(text, text, text, timestamptz, double precision, double precision, double precision, boolean) to anon, authenticated;
grant execute on function public.admin_generate_employee_access_token(uuid) to authenticated;
grant execute on function public.admin_revoke_employee_access_token(uuid) to authenticated;
revoke all on function public.admin_update_profile_role(uuid, text) from public, anon, authenticated;
grant execute on function public.admin_update_profile_role(uuid, text) to authenticated;
revoke all on function public.admin_reset_system() from public, anon, authenticated;
grant execute on function public.admin_reset_system() to authenticated;
revoke all on function public.calculate_daily_duty_hours(uuid, date) from public, anon, authenticated;
grant execute on function public.calculate_daily_duty_hours(uuid, date) to authenticated;

insert into public.app_settings (id, center_lat, center_lng, radius_m, time_in, time_out)
values (1, 14.5995, 120.9842, 100, '09:00', '18:00')
on conflict (id) do nothing;
