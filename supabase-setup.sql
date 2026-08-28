-- ============================================================
-- PSLE Prep Toolkit — database setup
-- Paste this WHOLE file into Supabase → SQL Editor → Run.
-- Safe to run more than once.
-- ============================================================

-- ---------- 1. TABLES ----------

-- Extra details about each signed-up person. Supabase already stores
-- the email and the hashed password for us in auth.users.
create table if not exists profiles (
  id          uuid primary key references auth.users on delete cascade,
  parent_name text,
  phone       text,
  is_admin    boolean not null default false,
  created_at  timestamptz not null default now()
);

-- One row per purchase. This is the money table.
create table if not exists orders (
  id           uuid primary key default gen_random_uuid(),
  account_id   uuid references auth.users on delete set null,
  parent_name  text not null,
  phone        text,
  email        text,
  learner_name text not null,
  standard     text default 'Standard 7',
  plan         text not null check (plan in ('single','bundle','full')),
  plan_name    text,
  price        integer not null check (price >= 0),
  subjects     text[] not null default '{}',
  method       text,
  reference    text not null unique,
  code         text not null unique,
  status       text not null default 'pending-verification'
               check (status in ('pending-verification','verified','revoked')),
  device_limit integer not null default 3,
  verified_at  timestamptz,
  verified_by  uuid,
  created_at   timestamptz not null default now(),
  expires_at   date not null default '2026-10-31'
);

-- Which devices have used a code — this is what stops one paid code
-- being shared with a whole village.
create table if not exists devices (
  id          uuid primary key default gen_random_uuid(),
  code        text not null,
  fingerprint text not null,
  first_seen  timestamptz not null default now(),
  last_seen   timestamptz not null default now(),
  unique (code, fingerprint)
);

-- A learner's practice history, so clearing the browser does not wipe it.
create table if not exists progress (
  id         uuid primary key default gen_random_uuid(),
  code       text not null,
  subject    text not null,
  answered   integer not null default 0,
  correct    integer not null default 0,
  stars      integer not null default 0,
  updated_at timestamptz not null default now(),
  unique (code, subject)
);

-- A record of every verify / revoke. Never delete from this.
create table if not exists audit_log (
  id         uuid primary key default gen_random_uuid(),
  actor      uuid,
  action     text not null,
  order_code text,
  detail     text,
  created_at timestamptz not null default now()
);

create index if not exists orders_status_idx  on orders (status);
create index if not exists orders_code_idx    on orders (upper(code));
create index if not exists devices_code_idx   on devices (code);
create index if not exists progress_code_idx  on progress (code);


-- ---------- 2. AUTO-CREATE A PROFILE ON SIGN-UP ----------

create or replace function handle_new_user()
returns trigger
language plpgsql
security definer
set search_path = public
as $$
begin
  insert into profiles (id, parent_name, phone)
  values (new.id,
          new.raw_user_meta_data->>'parent_name',
          new.raw_user_meta_data->>'phone')
  on conflict (id) do nothing;
  return new;
end;
$$;

drop trigger if exists on_auth_user_created on auth.users;
create trigger on_auth_user_created
  after insert on auth.users
  for each row execute function handle_new_user();


-- ---------- 3. ROW LEVEL SECURITY ----------
-- This is the security boundary. With RLS on and no permissive SELECT
-- policy, a visitor cannot read the orders table at all — not even with
-- the public key visible in the website's code. The only way to check a
-- code is the redeem_code() function below, which decides server-side.

alter table profiles  enable row level security;
alter table orders    enable row level security;
alter table devices   enable row level security;
alter table progress  enable row level security;
alter table audit_log enable row level security;

-- helper: is the person making this request an admin?
create or replace function is_admin()
returns boolean
language sql
stable
security definer
set search_path = public
as $$
  select coalesce((select is_admin from profiles where id = auth.uid()), false);
$$;

-- PROFILES: you may read and edit only your own.
drop policy if exists "own profile read"  on profiles;
drop policy if exists "own profile write" on profiles;
drop policy if exists "admin reads profiles" on profiles;
create policy "own profile read"  on profiles for select using (id = auth.uid());
create policy "own profile write" on profiles for update using (id = auth.uid());
create policy "admin reads profiles" on profiles for select using (is_admin());

-- ORDERS: anyone may CREATE an order, but only ever as unpaid.
-- The check clause is what stops someone posting themselves a verified order.
drop policy if exists "anyone may place an order" on orders;
create policy "anyone may place an order" on orders
  for insert to anon, authenticated
  with check (
    status = 'pending-verification'
    and verified_at is null
    and verified_by is null
  );

-- ORDERS: a signed-in parent may read their own orders (to see status).
-- Matched on account_id OR email: a brand-new project has email
-- confirmation switched on, so the order is often placed before the
-- account has a session and account_id would otherwise stay null.
drop policy if exists "parent reads own orders" on orders;
create policy "parent reads own orders" on orders
  for select to authenticated
  using (
    account_id = auth.uid()
    or lower(coalesce(email, '')) = lower(coalesce(auth.jwt() ->> 'email', '~none~'))
  );

-- ORDERS: admins may do anything.
drop policy if exists "admin manages orders" on orders;
create policy "admin manages orders" on orders
  for all to authenticated
  using (is_admin()) with check (is_admin());

-- Note there is deliberately NO policy letting anon SELECT or UPDATE
-- orders. That is the point.

-- DEVICES / PROGRESS: written only through the functions below.
drop policy if exists "admin reads devices" on devices;
create policy "admin reads devices" on devices for select using (is_admin());

drop policy if exists "admin reads progress" on progress;
create policy "admin reads progress" on progress for select using (is_admin());

-- AUDIT LOG: admins read; nobody edits or deletes.
drop policy if exists "admin reads audit" on audit_log;
create policy "admin reads audit" on audit_log for select using (is_admin());


-- ---------- 4. REDEEM A CODE ----------
-- The only route in for a learner. Runs with elevated rights
-- (security definer) but returns nothing useful unless the order is
-- actually verified, so it cannot be used to fish for codes.

create or replace function redeem_code(p_code text, p_fingerprint text default null)
returns json
language plpgsql
security definer
set search_path = public
as $$
declare
  r orders;
  used integer;
begin
  select * into r from orders
   where upper(code) = upper(trim(p_code))
   limit 1;

  if not found then
    return json_build_object('authorised', false, 'reason', 'not-found');
  end if;

  if r.status = 'revoked' then
    return json_build_object('authorised', false, 'reason', 'revoked');
  end if;

  if r.status <> 'verified' then
    return json_build_object('authorised', false, 'reason', 'pending');
  end if;

  if r.expires_at < current_date then
    return json_build_object('authorised', false, 'reason', 'expired');
  end if;

  -- device limit
  if p_fingerprint is not null and length(p_fingerprint) > 0 then
    insert into devices (code, fingerprint)
    values (r.code, p_fingerprint)
    on conflict (code, fingerprint)
      do update set last_seen = now();

    select count(*) into used from devices where code = r.code;

    if used > r.device_limit then
      delete from devices
       where code = r.code and fingerprint = p_fingerprint
         and first_seen > now() - interval '10 seconds';
      return json_build_object('authorised', false, 'reason', 'device-limit',
                               'limit', r.device_limit);
    end if;
  end if;

  return json_build_object(
    'authorised', true,
    'reason', 'ok',
    'code', r.code,
    'learner', r.learner_name,
    'standard', r.standard,
    'subjects', case when array_length(r.subjects, 1) is null
                     then null else r.subjects end,
    'planName', coalesce(r.plan_name, r.plan),
    'price', r.price,
    'expires', r.expires_at
  );
end;
$$;

revoke all on function redeem_code(text, text) from public;
grant execute on function redeem_code(text, text) to anon, authenticated;


-- ---------- 5. SAVE PROGRESS ----------
-- Accepts progress only for a code that is genuinely verified.

create or replace function save_progress(
  p_code text, p_subject text,
  p_answered integer, p_correct integer, p_stars integer
) returns void
language plpgsql
security definer
set search_path = public
as $$
declare ok boolean;
begin
  select (status = 'verified') into ok from orders
   where upper(code) = upper(trim(p_code)) limit 1;

  if not coalesce(ok, false) then
    raise exception 'code not active';
  end if;

  insert into progress (code, subject, answered, correct, stars)
  values (upper(trim(p_code)), p_subject,
          greatest(p_answered, 0), greatest(p_correct, 0), greatest(p_stars, 0))
  on conflict (code, subject) do update
    set answered   = greatest(excluded.answered, progress.answered),
        correct    = greatest(excluded.correct,  progress.correct),
        stars      = greatest(excluded.stars,    progress.stars),
        updated_at = now();
end;
$$;

revoke all on function save_progress(text, text, integer, integer, integer) from public;
grant execute on function save_progress(text, text, integer, integer, integer) to anon, authenticated;


-- ---------- 6. LOAD PROGRESS ----------

create or replace function load_progress(p_code text)
returns json
language plpgsql
security definer
set search_path = public
as $$
declare result json;
begin
  select json_agg(json_build_object(
           'subject', subject, 'answered', answered,
           'correct', correct, 'stars', stars))
    into result
    from progress
   where upper(code) = upper(trim(p_code));
  return coalesce(result, '[]'::json);
end;
$$;

revoke all on function load_progress(text) from public;
grant execute on function load_progress(text) to anon, authenticated;


-- ---------- 7. ADMIN: VERIFY / REVOKE ----------
-- Admin-only, and every call is written to the audit log.

create or replace function set_order_status(p_code text, p_status text)
returns json
language plpgsql
security definer
set search_path = public
as $$
declare r orders;
begin
  if not is_admin() then
    raise exception 'not authorised';
  end if;

  if p_status not in ('pending-verification','verified','revoked') then
    raise exception 'bad status';
  end if;

  update orders
     set status      = p_status,
         verified_at = case when p_status = 'verified' then now() else verified_at end,
         verified_by = case when p_status = 'verified' then auth.uid() else verified_by end
   where upper(code) = upper(trim(p_code))
   returning * into r;

  if not found then
    raise exception 'code not found';
  end if;

  insert into audit_log (actor, action, order_code, detail)
  values (auth.uid(), 'status:' || p_status, r.code, r.parent_name);

  -- revoking frees the devices so the code cannot linger anywhere
  if p_status = 'revoked' then
    delete from devices where code = r.code;
  end if;

  return json_build_object('code', r.code, 'status', r.status);
end;
$$;

revoke all on function set_order_status(text, text) from public;
grant execute on function set_order_status(text, text) to authenticated;


-- ---------- 7b. LINK PAST ORDERS TO AN ACCOUNT ----------
-- Called once after a parent signs in, so their earlier orders (placed
-- before the account had a session) get attached to it properly.

create or replace function claim_my_orders()
returns integer
language plpgsql
security definer
set search_path = public
as $$
declare n integer;
begin
  if auth.uid() is null then
    return 0;
  end if;

  update orders
     set account_id = auth.uid()
   where account_id is null
     and lower(coalesce(email, '')) = lower(coalesce(auth.jwt() ->> 'email', '~none~'));

  get diagnostics n = row_count;
  return n;
end;
$$;

revoke all on function claim_my_orders() from public;
grant execute on function claim_my_orders() to authenticated;


-- ---------- 8. MAKE YOURSELF THE ADMIN ----------
-- Sign up on the website FIRST with the email you want to use, then
-- replace the email below and run it. Using the same email for a
-- customer account is fine — one account can be both.
--
--   insert into profiles (id, is_admin)
--   select id, true from auth.users where email = 'you@example.com'
--   on conflict (id) do update set is_admin = true;
--
-- See who exists and who is an admin:
--   select u.email, coalesce(p.is_admin, false) as is_admin
--     from auth.users u left join profiles p on p.id = u.id;
