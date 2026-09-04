-- ============================================================
-- PSLE Prep Toolkit — free sample lead capture
--
-- Run this ONCE in Supabase → SQL Editor, AFTER supabase-setup.sql.
-- Safe to re-run.
--
-- Creates the table that stores everyone who tries the free sample,
-- so you have a name and a phone number to follow up with.
--
-- Security: a visitor can ADD themselves and nothing else. They cannot
-- read the list — so nobody can harvest your parents' phone numbers.
-- Only you, signed in as admin, can see it.
-- ============================================================

create table if not exists leads (
  id           uuid primary key default gen_random_uuid(),
  name         text not null,
  phone        text not null,
  email        text,
  learner_name text,
  standard     text,
  source       text default 'free-sample',
  attempts     integer not null default 1,
  score        integer,
  total        integer,
  finished     boolean not null default false,
  converted    boolean not null default false,
  created_at   timestamptz not null default now(),
  last_seen    timestamptz not null default now()
);

create unique index if not exists leads_phone_idx on leads (phone);
create index if not exists leads_created_idx on leads (created_at desc);

alter table leads enable row level security;

-- Deliberately NO anon select/update/delete policy. Everything a visitor
-- does goes through capture_lead() below.
drop policy if exists "admin manages leads" on leads;
create policy "admin manages leads" on leads
  for all to authenticated
  using (is_admin()) with check (is_admin());


-- ---------- A visitor signs up to try the sample ----------
-- Returns an id the page uses to record their score later. Grants
-- nothing and reveals nothing about anyone else.

create or replace function capture_lead(
  p_name text, p_phone text, p_email text,
  p_learner text default null, p_standard text default null
) returns json
language plpgsql
security definer
set search_path = public
as $$
declare rec leads; clean_phone text;
begin
  if coalesce(trim(p_name), '') = '' then
    raise exception 'name required';
  end if;

  clean_phone := regexp_replace(coalesce(p_phone, ''), '[^0-9]', '', 'g');
  if length(clean_phone) < 7 then
    raise exception 'phone required';
  end if;

  insert into leads (name, phone, email, learner_name, standard)
  values (trim(p_name), clean_phone, nullif(trim(coalesce(p_email, '')), ''),
          nullif(trim(coalesce(p_learner, '')), ''), nullif(trim(coalesce(p_standard, '')), ''))
  on conflict (phone) do update
     set name         = coalesce(nullif(trim(p_name), ''), leads.name),
         email        = coalesce(nullif(trim(coalesce(p_email, '')), ''), leads.email),
         learner_name = coalesce(nullif(trim(coalesce(p_learner, '')), ''), leads.learner_name),
         standard     = coalesce(nullif(trim(coalesce(p_standard, '')), ''), leads.standard),
         attempts     = leads.attempts + 1,
         last_seen    = now()
  returning * into rec;

  return json_build_object('ok', true, 'id', rec.id, 'name', rec.name);
end;
$$;

revoke all on function capture_lead(text, text, text, text, text) from public;
grant execute on function capture_lead(text, text, text, text, text) to anon, authenticated;


-- ---------- Record how they did, once they finish ----------
-- Tells you who is genuinely engaged: a parent who scored 24/30 and
-- worked through the whole set is a far warmer lead than one who quit.

create or replace function record_sample_score(p_id uuid, p_score integer, p_total integer)
returns void
language plpgsql
security definer
set search_path = public
as $$
begin
  update leads
     set score = greatest(coalesce(p_score, 0), 0),
         total = greatest(coalesce(p_total, 0), 0),
         finished = true,
         last_seen = now()
   where id = p_id;
end;
$$;

revoke all on function record_sample_score(uuid, integer, integer) from public;
grant execute on function record_sample_score(uuid, integer, integer) to anon, authenticated;


-- ---------- Admin: the follow-up list ----------
-- Marks anyone who has since bought, so you do not chase existing
-- customers. Matched on phone number.

create or replace function list_leads()
returns json
language plpgsql
security definer
set search_path = public
as $$
declare result json;
begin
  if not is_admin() then
    raise exception 'not authorised';
  end if;

  select json_agg(row_to_json(l) order by l.created_at desc) into result
  from (
    select d.id, d.name, d.phone, d.email, d.learner_name, d.standard,
           d.attempts, d.score, d.total, d.finished, d.created_at, d.last_seen,
           exists (
             select 1 from orders o
              where regexp_replace(coalesce(o.phone, ''), '[^0-9]', '', 'g') = d.phone
                and o.status = 'verified'
           ) as has_bought
      from leads d
  ) l;

  return coalesce(result, '[]'::json);
end;
$$;

revoke all on function list_leads() from public;
grant execute on function list_leads() to authenticated;


-- ---------- Delete a lead (admin only) ----------
create or replace function delete_lead(p_id uuid)
returns void
language plpgsql
security definer
set search_path = public
as $$
begin
  if not is_admin() then
    raise exception 'not authorised';
  end if;
  delete from leads where id = p_id;
end;
$$;

revoke all on function delete_lead(uuid) from public;
grant execute on function delete_lead(uuid) to authenticated;


-- ---------- Check it ----------
--   select name, phone, score, total, finished, created_at
--     from leads order by created_at desc;
