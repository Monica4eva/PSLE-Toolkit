-- ============================================================
-- PSLE Prep Toolkit — phone / email alerts via Make.com
--
-- Run this ONCE, AFTER supabase-setup.sql.
--
-- ⚠ BEFORE YOU RUN IT: replace the URL on the line marked
--    >>> PASTE YOUR MAKE.COM WEBHOOK URL HERE <<<
--    with the address Make gives you (Step 2 of the guide).
--
-- What it does: every time a parent places an order OR asks for an
-- upgrade, Supabase sends the details to Make.com, and Make emails or
-- WhatsApps you. Nothing else about the site changes.
--
-- Safe to re-run — use it again whenever you need to change the URL.
-- ============================================================

-- pg_net is what lets the database call out to the internet.
create extension if not exists pg_net;


-- ---------- The alert sender ----------

create or replace function notify_make()
returns trigger
language plpgsql
security definer
set search_path = public, extensions
as $$
declare
  hook text;
  body jsonb;
begin
  hook := 'https://hook.eu1.make.com/gk6c4krcqjoqbdoo7d159ndwzqu2ja9k';

  -- Not configured yet? Do nothing rather than fail the parent's order.
  if hook is null or hook like '%PASTE-YOUR-OWN-URL-HERE%' then
    return new;
  end if;

  if TG_TABLE_NAME = 'orders' then
    body := jsonb_build_object(
      'kind',      'new_order',
      'headline',  'New order — P' || new.price || ' from ' || coalesce(new.parent_name, 'a parent'),
      'code',      new.code,
      'reference', new.reference,
      'parent',    coalesce(new.parent_name, ''),
      'phone',     coalesce(new.phone, ''),
      'email',     coalesce(new.email, ''),
      'learner',   coalesce(new.learner_name, ''),
      'standard',  coalesce(new.standard, ''),
      'package',   coalesce(new.plan_name, new.plan),
      'amount',    new.price,
      'subjects',  array_to_string(new.subjects, ', '),
      'method',    coalesce(new.method, ''),
      'status',    new.status,
      'placed_at', to_char(new.created_at, 'DD Mon YYYY HH24:MI')
    );
  else
    body := jsonb_build_object(
      'kind',      'upgrade_request',
      'headline',  'Upgrade request — P' || new.amount || ' on code ' || new.code,
      'code',      new.code,
      'reference', new.reference,
      'package',   coalesce(new.to_plan_name, new.to_plan),
      'amount',    new.amount,
      'subjects',  array_to_string(new.subjects, ', '),
      'method',    coalesce(new.method, ''),
      'status',    new.status,
      'placed_at', to_char(new.created_at, 'DD Mon YYYY HH24:MI')
    );
  end if;

  -- Fire and forget. If Make is down the parent's order still succeeds.
  begin
    perform net.http_post(
      url     := hook,
      headers := '{"Content-Type": "application/json"}'::jsonb,
      body    := body
    );
  exception when others then
    null;
  end;

  return new;
end;
$$;


-- ---------- Attach it ----------

drop trigger if exists alert_on_new_order on orders;
create trigger alert_on_new_order
  after insert on orders
  for each row execute function notify_make();

drop trigger if exists alert_on_new_upgrade on upgrades;
create trigger alert_on_new_upgrade
  after insert on upgrades
  for each row execute function notify_make();


-- ---------- Check it is working ----------
-- Run this after placing a test order. status_code 200 means Make got it.
--
--   select created, status_code, error_msg
--     from net._http_response
--    order by created desc
--    limit 5;
