-- ============================================================
-- PSLE Prep Toolkit — enforce two-step verification for admins
--
-- Run this ONCE, AFTER supabase-setup.sql.
--
-- Without this file, two-step verification would only be a screen in
-- the browser — someone who got past it with dev tools would still be
-- able to verify payments. This makes the DATABASE itself refuse admin
-- actions unless the six-digit code was entered.
--
-- It is written to be safe: if you have not set up 2FA yet, nothing
-- changes and you can still sign in with just your password. The moment
-- you enrol a phone, the code becomes compulsory.
--
-- Safe to re-run.
-- ============================================================

create or replace function is_admin()
returns boolean
language sql
stable
security definer
set search_path = public
as $$
  select
    -- must be flagged as an admin, and…
    coalesce((select p.is_admin from profiles p where p.id = auth.uid()), false)
    and (
      -- …if this account has two-step verification set up, the current
      -- session must have completed it (aal2). Accounts with no factor
      -- enrolled are unaffected.
      not exists (
        select 1 from auth.mfa_factors f
         where f.user_id = auth.uid()
           and f.status  = 'verified'
      )
      or coalesce(auth.jwt() ->> 'aal', 'aal1') = 'aal2'
    );
$$;

revoke all on function is_admin() from public;
grant execute on function is_admin() to authenticated;


-- ---------- Check it ----------
-- Signed in WITHOUT the code, this returns false once 2FA is enrolled:
--   select is_admin();
--
-- See whether a phone is enrolled:
--   select u.email, f.friendly_name, f.status, f.created_at
--     from auth.mfa_factors f
--     join auth.users u on u.id = f.user_id;
--
-- LOCKED OUT? If you lose the phone, delete the factor here and you are
-- back to password-only, then set it up again on the new phone:
--   delete from auth.mfa_factors
--    where user_id = (select id from auth.users where email = 'you@example.com');
