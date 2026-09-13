-- ============================================================
-- Add Moral Education and Religious Studies to existing orders
--
-- Run this ONCE, after deploying the version that adds the two new
-- subjects. It is safe to re-run.
--
-- Why this is needed: orders placed before these subjects existed store
-- only six subject ids. The app already protects full-access buyers in
-- the browser, but this makes the DATABASE correct too, so the admin
-- dashboard and any future change agree with what the parent owns.
-- ============================================================

-- 1. Anyone who bought Full Toolkit Access gets the two new subjects.
update orders
   set subjects = array['maths','english','setswana','social','science','agric','moral','religious']
 where plan = 'full';

-- 2. The plan name on those orders stays as it is — the price they paid
--    does not change, they simply get more for it.

-- 3. Check the result:
select code, parent_name, plan, price, array_length(subjects, 1) as subject_count, status
  from orders
 order by created_at desc;

-- Single-subject and 3-subject buyers are deliberately untouched: they
-- chose specific subjects and can add more through the upgrade flow.
