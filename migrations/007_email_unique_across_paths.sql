-- The Gated Shifter — one membership record per email, across all paths
--
-- 006 made the address unique per path, which still allowed the same person
-- to hold a Collector record and a Specialist record. The rule is now:
--
--   Collector / Specialist / Partner   one record per email, across all three
--   Apparel                            one record per email, counted separately
--
-- So an existing member can still register apparel interest — which is what
-- the button in their confirmation email invites them to do — but nobody can
-- file a second membership application under an address already in use.
--
-- Safe to run repeatedly.

alter table member_intake add column if not exists duplicate_of bigint;

/* ------------------------------------------------------------------ *
 * Existing repeats keep their history. Within the membership paths the
 * earliest record per address is kept live; later ones point at it and
 * drop out of the unique index. Same again for apparel, separately.
 * ------------------------------------------------------------------ */
with membership as (
  select id,
         row_number() over (partition by lower(email) order by created_at, id) as rn,
         first_value(id) over (partition by lower(email) order by created_at, id) as keep_id
    from member_intake
   where member_type is distinct from 'Apparel'
)
update member_intake m
   set duplicate_of = k.keep_id
  from membership k
 where k.id = m.id and k.rn > 1 and m.duplicate_of is null;

with apparel as (
  select id,
         row_number() over (partition by lower(email) order by created_at, id) as rn,
         first_value(id) over (partition by lower(email) order by created_at, id) as keep_id
    from member_intake
   where member_type = 'Apparel'
)
update member_intake m
   set duplicate_of = k.keep_id
  from apparel k
 where k.id = m.id and k.rn > 1 and m.duplicate_of is null;

/* ------------------------------------------------------------------ *
 * 006's per-path index is replaced by the two below.
 * ------------------------------------------------------------------ */
drop index if exists member_intake_email_type_unique;

create unique index if not exists member_intake_membership_email_unique
  on member_intake (lower(email))
  where duplicate_of is null and member_type is distinct from 'Apparel';

create unique index if not exists member_intake_apparel_email_unique
  on member_intake (lower(email))
  where duplicate_of is null and member_type = 'Apparel';