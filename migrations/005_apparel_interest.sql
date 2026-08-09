-- The Gated Shifter — apparel interest register
-- The apparel enquiry is an intake like any other: same table, same
-- deletion token, same export. It is an expression of interest only —
-- nothing is sold and no payment information is ever collected.
-- Safe to run repeatedly.

/* ------------------------------------------------------------------ *
 * Lot 04 — Apparel
 * ------------------------------------------------------------------ */
alter table member_intake add column if not exists apparel_items text[] not null default '{}';
alter table member_intake add column if not exists apparel_size  text;

/* ------------------------------------------------------------------ *
 * 002 constrained member_type to the three application paths. Apparel
 * enquiries are a fourth kind of record in the same table, so the
 * constraint is widened rather than the record being forced into one of
 * the membership types.
 * ------------------------------------------------------------------ */
alter table member_intake drop constraint if exists member_intake_member_type_valid;

alter table member_intake
  add constraint member_intake_member_type_valid
  check (member_type in ('Collector', 'Specialist', 'Partner', 'Apparel'));

/* ------------------------------------------------------------------ *
 * Filtering: apparel enquiries are read as their own list, and the
 * items array is worth searching by garment.
 * ------------------------------------------------------------------ */
create index if not exists member_intake_apparel_items_idx on member_intake using gin (apparel_items);
create index if not exists member_intake_apparel_size_idx  on member_intake (apparel_size);