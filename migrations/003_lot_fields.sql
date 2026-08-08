-- The Gated Shifter — Lot-specific application fields
-- Adds the handful of fields unique to the Collector, Specialist and
-- Partner applications that 001/002 did not already provide for.
-- Safe to run repeatedly.

/* ------------------------------------------------------------------ *
 * Lot 01 — Collector
 * primary_marques (002) already covers "Marques of Focus".
 * referred_by (001) already covers "How did you hear of us?".
 * ------------------------------------------------------------------ */
alter table member_intake add column if not exists collection_size   text;
alter table member_intake add column if not exists defining_vehicle  text;

/* ------------------------------------------------------------------ *
 * Lot 02 — Specialist
 * specialist_needs (002) is repurposed here to hold the chosen
 * discipline, since nothing else in 002 was ever using it.
 * ------------------------------------------------------------------ */
alter table member_intake add column if not exists workshop_practice text;
alter table member_intake add column if not exists proud_work        text;
alter table member_intake add column if not exists vouch_referral    text;

/* ------------------------------------------------------------------ *
 * Lot 03 — Partner
 * partner_specialty (002) is repurposed here to hold the organization
 * name, since nothing else in 002 was ever using it.
 * ------------------------------------------------------------------ */
alter table member_intake add column if not exists partner_area      text;
alter table member_intake add column if not exists partnership_notes text;

/* ------------------------------------------------------------------ *
 * Discipline / area are short controlled picks, worth filtering on.
 * ------------------------------------------------------------------ */
create index if not exists member_intake_specialist_needs_idx  on member_intake (specialist_needs);
create index if not exists member_intake_partner_area_idx      on member_intake (partner_area);
