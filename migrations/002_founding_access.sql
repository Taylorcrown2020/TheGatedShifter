-- The Gated Shifter — Founding Access intake
-- Extends 001 with the member/intent fields, self-service deletion tokens
-- and a removal log. Safe to run repeatedly.

/* ------------------------------------------------------------------ *
 * Member identity
 * ------------------------------------------------------------------ */
alter table member_intake add column if not exists first_name      text;
alter table member_intake add column if not exists last_name       text;
alter table member_intake add column if not exists mobile_phone    text;
alter table member_intake add column if not exists city            text;
alter table member_intake add column if not exists state_region    text;
alter table member_intake add column if not exists country         text;
alter table member_intake add column if not exists member_type     text;

/* ------------------------------------------------------------------ *
 * Interest and intent
 * ------------------------------------------------------------------ */
alter table member_intake add column if not exists primary_marques   text;
alter table member_intake add column if not exists specialist_needs  text;
alter table member_intake add column if not exists partner_specialty text;
alter table member_intake add column if not exists looking_for_now   text[] not null default '{}';
alter table member_intake add column if not exists additional_notes  text;
alter table member_intake add column if not exists founding_access   boolean not null default true;

/* ------------------------------------------------------------------ *
 * Consent
 * ------------------------------------------------------------------ */
alter table member_intake add column if not exists privacy_consent   boolean not null default false;
alter table member_intake add column if not exists marketing_consent  boolean not null default false;
alter table member_intake add column if not exists consent_timestamp  timestamptz;

/* ------------------------------------------------------------------ *
 * Capture context
 * ------------------------------------------------------------------ */
alter table member_intake add column if not exists channel      text not null default 'web';
alter table member_intake add column if not exists campaign     text;
alter table member_intake add column if not exists placement    text;
alter table member_intake add column if not exists captured_by  text;
alter table member_intake add column if not exists referral_code text;

/* ------------------------------------------------------------------ *
 * Self-service deletion. One unguessable token per record; it is the
 * only thing the footer link in an email carries.
 * ------------------------------------------------------------------ */
alter table member_intake add column if not exists delete_token uuid not null default gen_random_uuid();

create unique index if not exists member_intake_delete_token_idx
  on member_intake (delete_token);

/* ------------------------------------------------------------------ *
 * Email delivery bookkeeping — so a failed send is visible and retryable
 * without guessing which records were notified.
 * ------------------------------------------------------------------ */
alter table member_intake add column if not exists confirmation_sent_at timestamptz;
alter table member_intake add column if not exists last_email_error     text;

/* ------------------------------------------------------------------ *
 * 001 required a single full_name. The form now captures first and last,
 * and full_name is kept in step for older rows and for exports.
 * ------------------------------------------------------------------ */
alter table member_intake alter column full_name drop not null;

update member_intake
   set first_name = coalesce(first_name, nullif(split_part(full_name, ' ', 1), '')),
       last_name  = coalesce(last_name,
                             nullif(trim(substr(full_name, position(' ' in full_name) + 1)), ''))
 where full_name is not null
   and (first_name is null or last_name is null);

update member_intake
   set member_type = 'Collector'
 where member_type is null;

/* ------------------------------------------------------------------ *
 * Status vocabulary. John's letter uses NEW, so the whole column is
 * uppercase. REVIEW is used when a returning email needs a human look.
 *
 * Order matters: 001's constraint only permits lowercase values, so it
 * has to go before the rows can be uppercased. Doing it the other way
 * round makes the update fail and rolls the whole migration back.
 * ------------------------------------------------------------------ */
alter table member_intake drop constraint if exists member_intake_status_valid;

update member_intake set status = upper(status) where status <> upper(status);

alter table member_intake
  add constraint member_intake_status_valid
  check (status in ('NEW', 'REVIEW', 'CONTACTED', 'QUALIFIED', 'DECLINED', 'SPAM'));

alter table member_intake alter column status set default 'NEW';

alter table member_intake drop constraint if exists member_intake_member_type_valid;

alter table member_intake
  add constraint member_intake_member_type_valid
  check (member_type in ('Collector', 'Specialist', 'Partner'));

/* ------------------------------------------------------------------ *
 * 001 blocked a second submission from the same email on the same day.
 * A returning person's new intent matters more than a tidy table, so the
 * hard block is removed: every submission is kept as its own record and
 * a repeat is flagged REVIEW instead. Rapid double-taps are caught in
 * the application by an idempotency window, not by losing the row.
 * ------------------------------------------------------------------ */
drop index if exists member_intake_dedupe_idx;

/* ------------------------------------------------------------------ *
 * Filtering the way the Monterey follow-up actually reads the table
 * ------------------------------------------------------------------ */
create index if not exists member_intake_member_type_idx on member_intake (member_type);
create index if not exists member_intake_status_idx      on member_intake (status);
create index if not exists member_intake_channel_idx     on member_intake (channel);
create index if not exists member_intake_placement_idx   on member_intake (placement);
create index if not exists member_intake_intent_idx      on member_intake using gin (looking_for_now);

/* ------------------------------------------------------------------ *
 * Deletion log. Holds no personal data — only a salted hash of the
 * email, so a deletion can be evidenced without keeping the person.
 * ------------------------------------------------------------------ */
create table if not exists member_removal_log (
  id          bigserial primary key,
  email_hash  text        not null,
  removed_at  timestamptz not null default now(),
  record_created_at timestamptz,
  source      text,
  channel     text
);

create index if not exists member_removal_log_removed_at_idx
  on member_removal_log (removed_at desc);