-- The Gated Shifter — introduction requests
-- Safe to run repeatedly.

create table if not exists member_intake (
  id              bigserial primary key,
  created_at      timestamptz not null default now(),

  -- Submitted by the visitor
  full_name       text        not null,
  email           text        not null,
  phone           text,
  referred_by     text,
  marques         text,                 -- cars / marques of interest
  message         text,
  consent         boolean     not null default false,

  -- Capture context (which QR code, the tablet, or the open web)
  source          text        not null default 'web',
  page_path       text,
  user_agent      text,
  ip_hash         text,                 -- salted SHA-256, never the raw IP

  -- Follow-up workflow
  status          text        not null default 'new',
  notes           text,

  -- Plain date column so the dedupe index below can be immutable.
  created_date    date        not null default (now() at time zone 'utc')::date,

  constraint member_intake_email_shape check (position('@' in email) > 1),
  constraint member_intake_status_valid
    check (status in ('new', 'contacted', 'qualified', 'declined', 'spam'))
);

create index if not exists member_intake_created_at_idx
  on member_intake (created_at desc);

create index if not exists member_intake_email_idx
  on member_intake (lower(email));

create index if not exists member_intake_source_idx
  on member_intake (source);

-- Stops an accidental double-tap on the tablet from creating two rows for the
-- same person on the same day. A genuine second inquiry weeks later still saves.
create unique index if not exists member_intake_dedupe_idx
  on member_intake (lower(email), created_date);