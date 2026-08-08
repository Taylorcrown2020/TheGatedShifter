-- The Gated Shifter — administrative access
-- Adds the tables behind the /admin export portal: operator accounts,
-- server-side sessions, and an append-only audit trail of who signed in
-- and who exported member data.
-- Safe to run repeatedly.

/* ------------------------------------------------------------------ *
 * Operators. One row per person who may sign in. Passwords are stored
 * only as a scrypt hash with a per-row salt — never recoverable.
 * ------------------------------------------------------------------ */
create table if not exists admin_users (
  id                  bigserial   primary key,
  email               text        not null,
  password_hash       text        not null,
  created_at          timestamptz not null default now(),
  password_changed_at timestamptz not null default now(),
  last_login_at       timestamptz,
  failed_attempts     integer     not null default 0,
  locked_until        timestamptz,
  disabled_at         timestamptz,

  constraint admin_users_email_shape check (position('@' in email) > 1)
);

create unique index if not exists admin_users_email_idx
  on admin_users (lower(email));

/* ------------------------------------------------------------------ *
 * Sessions live in the database, not in a signed cookie, so access can
 * be revoked immediately and every session is inspectable. The cookie
 * carries a random token; only its SHA-256 is stored here, so a stolen
 * database backup cannot be replayed as a login.
 * ------------------------------------------------------------------ */
create table if not exists admin_sessions (
  token_hash   text        primary key,
  user_id      bigint      not null references admin_users (id) on delete cascade,
  created_at   timestamptz not null default now(),
  last_seen_at timestamptz not null default now(),
  expires_at   timestamptz not null,
  revoked_at   timestamptz,
  ip_hash      text,
  user_agent   text
);

create index if not exists admin_sessions_user_idx    on admin_sessions (user_id);
create index if not exists admin_sessions_expires_idx on admin_sessions (expires_at);

/* ------------------------------------------------------------------ *
 * Audit trail. Append-only by convention: nothing in the application
 * updates or deletes from this table. Holds no member personal data —
 * an export is recorded as a row count, not as the rows themselves.
 * ------------------------------------------------------------------ */
create table if not exists admin_audit_log (
  id         bigserial   primary key,
  at         timestamptz not null default now(),
  actor      text,
  action     text        not null,
  detail     text,
  ip_hash    text,
  user_agent text
);

create index if not exists admin_audit_log_at_idx     on admin_audit_log (at desc);
create index if not exists admin_audit_log_action_idx on admin_audit_log (action);