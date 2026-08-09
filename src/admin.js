/**
 * The Gated Shifter — administrative export portal.
 *
 * One job: let a named operator sign in and download the member_intake
 * export, with every sign-in and every download recorded.
 *
 * Access controls implemented here:
 *   - Credentials stored as scrypt hashes with a per-row salt.
 *   - Server-side sessions (revocable), 30 minute idle / 12 hour absolute
 *     expiry, opaque random token, only its hash persisted.
 *   - Cookie is HttpOnly, SameSite=Strict, Secure behind TLS.
 *   - Failed logins counted per account; 5 failures locks it for 15
 *     minutes. Login responses never reveal whether the email exists.
 *   - Every login, logout, lockout and export written to admin_audit_log.
 *   - The export is a GET, but it is session-gated, never token-in-URL.
 *
 * SOC 2 is an audit of an organisation, not a property of a file. These
 * are the technical controls that a CC6 (logical access) and CC7
 * (monitoring) review asks to see. The remaining gaps are listed in
 * ADMIN-NOTES.md.
 */

import crypto from 'node:crypto';
import express from 'express';
import { pool, query } from './db.js';

const SESSION_COOKIE = 'gs_admin';
const IDLE_MS = 30 * 60 * 1000; //  signed out after 30 minutes of inactivity
const ABSOLUTE_MS = 12 * 60 * 60 * 1000; // and after 12 hours regardless
const MAX_FAILED = 5;
const LOCK_MS = 15 * 60 * 1000;
const MIN_PASSWORD = 12;

const IP_SALT = process.env.IP_HASH_SALT || 'gatedshifter-dev-salt';

const sha256 = (value) => crypto.createHash('sha256').update(String(value)).digest('hex');
const hashIp = (ip) => sha256(IP_SALT + (ip || ''));
const clean = (value, max) => (typeof value === 'string' ? value.trim().slice(0, max) : '');

/* ------------------------------------------------------------------ *
 * Passwords
 * ------------------------------------------------------------------ */
const SCRYPT = { N: 16384, r: 8, p: 1, keylen: 64, maxmem: 64 * 1024 * 1024 };

export function hashPassword(password) {
  if (String(password).length < MIN_PASSWORD) {
    throw new Error(`Password must be at least ${MIN_PASSWORD} characters.`);
  }
  const salt = crypto.randomBytes(16);
  const key = crypto.scryptSync(password, salt, SCRYPT.keylen, SCRYPT);
  return ['scrypt', SCRYPT.N, SCRYPT.r, SCRYPT.p, salt.toString('hex'), key.toString('hex')].join('$');
}

export function verifyPassword(password, stored) {
  const parts = String(stored || '').split('$');
  if (parts.length !== 6 || parts[0] !== 'scrypt') return false;

  const [, N, r, p, saltHex, keyHex] = parts;
  const expected = Buffer.from(keyHex, 'hex');
  try {
    const actual = crypto.scryptSync(password, Buffer.from(saltHex, 'hex'), expected.length, {
      N: Number(N),
      r: Number(r),
      p: Number(p),
      maxmem: SCRYPT.maxmem,
    });
    return actual.length === expected.length && crypto.timingSafeEqual(actual, expected);
  } catch {
    return false;
  }
}

/* ------------------------------------------------------------------ *
 * Audit trail
 * ------------------------------------------------------------------ */
export async function audit(action, { actor = null, detail = null, req = null } = {}) {
  try {
    await query(
      `insert into admin_audit_log (actor, action, detail, ip_hash, user_agent)
       values ($1, $2, $3, $4, $5)`,
      [
        actor,
        action,
        detail ? String(detail).slice(0, 500) : null,
        req ? hashIp(req.ip) : null,
        req ? clean(req.get('user-agent'), 300) : null,
      ]
    );
  } catch (err) {
    // An unwritable audit row must never break the request, but it must
    // be visible in the platform logs.
    console.error(`Audit write failed (${action}):`, err.message);
  }
}

/* ------------------------------------------------------------------ *
 * Sessions
 * ------------------------------------------------------------------ */
function readCookie(req, name) {
  const header = req.headers.cookie || '';
  for (const part of header.split(';')) {
    const [key, ...rest] = part.trim().split('=');
    if (key === name) return decodeURIComponent(rest.join('='));
  }
  return '';
}

const isSecure = (req) => (req.get('x-forwarded-proto') || req.protocol || '').toLowerCase() === 'https';

function setSessionCookie(req, res, token) {
  const bits = [
    `${SESSION_COOKIE}=${token}`,
    'Path=/',
    'HttpOnly',
    'SameSite=Strict',
    `Max-Age=${Math.floor(ABSOLUTE_MS / 1000)}`,
  ];
  if (isSecure(req)) bits.push('Secure');
  res.setHeader('Set-Cookie', bits.join('; '));
}

function clearSessionCookie(req, res) {
  const bits = [`${SESSION_COOKIE}=`, 'Path=/', 'HttpOnly', 'SameSite=Strict', 'Max-Age=0'];
  if (isSecure(req)) bits.push('Secure');
  res.setHeader('Set-Cookie', bits.join('; '));
}

async function createSession(userId, req) {
  const token = crypto.randomBytes(32).toString('base64url');
  await query(
    `insert into admin_sessions (token_hash, user_id, expires_at, ip_hash, user_agent)
     values ($1, $2, now() + ($3 || ' milliseconds')::interval, $4, $5)`,
    [sha256(token), userId, String(ABSOLUTE_MS), hashIp(req.ip), clean(req.get('user-agent'), 300)]
  );
  return token;
}

/**
 * Resolves the session on every admin request and slides the idle window
 * forward. Returns null for anything expired, revoked, idle too long, or
 * belonging to a disabled account.
 */
async function currentAdmin(req) {
  const token = readCookie(req, SESSION_COOKIE);
  if (!token || token.length < 20) return null;

  const { rows } = await query(
    `select s.token_hash, u.id, u.email, u.last_login_at
       from admin_sessions s
       join admin_users u on u.id = s.user_id
      where s.token_hash = $1
        and s.revoked_at is null
        and s.expires_at > now()
        and s.last_seen_at > now() - ($2 || ' milliseconds')::interval
        and u.disabled_at is null
      limit 1`,
    [sha256(token), String(IDLE_MS)]
  );

  if (!rows.length) return null;

  await query('update admin_sessions set last_seen_at = now() where token_hash = $1', [rows[0].token_hash]).catch(
    () => {}
  );

  return { id: rows[0].id, email: rows[0].email, lastLoginAt: rows[0].last_login_at };
}

async function requireAdmin(req, res, next) {
  try {
    const admin = await currentAdmin(req);
    if (!admin) {
      clearSessionCookie(req, res);
      return res.status(401).json({ ok: false, message: 'Sign in to continue.' });
    }
    req.admin = admin;
    return next();
  } catch (err) {
    console.error('Admin session lookup failed:', err.message);
    return res.status(503).json({ ok: false, message: 'Service unavailable.' });
  }
}

/**
 * State-changing admin calls must carry this header. A cross-site form
 * post cannot set it, and the cookie is SameSite=Strict, so the two
 * together close off CSRF without a token round-trip.
 */
function requireFetch(req, res, next) {
  if (req.get('x-gs-admin') !== '1') {
    return res.status(400).json({ ok: false, message: 'Bad request.' });
  }
  return next();
}

/* ------------------------------------------------------------------ *
 * Login throttling, on top of the per-account lockout
 * ------------------------------------------------------------------ */
const attempts = new Map();
const ATTEMPT_WINDOW_MS = 15 * 60 * 1000;
const ATTEMPTS_PER_IP = 20;

setInterval(() => {
  const cutoff = Date.now() - ATTEMPT_WINDOW_MS;
  for (const [key, times] of attempts) {
    const kept = times.filter((t) => t > cutoff);
    if (kept.length) attempts.set(key, kept);
    else attempts.delete(key);
  }
}, ATTEMPT_WINDOW_MS).unref();

function tooManyAttempts(ip) {
  const now = Date.now();
  const times = (attempts.get(ip) || []).filter((t) => t > now - ATTEMPT_WINDOW_MS);
  times.push(now);
  attempts.set(ip, times);
  return times.length > ATTEMPTS_PER_IP;
}

/* ------------------------------------------------------------------ *
 * CSV export — the one thing this portal exists to do.
 * Shared with the legacy token endpoint in server.js so the two can
 * never drift apart.
 * ------------------------------------------------------------------ */
export async function buildIntakeCsv() {
  const { rows } = await query(
    `select id,
            to_char(created_at, 'YYYY-MM-DD HH24:MI:SS') as created_at_utc,
            member_type, first_name, last_name, email, mobile_phone,
            city, state_region, country,
            primary_marques, collection_size, defining_vehicle, referred_by,
            specialist_needs as discipline, workshop_practice, proud_work, vouch_referral,
            partner_specialty as organization, partner_area, partnership_notes,
            apparel_size, array_to_string(apparel_items, ' | ') as apparel_items,
            array_to_string(looking_for_now, ' | ') as looking_for_now,
            additional_notes,
            founding_access, status,
            privacy_consent, marketing_consent,
            to_char(consent_timestamp, 'YYYY-MM-DD HH24:MI:SS') as consent_timestamp_utc,
            source, channel, campaign, placement, captured_by, referral_code,
            to_char(confirmation_sent_at, 'YYYY-MM-DD HH24:MI:SS') as confirmation_sent_at_utc
       from member_intake
      order by created_at desc`
  );

  const columns = [
    'id',
    'created_at_utc',
    'member_type',
    'first_name',
    'last_name',
    'email',
    'mobile_phone',
    'city',
    'state_region',
    'country',
    'primary_marques',
    'collection_size',
    'defining_vehicle',
    'referred_by',
    'discipline',
    'workshop_practice',
    'proud_work',
    'vouch_referral',
    'organization',
    'partner_area',
    'partnership_notes',
    'apparel_items',
    'apparel_size',
    'looking_for_now',
    'additional_notes',
    'founding_access',
    'status',
    'privacy_consent',
    'marketing_consent',
    'consent_timestamp_utc',
    'source',
    'channel',
    'campaign',
    'placement',
    'captured_by',
    'referral_code',
    'confirmation_sent_at_utc',
  ];

  // Leading apostrophe on anything a spreadsheet would treat as a formula.
  const escape = (value) => {
    let out = String(value ?? '');
    if (/^[=+\-@\t\r]/.test(out)) out = `'${out}`;
    return `"${out.replace(/"/g, '""')}"`;
  };

  const body = rows.map((row) => columns.map((key) => escape(row[key])).join(','));
  return { csv: [columns.join(','), ...body].join('\n'), count: rows.length };
}

/* ------------------------------------------------------------------ *
 * Routes
 * ------------------------------------------------------------------ */
export const adminRouter = express.Router();

adminRouter.use('/api/admin', (_req, res, next) => {
  res.setHeader('Cache-Control', 'no-store');
  next();
});

adminRouter.post('/api/admin/login', requireFetch, async (req, res) => {
  const email = clean(req.body?.email, 254).toLowerCase();
  const password = typeof req.body?.password === 'string' ? req.body.password : '';
  const generic = { ok: false, message: 'That email and password do not match an account.' };

  if (tooManyAttempts(`login:${req.ip || '0.0.0.0'}`)) {
    await audit('login.throttled', { actor: email || null, req });
    return res.status(429).json({ ok: false, message: 'Too many attempts. Wait 15 minutes and try again.' });
  }

  if (!email || !password) return res.status(400).json(generic);

  try {
    const { rows } = await query(
      `select id, email, password_hash, locked_until, disabled_at, failed_attempts, last_login_at
         from admin_users
        where lower(email) = $1
        limit 1`,
      [email]
    );

    const user = rows[0];

    // Same shape of work and the same answer whether or not the account
    // exists, so the response cannot be used to enumerate operators.
    if (!user || user.disabled_at) {
      verifyPassword(password, hashPassword('placeholder-not-a-real-secret'));
      await audit('login.failure', { actor: email, detail: user ? 'account disabled' : 'no such account', req });
      return res.status(401).json(generic);
    }

    if (user.locked_until && new Date(user.locked_until) > new Date()) {
      await audit('login.locked', { actor: user.email, req });
      return res.status(423).json({
        ok: false,
        message: 'This account is temporarily locked after repeated failed sign-ins. Try again in 15 minutes.',
      });
    }

    if (!verifyPassword(password, user.password_hash)) {
      const failed = Number(user.failed_attempts || 0) + 1;
      const lock = failed >= MAX_FAILED;
      await query(
        `update admin_users
            set failed_attempts = $2,
                locked_until = case when $3 then now() + ($4 || ' milliseconds')::interval else locked_until end
          where id = $1`,
        [user.id, lock ? 0 : failed, lock, String(LOCK_MS)]
      );
      await audit(lock ? 'login.lockout' : 'login.failure', {
        actor: user.email,
        detail: `attempt ${failed} of ${MAX_FAILED}`,
        req,
      });
      return res.status(401).json(generic);
    }

    const token = await createSession(user.id, req);
    await query(
      `update admin_users set last_login_at = now(), failed_attempts = 0, locked_until = null where id = $1`,
      [user.id]
    );
    await audit('login.success', { actor: user.email, req });

    setSessionCookie(req, res, token);
    return res.json({ ok: true, email: user.email, previous_login_at: user.last_login_at });
  } catch (err) {
    console.error('Admin login failed:', err.message);
    return res.status(503).json({ ok: false, message: 'Service unavailable. Try again shortly.' });
  }
});

adminRouter.post('/api/admin/logout', requireFetch, async (req, res) => {
  const token = readCookie(req, SESSION_COOKIE);
  if (token) {
    const { rows } = await query(
      `update admin_sessions s
          set revoked_at = now()
        where s.token_hash = $1
          and s.revoked_at is null
      returning (select email from admin_users u where u.id = s.user_id) as email`,
      [sha256(token)]
    ).catch(() => ({ rows: [] }));
    if (rows.length) await audit('logout', { actor: rows[0].email, req });
  }
  clearSessionCookie(req, res);
  return res.json({ ok: true });
});

adminRouter.get('/api/admin/session', async (req, res) => {
  try {
    const admin = await currentAdmin(req);
    if (!admin) return res.status(401).json({ ok: false });
    return res.json({ ok: true, email: admin.email, last_login_at: admin.lastLoginAt });
  } catch (err) {
    console.error('Admin session check failed:', err.message);
    return res.status(503).json({ ok: false });
  }
});

/** Counts only — no member personal data leaves this endpoint. */
adminRouter.get('/api/admin/summary', requireAdmin, async (_req, res) => {
  try {
    const [{ rows: totals }, { rows: byType }, { rows: recent }] = await Promise.all([
      query(`select count(*)::int as total,
                    count(*) filter (where status = 'NEW')::int as new_count,
                    count(*) filter (where status = 'REVIEW')::int as review_count,
                    count(*) filter (where confirmation_sent_at is null)::int as unconfirmed_count,
                    to_char(max(created_at), 'YYYY-MM-DD HH24:MI') as latest_utc
               from member_intake`),
      query(`select member_type, count(*)::int as count
               from member_intake group by member_type order by member_type`),
      query(`select count(*)::int as count
               from member_intake where created_at > now() - interval '7 days'`),
    ]);

    return res.json({
      ok: true,
      total: totals[0].total,
      new_count: totals[0].new_count,
      review_count: totals[0].review_count,
      unconfirmed_count: totals[0].unconfirmed_count,
      latest_utc: totals[0].latest_utc,
      last_seven_days: recent[0].count,
      by_type: byType,
    });
  } catch (err) {
    console.error('Admin summary failed:', err.message);
    return res.status(503).json({ ok: false, message: 'Summary unavailable.' });
  }
});

adminRouter.get('/api/admin/export.csv', requireAdmin, async (req, res) => {
  try {
    const { csv, count } = await buildIntakeCsv();
    await audit('export.csv', { actor: req.admin.email, detail: `${count} records`, req });

    const stamp = new Date().toISOString().slice(0, 10);
    res.setHeader('Content-Type', 'text/csv; charset=utf-8');
    res.setHeader('Content-Disposition', `attachment; filename="member_intake_${stamp}.csv"`);
    return res.send(csv);
  } catch (err) {
    console.error('Admin CSV export failed:', err.message);
    return res.status(503).json({ ok: false, message: 'Export unavailable.' });
  }
});

/** The last 50 audit entries, so the client can see their own access history. */
adminRouter.get('/api/admin/audit', requireAdmin, async (_req, res) => {
  try {
    const { rows } = await query(
      `select to_char(at, 'YYYY-MM-DD HH24:MI') as at_utc, actor, action, detail
         from admin_audit_log
        order by at desc
        limit 50`
    );
    return res.json({ ok: true, entries: rows });
  } catch (err) {
    console.error('Audit read failed:', err.message);
    return res.status(503).json({ ok: false });
  }
});

/* ------------------------------------------------------------------ *
 * Housekeeping — expired sessions are not kept around
 * ------------------------------------------------------------------ */
export function startSessionReaper() {
  const sweep = () =>
    query(`delete from admin_sessions where expires_at < now() - interval '7 days'`).catch(() => {});
  sweep();
  return setInterval(sweep, 6 * 60 * 60 * 1000).unref();
}

/* ------------------------------------------------------------------ *
 * First operator. Set ADMIN_BOOTSTRAP_EMAIL and ADMIN_BOOTSTRAP_PASSWORD
 * to create one account on the next deploy, then delete both variables —
 * the account persists in the database without them.
 * ------------------------------------------------------------------ */
export async function ensureBootstrapAdmin() {
  const email = clean(process.env.ADMIN_BOOTSTRAP_EMAIL, 254).toLowerCase();
  const password = process.env.ADMIN_BOOTSTRAP_PASSWORD || '';
  if (!email || !password) return;

  const { rows } = await query('select count(*)::int as count from admin_users where disabled_at is null');
  if (rows[0].count > 0) {
    console.warn(
      'ADMIN_BOOTSTRAP_* is still set but an admin account already exists — ignoring. Remove both variables.'
    );
    return;
  }

  if (password.length < MIN_PASSWORD) {
    console.error(`ADMIN_BOOTSTRAP_PASSWORD is shorter than ${MIN_PASSWORD} characters — no account created.`);
    return;
  }

  await query('insert into admin_users (email, password_hash) values ($1, $2)', [email, hashPassword(password)]);
  await audit('user.created', { actor: email, detail: 'bootstrap from environment' });
  console.warn(`Admin account created for ${email}. Delete ADMIN_BOOTSTRAP_EMAIL and ADMIN_BOOTSTRAP_PASSWORD now.`);
}

/* ------------------------------------------------------------------ *
 * CLI:  npm run admin -- create  someone@example.com "long passphrase"
 *       npm run admin -- reset   someone@example.com "new passphrase"
 *       npm run admin -- disable someone@example.com
 *       npm run admin -- list
 *       npm run admin -- sessions:revoke someone@example.com
 * ------------------------------------------------------------------ */
async function cli(argv) {
  const [command, email, password] = argv;
  const address = (email || '').trim().toLowerCase();

  switch (command) {
    case 'create': {
      if (!address || !password) throw new Error('Usage: create <email> <password>');
      await query('insert into admin_users (email, password_hash) values ($1, $2)', [address, hashPassword(password)]);
      await audit('user.created', { actor: address, detail: 'created via CLI' });
      console.log(`Created ${address}.`);
      break;
    }
    case 'reset': {
      if (!address || !password) throw new Error('Usage: reset <email> <password>');
      const { rowCount } = await query(
        `update admin_users
            set password_hash = $2, password_changed_at = now(), failed_attempts = 0, locked_until = null
          where lower(email) = $1`,
        [address, hashPassword(password)]
      );
      if (!rowCount) throw new Error(`No account for ${address}.`);
      // A password change ends every existing session for that operator.
      await query(
        `update admin_sessions set revoked_at = now()
          where revoked_at is null
            and user_id = (select id from admin_users where lower(email) = $1)`,
        [address]
      );
      await audit('user.password_reset', { actor: address, detail: 'reset via CLI; sessions revoked' });
      console.log(`Password reset for ${address}. All of their sessions were signed out.`);
      break;
    }
    case 'disable': {
      if (!address) throw new Error('Usage: disable <email>');
      const { rowCount } = await query(
        'update admin_users set disabled_at = now() where lower(email) = $1 and disabled_at is null',
        [address]
      );
      if (!rowCount) throw new Error(`No active account for ${address}.`);
      await query(
        `update admin_sessions set revoked_at = now()
          where revoked_at is null
            and user_id = (select id from admin_users where lower(email) = $1)`,
        [address]
      );
      await audit('user.disabled', { actor: address, detail: 'disabled via CLI' });
      console.log(`Disabled ${address} and signed out their sessions.`);
      break;
    }
    case 'sessions:revoke': {
      if (!address) throw new Error('Usage: sessions:revoke <email>');
      const { rowCount } = await query(
        `update admin_sessions set revoked_at = now()
          where revoked_at is null
            and user_id = (select id from admin_users where lower(email) = $1)`,
        [address]
      );
      await audit('user.sessions_revoked', { actor: address, detail: `${rowCount} session(s)` });
      console.log(`Revoked ${rowCount} session(s) for ${address}.`);
      break;
    }
    case 'list': {
      const { rows } = await query(
        `select email,
                to_char(created_at, 'YYYY-MM-DD') as created,
                coalesce(to_char(last_login_at, 'YYYY-MM-DD HH24:MI'), 'never') as last_login,
                case when disabled_at is null then 'active' else 'disabled' end as state
           from admin_users order by email`
      );
      if (!rows.length) console.log('No admin accounts yet.');
      for (const row of rows) {
        console.log(`${row.email}\t${row.state}\tcreated ${row.created}\tlast login ${row.last_login}`);
      }
      break;
    }
    default:
      throw new Error('Commands: create | reset | disable | sessions:revoke | list');
  }
}

if (process.argv[1] && process.argv[1].endsWith('admin.js')) {
  cli(process.argv.slice(2))
    .then(() => pool.end())
    .catch(async (err) => {
      console.error(err.message);
      await pool.end().catch(() => {});
      process.exit(1);
    });
}