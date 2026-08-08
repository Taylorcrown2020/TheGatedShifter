import express from 'express';
import crypto from 'node:crypto';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { pool, query, healthcheck } from './src/db.js';
import { runMigrations } from './src/migrate.js';
import {
  mailerConfigured,
  sendMemberConfirmation,
  notifyPrivateInbox,
  sendDeletionConfirmation,
  upsertBrevoContact,
  deleteBrevoContact,
} from './src/mailer.js';

const __dirname = dirname(fileURLToPath(import.meta.url));
const publicDir = join(__dirname, 'public');
const app = express();

const PORT = process.env.PORT || 10000;
const IP_SALT = process.env.IP_HASH_SALT || 'gatedshifter-dev-salt';
const CANONICAL_HOST = (process.env.CANONICAL_HOST || 'www.gatedshifter.co').toLowerCase();

app.set('trust proxy', 1); // Render terminates TLS at its load balancer
app.disable('x-powered-by');
app.use(express.json({ limit: '32kb' }));
app.use(express.urlencoded({ extended: false, limit: '32kb' }));

/* ------------------------------------------------------------------ *
 * Canonical host and HTTPS
 *
 * Every QR code points at https://www.gatedshifter.co/join.
 *
 * Only the .com is redirected here, and only because it never points at
 * Render. The apex .co and the http→https upgrade are handled by the
 * platform: Render designates one custom domain as primary and 301s the
 * others to it, and it already redirects http to https.
 *
 * Two systems redirecting the same host is what produces
 * ERR_TOO_MANY_REDIRECTS, so this file no longer touches either.
 * In Render → Settings → Custom Domains, www.gatedshifter.co must be the
 * primary domain, with gatedshifter.co redirecting to it.
 *
 * Set FORCE_CANONICAL_HOST=true only if the platform cannot do it, and if
 * you do, turn Render's own redirect off first.
 * ------------------------------------------------------------------ */
const FORCE_CANONICAL_HOST = process.env.FORCE_CANONICAL_HOST === 'true';

const REDIRECT_HOSTS = new Set(['gatedshifter.com', 'www.gatedshifter.com']);

app.use((req, res, next) => {
  const host = (req.headers.host || '').toLowerCase().split(':')[0];
  const proto = (req.get('x-forwarded-proto') || req.protocol || '').toLowerCase();

  const wrongDomain = REDIRECT_HOSTS.has(host);
  const wrongHost = FORCE_CANONICAL_HOST && host.endsWith('gatedshifter.co') && host !== CANONICAL_HOST;

  if (wrongDomain || wrongHost) {
    return res.redirect(301, `https://${CANONICAL_HOST}${req.originalUrl}`);
  }

  // Sent only when the request genuinely arrived over TLS. Announcing HSTS
  // on a plain-http request is how a misconfigured proxy turns into a loop.
  if (proto === 'https') {
    res.setHeader('Strict-Transport-Security', 'max-age=31536000; includeSubDomains');
  }

  next();
});

/* ------------------------------------------------------------------ *
 * Security headers
 * ------------------------------------------------------------------ */
app.use((_req, res, next) => {
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('X-Frame-Options', 'DENY');
  res.setHeader('Referrer-Policy', 'strict-origin-when-cross-origin');
  res.setHeader('Permissions-Policy', 'geolocation=(), microphone=(), camera=()');
  res.setHeader(
    'Content-Security-Policy',
    [
      "default-src 'self'",
      "script-src 'self' 'unsafe-inline'",
      "connect-src 'self'",
      "img-src 'self' data:",
      "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com",
      "font-src 'self' https://fonts.gstatic.com",
      "form-action 'self'",
      "frame-ancestors 'none'",
      "base-uri 'self'",
      'upgrade-insecure-requests',
    ].join('; ')
  );
  next();
});

/* ------------------------------------------------------------------ *
 * Rate limiting — in-memory, sized for a single instance
 * ------------------------------------------------------------------ */
const hits = new Map();
const WINDOW_MS = 10 * 60 * 1000;
const MAX_PER_WINDOW = 20; // a tablet enrolling a queue of people is normal

setInterval(() => {
  const cutoff = Date.now() - WINDOW_MS;
  for (const [key, times] of hits) {
    const kept = times.filter((t) => t > cutoff);
    if (kept.length) hits.set(key, kept);
    else hits.delete(key);
  }
}, WINDOW_MS).unref();

function rateLimited(ip) {
  const now = Date.now();
  const times = (hits.get(ip) || []).filter((t) => t > now - WINDOW_MS);
  times.push(now);
  hits.set(ip, times);
  return times.length > MAX_PER_WINDOW;
}

/* ------------------------------------------------------------------ *
 * Validation
 * ------------------------------------------------------------------ */
const EMAIL_RE = /^[^\s@]+@[^\s@]+\.[a-z]{2,}$/i;

const MEMBER_TYPES = ['Collector', 'Specialist', 'Partner'];

const INTENTS = [
  'Buy a vehicle',
  'Sell a vehicle discreetly',
  'Find a trusted specialist',
  'Source parts',
  'Vehicle valuation',
  'Provenance / documentation',
  'Collector events & experiences',
  'Connect with other collectors',
  'Offer specialist services',
  'Explore a partnership',
  'Just exploring',
];

const clean = (value, max) => (typeof value === 'string' ? value.trim().replace(/\s+/g, ' ').slice(0, max) : '');
const cleanMultiline = (value, max) => (typeof value === 'string' ? value.trim().slice(0, max) : '');
const truthy = (value) => value === true || value === 'true' || value === 'on' || value === 1;

// Tracking values arrive from the URL, so they are never trusted as text —
// each one is reduced to a short slug before it goes near the database.
const slug = (value, fallback = '') => {
  const out = clean(value, 40).toLowerCase().replace(/[^a-z0-9_.-]/g, '');
  return out || fallback;
};

function validate(body) {
  const memberType = clean(body.member_type, 20);
  const intents = Array.isArray(body.looking_for_now)
    ? body.looking_for_now.filter((item) => INTENTS.includes(item)).slice(0, INTENTS.length)
    : [];

  const data = {
    member_type: MEMBER_TYPES.includes(memberType) ? memberType : '',
    first_name: clean(body.first_name, 80),
    last_name: clean(body.last_name, 80),
    email: clean(body.email, 254).toLowerCase(),
    mobile_phone: clean(body.mobile_phone, 40),
    city: clean(body.city, 120),
    state_region: clean(body.state_region, 120),
    country: clean(body.country, 80),
    primary_marques: cleanMultiline(body.primary_marques, 600),
    looking_for_now: [...new Set(intents)],
    additional_notes: cleanMultiline(body.additional_notes, 2000),
    privacy_consent: truthy(body.privacy_consent) || truthy(body.consent),
    marketing_consent: truthy(body.marketing_consent),
    source: slug(body.source, 'web'),
    channel: slug(body.channel, 'web'),
    campaign: slug(body.campaign),
    placement: slug(body.placement),
    captured_by: slug(body.captured_by),
    referral_code: slug(body.referral_code),
    page_path: clean(body.page_path, 200),
  };

  const errors = {};
  if (!data.member_type) errors.member_type = 'Choose Collector, Specialist or Partner.';
  if (data.first_name.length < 1) errors.first_name = 'Enter a first name.';
  if (data.last_name.length < 1) errors.last_name = 'Enter a last name.';
  if (!EMAIL_RE.test(data.email)) errors.email = 'Enter an email address we can reply to.';
  if (data.mobile_phone && data.mobile_phone.replace(/\D/g, '').length < 7) {
    errors.mobile_phone = 'Enter a mobile number with at least 7 digits, or leave it blank.';
  }
  if (!data.privacy_consent) {
    errors.privacy_consent = 'Please confirm we may contact you about your request.';
  }

  return { data, errors };
}

const hashEmail = (email) => crypto.createHash('sha256').update(IP_SALT + email).digest('hex');

/* ------------------------------------------------------------------ *
 * POST /api/intake — record a Founding Access request
 * ------------------------------------------------------------------ */
app.post('/api/intake', async (req, res) => {
  const ip = req.ip || '0.0.0.0';

  // Honeypot: a hidden field real people never fill in. Answer as though
  // it worked so a script learns nothing, and write nothing.
  if (clean(req.body.company_website, 200)) {
    return res.status(202).json({ ok: true });
  }

  // Timing check: a form completed in under two seconds is a script.
  const elapsed = Number(req.body.elapsed_ms || 0);
  if (elapsed && elapsed < 2000) {
    return res.status(202).json({ ok: true });
  }

  if (rateLimited(ip)) {
    return res.status(429).json({
      ok: false,
      message: 'Too many requests from this connection. Wait a moment and try again.',
    });
  }

  const { data, errors } = validate(req.body);
  if (Object.keys(errors).length) {
    return res.status(400).json({ ok: false, errors });
  }

  const fullName = [data.first_name, data.last_name].filter(Boolean).join(' ');
  const ipHash = crypto.createHash('sha256').update(IP_SALT + ip).digest('hex');
  const userAgent = clean(req.get('user-agent'), 400);

  try {
    /* A double-tap, a retried request after a dropped connection, or an
     * impatient second Submit all arrive as the same person within
     * seconds. That is treated as the same intake — the earlier record is
     * returned as a success. A genuine second visit later in the week is
     * a new record. */
    const { rows: recent } = await query(
      `select id
         from member_intake
        where lower(email) = $1
          and created_at > now() - interval '2 minutes'
        order by created_at desc
        limit 1`,
      [data.email]
    );

    if (recent.length) {
      console.log(`Rapid repeat submit ignored for ${data.email} (record #${recent[0].id})`);
      return res.status(200).json({ ok: true, duplicate: true });
    }

    /* A returning email is never rejected and never overwrites the earlier
     * record: the new submission is kept in full and flagged REVIEW so the
     * new intent can be merged by a person. */
    const { rows: seen } = await query(
      `select 1 from member_intake where lower(email) = $1 limit 1`,
      [data.email]
    );
    const status = seen.length ? 'REVIEW' : 'NEW';

    const { rows } = await query(
      `insert into member_intake
         (full_name, first_name, last_name, email, mobile_phone, city, state_region, country,
          member_type, primary_marques, looking_for_now, additional_notes,
          consent, privacy_consent, marketing_consent, consent_timestamp,
          founding_access, status,
          source, channel, campaign, placement, captured_by, referral_code,
          page_path, user_agent, ip_hash)
       values ($1,$2,$3,$4,$5,$6,$7,$8,
               $9,$10,$11,$12,
               $13,$13,$14,now(),
               true,$15,
               $16,$17,$18,$19,$20,$21,
               $22,$23,$24)
       returning id, created_at, delete_token, status, founding_access`,
      [
        fullName,
        data.first_name,
        data.last_name,
        data.email,
        data.mobile_phone || null,
        data.city || null,
        data.state_region || null,
        data.country || null,
        data.member_type,
        data.primary_marques || null,
        data.looking_for_now,
        data.additional_notes || null,
        data.privacy_consent,
        data.marketing_consent,
        status,
        data.source,
        data.channel,
        data.campaign || null,
        data.placement || null,
        data.captured_by || null,
        data.referral_code || null,
        data.page_path || null,
        userAgent || null,
        ipHash,
      ]
    );

    const record = { ...data, ...rows[0] };
    console.log(
      `Intake #${record.id} recorded — ${data.member_type} / ${data.source}/${data.channel}` +
        `${data.placement ? '/' + data.placement : ''} (${record.status})`
    );

    // The member is already saved. Email is sent after the response so a
    // slow provider never holds up the next person at the tablet.
    res.status(201).json({ ok: true });

    dispatchEmails(record).catch((err) => console.error('Email dispatch failed:', err.message));
    return undefined;
  } catch (err) {
    console.error('Intake insert failed:', err.message);
    return res.status(503).json({
      ok: false,
      message: 'We couldn’t complete your enrollment. Please try again.',
    });
  }
});

/**
 * Confirmation to the member, notification to private@, contact record in
 * Brevo. Each is independent — one failing does not stop the others, and
 * none of them can fail the enrollment.
 */
async function dispatchEmails(record) {
  if (!mailerConfigured) {
    console.warn(`BREVO_API_KEY not set — no email sent for intake #${record.id}`);
    return;
  }

  const results = await Promise.allSettled([
    sendMemberConfirmation(record),
    notifyPrivateInbox(record),
    upsertBrevoContact(record),
  ]);

  const [confirmation] = results;

  if (confirmation.status === 'fulfilled') {
    await query('update member_intake set confirmation_sent_at = now(), last_email_error = null where id = $1', [
      record.id,
    ]).catch(() => {});
  } else {
    console.error(`Confirmation email failed for intake #${record.id}:`, confirmation.reason.message);
    await query('update member_intake set last_email_error = $2 where id = $1', [
      record.id,
      String(confirmation.reason.message).slice(0, 400),
    ]).catch(() => {});
  }

  results.slice(1).forEach((result, index) => {
    if (result.status === 'rejected') {
      console.error(
        `${index === 0 ? 'Internal notification' : 'Brevo contact upsert'} failed for intake #${record.id}:`,
        result.reason.message
      );
    }
  });
}

/* ------------------------------------------------------------------ *
 * POST /api/remove — the member deletes their own record
 *
 * The email footer links to /remove?t=<token>, which asks for a
 * confirmation and then calls this. Deletion is never on a GET, so an
 * email client prefetching the link cannot remove anyone.
 * ------------------------------------------------------------------ */
app.post('/api/remove', async (req, res) => {
  const token = clean(req.body.token, 60);
  if (!/^[0-9a-f-]{36}$/i.test(token)) {
    return res.status(404).json({ ok: false, message: 'This link is no longer valid.' });
  }

  if (rateLimited(`remove:${req.ip || '0.0.0.0'}`)) {
    return res.status(429).json({ ok: false, message: 'Too many attempts. Wait a moment and try again.' });
  }

  try {
    const { rows } = await query(
      `delete from member_intake
        where delete_token = $1
       returning id, email, first_name, created_at, source, channel`,
      [token]
    );

    if (!rows.length) {
      return res.status(404).json({ ok: false, message: 'This link is no longer valid.' });
    }

    const removed = rows[0];

    // The log evidences the deletion without keeping the person: a salted
    // hash of the email, and nothing else that identifies them.
    await query(
      `insert into member_removal_log (email_hash, record_created_at, source, channel)
       values ($1, $2, $3, $4)`,
      [hashEmail(removed.email), removed.created_at, removed.source, removed.channel]
    ).catch((err) => console.error('Removal log write failed:', err.message));

    console.log(`Record #${removed.id} deleted at the member's request`);

    res.status(200).json({ ok: true });

    if (mailerConfigured) {
      Promise.allSettled([
        deleteBrevoContact(removed.email),
        sendDeletionConfirmation(removed),
      ]).then((results) => {
        results.forEach((result) => {
          if (result.status === 'rejected') {
            console.error(`Deletion follow-up failed for #${removed.id}:`, result.reason.message);
          }
        });
      });
    }

    return undefined;
  } catch (err) {
    console.error('Deletion failed:', err.message);
    return res.status(503).json({
      ok: false,
      message: 'We couldn’t complete the deletion. Please try again, or write to private@gatedshifter.co.',
    });
  }
});

/* ------------------------------------------------------------------ *
 * GET /api/intake.csv — token-gated export, off unless the token is set
 * ------------------------------------------------------------------ */
app.get('/api/intake.csv', async (req, res) => {
  const expected = process.env.ADMIN_EXPORT_TOKEN;
  const supplied = String(req.get('x-export-token') || req.query.token || '');

  if (
    !expected ||
    supplied.length !== expected.length ||
    !crypto.timingSafeEqual(Buffer.from(supplied), Buffer.from(expected))
  ) {
    return res.status(404).end();
  }

  try {
    const { rows } = await query(
      `select id,
              to_char(created_at, 'YYYY-MM-DD HH24:MI:SS') as created_at_utc,
              member_type, first_name, last_name, email, mobile_phone,
              city, state_region, country,
              primary_marques,
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

    const escape = (value) => `"${String(value ?? '').replace(/"/g, '""')}"`;
    const header = Object.keys(rows[0] || { id: '' }).join(',');
    const csv = [header, ...rows.map((row) => Object.values(row).map(escape).join(','))].join('\n');
    const stamp = new Date().toISOString().slice(0, 10);

    res.setHeader('Content-Type', 'text/csv; charset=utf-8');
    res.setHeader('Content-Disposition', `attachment; filename="member_intake_${stamp}.csv"`);
    return res.send(csv);
  } catch (err) {
    console.error('CSV export failed:', err.message);
    return res.status(503).json({ ok: false, message: 'Export unavailable.' });
  }
});

/* ------------------------------------------------------------------ *
 * Health check — Render pings this to confirm the instance is live
 * ------------------------------------------------------------------ */
app.get('/healthz', async (_req, res) => {
  try {
    await healthcheck();
    res.json({ ok: true, db: 'up', mail: mailerConfigured ? 'configured' : 'unconfigured' });
  } catch (err) {
    res.status(503).json({ ok: false, db: 'down', error: err.message });
  }
});

/* ------------------------------------------------------------------ *
 * Pages
 * ------------------------------------------------------------------ */
app.use(
  express.static(publicDir, {
    extensions: ['html'],
    maxAge: '1h',
    setHeaders(res, path) {
      if (path.endsWith('.html')) res.setHeader('Cache-Control', 'no-store');
    },
  })
);

const page = (file) => (_req, res) => {
  res.setHeader('Cache-Control', 'no-store');
  res.sendFile(join(publicDir, file));
};

// /join is the URL on every QR code and on the tablet.
app.get('/join', page('join.html'));
app.get('/remove', page('remove.html'));
app.get('/privacy', page('privacy.html'));
app.get('/', page('index.html'));

app.use((_req, res) => {
  res.status(404);
  return page('index.html')(_req, res);
});

/* ------------------------------------------------------------------ *
 * Boot
 * ------------------------------------------------------------------ */
process.on('unhandledRejection', (reason) => {
  console.error('Unhandled rejection:', reason instanceof Error ? reason.message : reason);
});

async function start() {
  if (process.env.DATABASE_URL) {
    try {
      await runMigrations();
    } catch (err) {
      // Serve the pages even if migrations fail — a broken database should
      // not take the site down mid-event. Submissions return 503 and log.
      console.error('Startup migrations failed:', err.message);
    }
  }

  const server = app.listen(PORT, '0.0.0.0', () => {
    console.log(`The Gated Shifter listening on 0.0.0.0:${PORT}`);
    if (!mailerConfigured) console.warn('BREVO_API_KEY is not set — confirmation email is disabled.');
  });

  const shutdown = async (signal) => {
    console.log(`${signal} received, shutting down.`);
    server.close(async () => {
      await pool.end().catch(() => {});
      process.exit(0);
    });
    setTimeout(() => process.exit(1), 10_000).unref();
  };

  process.on('SIGTERM', () => shutdown('SIGTERM'));
  process.on('SIGINT', () => shutdown('SIGINT'));
}

start();