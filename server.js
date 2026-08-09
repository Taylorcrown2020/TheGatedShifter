import express from 'express';
import crypto from 'node:crypto';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { pool, query, healthcheck } from './src/db.js';
import { runMigrations } from './src/migrate.js';
import {
  adminRouter,
  buildIntakeCsv,
  ensureBootstrapAdmin,
  startSessionReaper,
} from './src/admin.js';
import {
  mailerConfigured,
  sendMemberConfirmation,
  sendApparelConfirmation,
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

/* Bumped whenever behaviour changes, so it is possible to tell from the
 * outside which code a deploy is actually running: curl /healthz, or read
 * the first line of the Render log. */
const BUILD = '2026-08-08 · delete-by-email · unique-email-across-paths · consent-required';

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
const MAX_PER_WINDOW = 40; // one tablet enrolling a queue shares a single IP

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

/* ------------------------------------------------------------------ *
 * Duplicate policy — one record per email.
 *
 *   Collector / Specialist / Partner   one record per address, across all
 *                                      three. An address used for any
 *                                      membership application cannot be
 *                                      used for another one.
 *   Apparel                            counted on its own. An existing
 *                                      member can register apparel
 *                                      interest once — which is what the
 *                                      button in their confirmation email
 *                                      invites them to do — but not twice.
 *
 * Enforced here and, independently, by the two partial unique indexes in
 * migration 007, so nothing that bypasses this handler can create a
 * second record either.
 *
 * To make apparel share the same namespace (one record per address, full
 * stop), set APPAREL_COUNTED_SEPARATELY to false and drop
 * member_intake_apparel_email_unique.
 * ------------------------------------------------------------------ */
const APPAREL_COUNTED_SEPARATELY = true;

const MEMBER_TYPES = ['Collector', 'Specialist', 'Partner', 'Apparel'];

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

// Lot 01 / 02 / 03 controlled picks — kept short so a bad client can't
// stuff free text into what the admin views treat as a filterable field.
const COLLECTION_SIZES = [
  '1–3 automobiles',
  '4–10 automobiles',
  '11–25 automobiles',
  '25+ automobiles',
  // Earlier wording. Kept so a cached page or a printed QR journey that
  // lands on an old copy still submits instead of erroring.
  '1–3 cars',
  '4–10 cars',
  '11–25 cars',
  '25+ cars',
];
const DISCIPLINES = [
  'Restoration',
  'Mechanical / engine',
  'Bodywork & paint',
  'Upholstery & trim',
  'Detailing',
  'Historian / research',
  'Appraisal / valuation',
  'Transport / logistics',
  'Other',
];
const PARTNER_AREAS = [
  'Insurance',
  'Transport & logistics',
  'Auction & brokerage',
  'Storage & facilities',
  'Events & rallies',
  'Other',
  // Earlier wording, accepted for the same reason as above.
  'Transport',
  'Auction house',
  'Storage',
  'Events',
];

// Lot 04 — Apparel. An interest register: garments and a size, nothing else.
// No prices, no quantities, no payment fields exist anywhere in this flow.
const APPAREL_ITEMS = [
  'Shirts & polos',
  'Knitwear',
  'Outerwear & jackets',
  'Caps & headwear',
  'Driving gloves',
  'Scarves & accessories',
  'Luggage & leather',
  'Garage & workshop wear',
];
const APPAREL_SIZES = ['XS', 'S', 'M', 'L', 'XL', 'XXL', '3XL', 'Not sure yet'];

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

    // Lot 01 — Collector
    referred_by: clean(body.referred_by, 160),
    collection_size: clean(body.collection_size, 40),
    defining_vehicle: cleanMultiline(body.defining_vehicle, 600),

    // Lot 02 — Specialist (stored in the pre-existing specialist_needs column)
    discipline: clean(body.discipline, 40),
    workshop_practice: clean(body.workshop_practice, 200),
    proud_work: cleanMultiline(body.proud_work, 600),
    vouch_referral: clean(body.vouch_referral, 160),

    // Lot 03 — Partner (organization stored in the pre-existing partner_specialty column)
    organization: clean(body.organization, 160),
    partner_area: clean(body.partner_area, 40),
    partnership_notes: cleanMultiline(body.partnership_notes, 600),

    // Lot 04 — Apparel
    apparel_items: Array.isArray(body.apparel_items)
      ? [...new Set(body.apparel_items.filter((item) => APPAREL_ITEMS.includes(item)))]
      : [],
    apparel_size: clean(body.apparel_size, 20),
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

  if (data.member_type === 'Collector') {
    if (!data.city) errors.city = 'Enter a city and country.';
    if (!COLLECTION_SIZES.includes(data.collection_size)) errors.collection_size = 'Choose a collection size.';
  }

  if (data.member_type === 'Specialist') {
    if (!DISCIPLINES.includes(data.discipline)) errors.discipline = 'Choose a discipline.';
  }

  if (data.member_type === 'Partner') {
    if (!data.organization) errors.organization = 'Enter your company or institution.';
    if (!PARTNER_AREAS.includes(data.partner_area)) errors.partner_area = 'Choose an area.';
  }

  if (data.member_type === 'Apparel') {
    if (!data.apparel_items.length) errors.apparel_items = 'Choose at least one.';
    if (!APPAREL_SIZES.includes(data.apparel_size)) errors.apparel_size = 'Choose a size, or “Not sure yet”.';
  }

  return { data, errors };
}

const hashEmail = (email) => crypto.createHash('sha256').update(IP_SALT + email).digest('hex');

/** What a returning applicant is told. Never "already exists" alone — they
 * get the way to change or remove what is on file. */
function duplicateMessage(existingType) {
  const as = existingType ? ` as a ${existingType}` : '';
  return (
    `This email address is already registered${as}. We keep one record per person, so nothing further ` +
    'is needed. To change what we hold, reply to the confirmation email we sent you, or write to ' +
    'private@gatedshifter.co. The deletion link in that email removes your information entirely.'
  );
}

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

    /* One record per email. The membership paths share a single namespace,
     * so a Collector address cannot come back as a Specialist. Apparel is
     * counted on its own. The indexes in migration 007 enforce the same
     * thing, so a race between two simultaneous submissions still cannot
     * create a second record — it lands in the 23505 branch below. */
    const apparelSubmission = APPAREL_COUNTED_SEPARATELY && data.member_type === 'Apparel';

    const { rows: taken } = await query(
      apparelSubmission
        ? `select id, member_type from member_intake
            where lower(email) = $1 and member_type = 'Apparel' and duplicate_of is null limit 1`
        : `select id, member_type from member_intake
            where lower(email) = $1
              and duplicate_of is null
              ${APPAREL_COUNTED_SEPARATELY ? "and member_type is distinct from 'Apparel'" : ''}
            limit 1`,
      [data.email]
    );

    if (taken.length) {
      console.log(
        `Duplicate submission refused: ${data.email} as ${data.member_type} ` +
          `(existing record #${taken[0].id}, ${taken[0].member_type})`
      );
      return res.status(409).json({
        ok: false,
        errors: { email: 'This email address is already on file.' },
        message: duplicateMessage(taken[0].member_type),
      });
    }

    /* The address is new to this namespace but known in the other one — an
     * existing member registering apparel interest, or the reverse. Normal,
     * so the record is NEW rather than flagged for review. */
    const { rows: seen } = await query(
      `select member_type from member_intake where lower(email) = $1 limit 1`,
      [data.email]
    );
    if (seen.length) {
      console.log(`${data.email} already holds a ${seen[0].member_type} record — new ${data.member_type} record alongside it`);
    }
    const status = 'NEW';

    const { rows } = await query(
      `insert into member_intake
         (full_name, first_name, last_name, email, mobile_phone, city, state_region, country,
          member_type, primary_marques, looking_for_now, additional_notes,
          consent, privacy_consent, marketing_consent, consent_timestamp,
          founding_access, status,
          source, channel, campaign, placement, captured_by, referral_code,
          page_path, user_agent, ip_hash,
          referred_by, collection_size, defining_vehicle,
          specialist_needs, workshop_practice, proud_work, vouch_referral,
          partner_specialty, partner_area, partnership_notes,
          apparel_items, apparel_size)
       values ($1,$2,$3,$4,$5,$6,$7,$8,
               $9,$10,$11,$12,
               $13,$13,$14,now(),
               true,$15,
               $16,$17,$18,$19,$20,$21,
               $22,$23,$24,
               $25,$26,$27,
               $28,$29,$30,$31,
               $32,$33,$34,
               $35,$36)
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
        data.referred_by || null,
        data.collection_size || null,
        data.defining_vehicle || null,
        data.discipline || null,
        data.workshop_practice || null,
        data.proud_work || null,
        data.vouch_referral || null,
        data.organization || null,
        data.partner_area || null,
        data.partnership_notes || null,
        data.apparel_items,
        data.apparel_size || null,
      ]
    );

    /* The notification email reads the column names (specialist_needs,
     * partner_specialty), so both are carried alongside the form names.
     * Without this the Discipline and Organization lines were blank. */
    const record = {
      ...data,
      specialist_needs: data.discipline,
      partner_specialty: data.organization,
      ...rows[0],
    };
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
    // 23505 = unique violation. Two submissions arriving at the same instant
    // both pass the check above; the index refuses the second one.
    if (err.code === '23505') {
      console.log(`Duplicate submission refused at the index for ${data.email}`);
      return res.status(409).json({
        ok: false,
        errors: { email: 'This email address is already on file.' },
        message: duplicateMessage(data.member_type),
      });
    }
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

  const confirmation =
    record.member_type === 'Apparel' ? sendApparelConfirmation(record) : sendMemberConfirmation(record);

  const results = await Promise.allSettled([confirmation, notifyPrivateInbox(record), upsertBrevoContact(record)]);

  const [confirmationResult] = results;

  if (confirmationResult.status === 'fulfilled') {
    await query('update member_intake set confirmation_sent_at = now(), last_email_error = null where id = $1', [
      record.id,
    ]).catch(() => {});
  } else {
    console.error(`Confirmation email failed for intake #${record.id}:`, confirmationResult.reason.message);
    await query('update member_intake set last_email_error = $2 where id = $1', [
      record.id,
      String(confirmationResult.reason.message).slice(0, 400),
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
    /* "Delete my information" means all of it. The token identifies the
     * person; every record filed under that email address goes, in one
     * statement so it cannot half-succeed.
     *
     * This is the fix for records surviving a deletion: the old query
     * removed only the row the token belonged to, so any earlier or later
     * submission from the same person stayed in the table. */
    const { rows } = await query(
      `with target as (
         select email from member_intake where delete_token = $1
       )
       delete from member_intake m
        using target t
        where lower(m.email) = lower(t.email)
       returning m.id, m.email, m.first_name, m.member_type, m.created_at, m.source, m.channel`,
      [token]
    );

    if (!rows.length) {
      return res.status(404).json({ ok: false, message: 'This link is no longer valid.' });
    }

    const removed = rows[0];

    // The log evidences each deletion without keeping the person: a salted
    // hash of the email, and nothing else that identifies them.
    await Promise.all(
      rows.map((row) =>
        query(
          `insert into member_removal_log (email_hash, record_created_at, source, channel)
           values ($1, $2, $3, $4)`,
          [hashEmail(row.email), row.created_at, row.source, row.channel]
        )
      )
    ).catch((err) => console.error('Removal log write failed:', err.message));

    console.log(
      `Deletion at the member's request removed ${rows.length} record(s): ` +
        rows.map((row) => `#${row.id} (${row.member_type || 'unknown'})`).join(', ')
    );

    res.status(200).json({ ok: true, removed: rows.length });

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
    const { csv, count } = await buildIntakeCsv();
    const stamp = new Date().toISOString().slice(0, 10);
    console.log(`CSV export by static token — ${count} records`);

    res.setHeader('Content-Type', 'text/csv; charset=utf-8');
    res.setHeader('Content-Disposition', `attachment; filename="member_intake_${stamp}.csv"`);
    return res.send(csv);
  } catch (err) {
    console.error('CSV export failed:', err.message);
    return res.status(503).json({ ok: false, message: 'Export unavailable.' });
  }
});

/* ------------------------------------------------------------------ *
 * Admin portal — session-gated export at /admin.
 * Mounted before the static handler so /api/admin/* is never treated
 * as a file lookup.
 * ------------------------------------------------------------------ */
app.use(adminRouter);

/* ------------------------------------------------------------------ *
 * Health check — Render pings this to confirm the instance is live
 * ------------------------------------------------------------------ */
app.get('/healthz', async (_req, res) => {
  try {
    await healthcheck();
    res.json({ ok: true, build: BUILD, db: 'up', mail: mailerConfigured ? 'configured' : 'unconfigured' });
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

// Each lot has its own dedicated application page — these are the URLs on
// the QR codes and "Begin Application" buttons on the home page.
app.get('/join-collector', page('join-collector.html'));
app.get('/join-specialist', page('join-specialist.html'));
app.get('/join-partner', page('join-partner.html'));

// /join used to be a chooser page. Old links (including any already-printed
// ?type= QR codes) are redirected straight to the matching lot page, with
// any tracking params carried along; unmatched links fall back to the
// "Three Ways In" section on the home page.
const JOIN_TYPE_PAGES = { collector: '/join-collector', specialist: '/join-specialist', partner: '/join-partner' };
app.get('/join', (req, res) => {
  const type = String(req.query.type || '').toLowerCase();
  const target = JOIN_TYPE_PAGES[type];
  const rest = new URLSearchParams(req.query);
  rest.delete('type');
  const qs = rest.toString();
  if (target) return res.redirect(302, qs ? `${target}?${qs}` : target);
  return res.redirect(302, qs ? `/?${qs}#apply` : '/#apply');
});

app.get('/admin', page('admin.html'));
app.get('/apparel', page('apparel.html'));
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

    // Creates the first operator only when ADMIN_BOOTSTRAP_* are set and
    // no admin account exists yet. Never overwrites an existing one.
    await ensureBootstrapAdmin().catch((err) => console.error('Admin bootstrap failed:', err.message));
    startSessionReaper();
  }

  const server = app.listen(PORT, '0.0.0.0', () => {
    console.log(`The Gated Shifter listening on 0.0.0.0:${PORT} — build ${BUILD}`);
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