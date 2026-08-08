import express from 'express';
import crypto from 'node:crypto';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { pool, query, healthcheck } from './src/db.js';
import { runMigrations } from './src/migrate.js';

const __dirname = dirname(fileURLToPath(import.meta.url));
const app = express();
const PORT = process.env.PORT || 10000;
const IP_SALT = process.env.IP_HASH_SALT || 'gatedshifter-dev-salt';

app.set('trust proxy', 1); // Render terminates TLS at its load balancer
app.disable('x-powered-by');
app.use(express.json({ limit: '16kb' }));
app.use(express.urlencoded({ extended: false, limit: '16kb' }));

/* ------------------------------------------------------------------ *
 * Security headers
 * ------------------------------------------------------------------ */
app.use((req, res, next) => {
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('X-Frame-Options', 'DENY');
  res.setHeader('Referrer-Policy', 'strict-origin-when-cross-origin');
  res.setHeader('Permissions-Policy', 'geolocation=(), microphone=(), camera=()');
  res.setHeader(
    'Content-Security-Policy',
    [
      "default-src 'self'",
      "script-src 'self' 'unsafe-inline' https://www.googletagmanager.com",
      "connect-src 'self' https://www.google-analytics.com https://*.analytics.google.com",
      "img-src 'self' data: https://www.googletagmanager.com https://www.google-analytics.com",
      "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com",
      "font-src 'self' https://fonts.gstatic.com",
      "form-action 'self'",
      "frame-ancestors 'none'",
      "base-uri 'self'",
    ].join('; ')
  );
  next();
});

/* ------------------------------------------------------------------ *
 * Rate limiting — in-memory, sized for a single instance
 * ------------------------------------------------------------------ */
const hits = new Map();
const WINDOW_MS = 10 * 60 * 1000;
const MAX_PER_WINDOW = 8;

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
const clean = (v, max) => (typeof v === 'string' ? v.trim().slice(0, max) : '');

function validate(body) {
  const data = {
    full_name: clean(body.full_name, 120),
    email: clean(body.email, 254).toLowerCase(),
    phone: clean(body.phone, 40),
    referred_by: clean(body.referred_by, 160),
    marques: clean(body.marques, 500),
    message: clean(body.message, 2000),
    consent: body.consent === true || body.consent === 'on' || body.consent === 'true',
    // Never trust the client's source string — normalize it to a safe slug.
    source: (clean(body.source, 40).toLowerCase().replace(/[^a-z0-9_-]/g, '') || 'web'),
    page_path: clean(body.page_path, 200),
  };

  const errors = {};
  if (data.full_name.length < 2) errors.full_name = 'Enter your full name.';
  if (!EMAIL_RE.test(data.email)) errors.email = 'Enter an email address we can reply to.';
  if (data.phone && data.phone.replace(/\D/g, '').length < 7) {
    errors.phone = 'Enter a phone number with at least 7 digits, or leave it blank.';
  }
  if (!data.consent) errors.consent = 'Please confirm we may contact you about your inquiry.';

  return { data, errors };
}

/* ------------------------------------------------------------------ *
 * POST /api/intake — record an introduction request
 * ------------------------------------------------------------------ */
app.post('/api/intake', async (req, res) => {
  const ip = req.ip || '0.0.0.0';

  // Honeypot: a hidden field real people never fill in.
  if (clean(req.body.company_website, 200)) {
    return res.status(202).json({ ok: true });
  }

  // Timing check: a form filled in under 2 seconds is a script.
  const elapsed = Number(req.body.elapsed_ms || 0);
  if (elapsed && elapsed < 2000) {
    return res.status(202).json({ ok: true });
  }

  if (rateLimited(ip)) {
    return res
      .status(429)
      .json({ ok: false, message: 'Too many requests from this connection. Try again shortly.' });
  }

  const { data, errors } = validate(req.body);
  if (Object.keys(errors).length) {
    return res.status(400).json({ ok: false, errors });
  }

  const ip_hash = crypto.createHash('sha256').update(IP_SALT + ip).digest('hex');
  const user_agent = clean(req.get('user-agent'), 400);

  try {
    const { rows } = await query(
      `insert into member_intake
         (full_name, email, phone, referred_by, marques, message,
          consent, source, page_path, user_agent, ip_hash)
       values ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)
       on conflict do nothing
       returning id, created_at`,
      [
        data.full_name,
        data.email,
        data.phone || null,
        data.referred_by || null,
        data.marques || null,
        data.message || null,
        data.consent,
        data.source,
        data.page_path || null,
        user_agent || null,
        ip_hash,
      ]
    );

    // No row returned means the dedupe index caught a repeat submission.
    // The visitor's intent was satisfied either way.
    const duplicate = rows.length === 0;
    if (duplicate) {
      console.log(`Duplicate intake suppressed for ${data.email} (source: ${data.source})`);
    } else {
      console.log(`Intake #${rows[0].id} recorded (source: ${data.source})`);
    }

    // Optional: forward to Brevo. Enabled only when BREVO_API_KEY is set.
    if (process.env.BREVO_API_KEY && !duplicate) {
      forwardToBrevo(data).catch((err) => console.error('Brevo sync failed:', err.message));
    }

    return res.status(201).json({ ok: true });
  } catch (err) {
    console.error('Intake insert failed:', err.message);
    return res.status(503).json({
      ok: false,
      message: 'We could not record your request. Please email private@gatedshifter.co.',
    });
  }
});

/**
 * Brevo contact upsert. Left as a single function so the list ID and
 * attribute names can be adjusted without touching the request handler.
 */
async function forwardToBrevo(data) {
  const [firstName, ...rest] = data.full_name.split(/\s+/);
  const response = await fetch('https://api.brevo.com/v3/contacts', {
    method: 'POST',
    headers: {
      'api-key': process.env.BREVO_API_KEY,
      'content-type': 'application/json',
      accept: 'application/json',
    },
    body: JSON.stringify({
      email: data.email,
      updateEnabled: true,
      attributes: {
        FIRSTNAME: firstName,
        LASTNAME: rest.join(' '),
        SMS: data.phone || undefined,
        MARQUES: data.marques || undefined,
        REFERRED_BY: data.referred_by || undefined,
        SOURCE: data.source,
      },
      listIds: process.env.BREVO_LIST_ID ? [Number(process.env.BREVO_LIST_ID)] : undefined,
    }),
  });
  if (!response.ok) {
    throw new Error(`Brevo returned ${response.status}: ${await response.text()}`);
  }
}

/* ------------------------------------------------------------------ *
 * GET /api/intake.csv — token-gated export, off unless the token is set
 * ------------------------------------------------------------------ */
app.get('/api/intake.csv', async (req, res) => {
  const expected = process.env.ADMIN_EXPORT_TOKEN;
  const supplied = req.get('x-export-token') || req.query.token || '';
  if (!expected || supplied.length !== expected.length ||
      !crypto.timingSafeEqual(Buffer.from(String(supplied)), Buffer.from(expected))) {
    return res.status(404).end();
  }

  try {
    const { rows } = await query(
      `select id,
              to_char(created_at, 'YYYY-MM-DD HH24:MI:SS') as created_at_utc,
              full_name, email, phone, referred_by,
              marques, message, source, status
         from member_intake
        order by created_at desc`
    );

    const escape = (v) => `"${String(v ?? '').replace(/"/g, '""')}"`;
    const header = Object.keys(rows[0] || { id: '' }).join(',');
    const csv = [header, ...rows.map((r) => Object.values(r).map(escape).join(','))].join('\n');

    res.setHeader('Content-Type', 'text/csv; charset=utf-8');
    res.setHeader('Content-Disposition', 'attachment; filename="member_intake.csv"');
    res.send(csv);
  } catch (err) {
    console.error('CSV export failed:', err.message);
    res.status(503).json({ ok: false, message: 'Export unavailable.' });
  }
});

/* ------------------------------------------------------------------ *
 * Health check — Render pings this to confirm the instance is live
 * ------------------------------------------------------------------ */
app.get('/healthz', async (_req, res) => {
  try {
    await healthcheck();
    res.json({ ok: true, db: 'up' });
  } catch (err) {
    res.status(503).json({ ok: false, db: 'down', error: err.message });
  }
});

/* ------------------------------------------------------------------ *
 * Static site
 * ------------------------------------------------------------------ */
app.use(
  express.static(join(__dirname, 'public'), {
    extensions: ['html'],
    maxAge: '1h',
    setHeaders(res, path) {
      if (path.endsWith('.html')) res.setHeader('Cache-Control', 'no-cache');
    },
  })
);

// /join is the URL on the QR codes; it serves the same page.
app.get(['/', '/join'], (_req, res) => {
  res.sendFile(join(__dirname, 'public', 'index.html'));
});

app.use((_req, res) => res.status(404).sendFile(join(__dirname, 'public', 'index.html')));

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
      // Serve the page even if migrations fail — a broken DB shouldn't
      // take the site down mid-event. Submissions will return 503 and log.
      console.error('Startup migrations failed:', err.message);
    }
  }

  const server = app.listen(PORT, '0.0.0.0', () => {
    console.log(`The Gated Shifter listening on 0.0.0.0:${PORT}`);
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