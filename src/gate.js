/**
 * The Gated Shifter — site access gate.
 *
 * Render has no built-in password protection for web services, so the gate
 * lives here, in front of everything.
 *
 * SITE_ACCESS
 *   'public'    (default, or unset) — no gate, the site behaves normally.
 *   'link'      only someone holding an invite link gets in. The link is
 *               https://www.gatedshifter.co/?key=<token>. The token is
 *               exchanged for a cookie and stripped from the URL, so it does
 *               not sit in the address bar, in history, or in a referrer
 *               header when they click through to another page.
 *   'password'  a passphrase box. Same tokens are accepted as the passphrase,
 *               for someone who was given a word rather than a link.
 *
 * SITE_ACCESS_KEYS
 *   Comma-separated. Either bare tokens, or label:token so the log says who
 *   came in and you can revoke one person without disturbing anyone else:
 *
 *     john:8f2c1d...,insurer:4b91aa...,photographer:0d77ce...
 *
 *   Generate them with:  openssl rand -hex 16
 *
 * SITE_ACCESS_DAYS
 *   How long a visitor stays in once admitted. Default 30.
 *
 * Always reachable, gate or no gate — these are deliberate:
 *   /healthz              Render's health check. Gating it fails the deploy.
 *   /remove, /api/remove  Deletion links in emails already sent. Someone must
 *                         never be locked out of deleting their own data.
 *   /privacy              Referenced from those emails.
 *   /admin, /api/admin/*  Has its own sign-in; the gate would double-lock it.
 *   /assets/*             So the gate page can show the mark.
 */

import crypto from 'node:crypto';
import express from 'express';

const MODE = (process.env.SITE_ACCESS || 'public').toLowerCase();
/* Optional end of the review period, as YYYY-MM-DD. After this date every key
 * stops working and the gate says the review period has ended. Set it to the
 * date agreed in writing; extend it by editing the variable, not by arguing. */
const UNTIL = process.env.SITE_ACCESS_UNTIL || '';
const DAYS = Number(process.env.SITE_ACCESS_DAYS || 30);
const COOKIE = 'gs_access';
const SECRET =
  process.env.SITE_ACCESS_SECRET || process.env.IP_HASH_SALT || 'gatedshifter-dev-access-secret';

export const gateEnabled = MODE === 'link' || MODE === 'password';
export const gateMode = MODE;

/** [{ label, token }] */
const KEYS = String(process.env.SITE_ACCESS_KEYS || '')
  .split(',')
  .map((entry) => entry.trim())
  .filter(Boolean)
  .map((entry) => {
    const at = entry.indexOf(':');
    return at > 0
      ? { label: entry.slice(0, at).trim(), token: entry.slice(at + 1).trim() }
      : { label: 'guest', token: entry };
  })
  .filter((key) => key.token.length >= 8);

const OPEN_PATHS = [
  '/healthz',
  '/remove',
  '/privacy',
  '/api/remove',
  '/admin',
  '/api/admin',
  '/assets',
  '/favicon.ico',
  '/robots.txt',
];

const isOpen = (path) =>
  OPEN_PATHS.some((open) => path === open || path.startsWith(`${open}/`) || path.startsWith(`${open}?`));

/* ------------------------------------------------------------------ *
 * Tokens and the cookie
 * ------------------------------------------------------------------ */
const sign = (payload) => crypto.createHmac('sha256', SECRET).update(payload).digest('base64url');

/** Constant-time match against every configured key. */
function matchKey(supplied) {
  const given = Buffer.from(String(supplied || ''));
  let found = null;
  for (const key of KEYS) {
    const expected = Buffer.from(key.token);
    // Compare every key regardless, so timing does not reveal which matched.
    const same = given.length === expected.length && crypto.timingSafeEqual(given, expected);
    if (same) found = key;
  }
  return found;
}

function issueCookie(req, res, label) {
  const expires = Date.now() + DAYS * 24 * 60 * 60 * 1000;
  const payload = `${label}|${expires}`;
  const value = `${Buffer.from(payload).toString('base64url')}.${sign(payload)}`;

  const secure = (req.get('x-forwarded-proto') || req.protocol || '').toLowerCase() === 'https';
  const bits = [
    `${COOKIE}=${value}`,
    'Path=/',
    'HttpOnly',
    'SameSite=Lax', // Lax, not Strict: an invite link arrives from an email client
    `Max-Age=${Math.floor((DAYS * 24 * 60 * 60 * 1000) / 1000)}`,
  ];
  if (secure) bits.push('Secure');
  res.append('Set-Cookie', bits.join('; '));
}

function readCookie(req) {
  const header = req.headers.cookie || '';
  for (const part of header.split(';')) {
    const [name, ...rest] = part.trim().split('=');
    if (name === COOKIE) return decodeURIComponent(rest.join('='));
  }
  return '';
}

/** The label of the admitted visitor, or null. */
function admitted(req) {
  const raw = readCookie(req);
  if (!raw || !raw.includes('.')) return null;

  const [encoded, signature] = raw.split('.');
  let payload;
  try {
    payload = Buffer.from(encoded, 'base64url').toString('utf8');
  } catch {
    return null;
  }

  const expected = Buffer.from(sign(payload));
  const given = Buffer.from(String(signature));
  if (given.length !== expected.length || !crypto.timingSafeEqual(given, expected)) return null;

  const [label, expires] = payload.split('|');
  if (!expires || Number(expires) < Date.now()) return null;

  // A key removed from SITE_ACCESS_KEYS stops working immediately, even for
  // someone already carrying a cookie.
  if (!KEYS.some((key) => key.label === label)) return null;

  return label;
}

/* ------------------------------------------------------------------ *
 * The gate page — the site's design, no dependencies
 * ------------------------------------------------------------------ */
function gatePage({ askForPassphrase, failed }) {
  return `<!DOCTYPE html>
<html lang="en"><head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0, viewport-fit=cover">
<title>The Gated Shifter</title>
<meta name="robots" content="noindex, nofollow">
<meta name="theme-color" content="#0B0C0E">
<link rel="preconnect" href="https://fonts.googleapis.com">
<link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
<link href="https://fonts.googleapis.com/css2?family=Cormorant+Garamond:wght@600&family=EB+Garamond:wght@400&family=Inter:wght@400;500&display=swap" rel="stylesheet">
<style>
  :root { --carbon:#0B0C0E; --charcoal:#171A1F; --slate:#2A2E33; --ivory:#EDEBE7; --stone:#A7ABB2;
          --platinum:#BFC3C7; --oxblood:#A8474B; --hairline:rgba(191,195,199,0.14); }
  *,*::before,*::after{margin:0;padding:0;box-sizing:border-box}
  html{font-size:16px;-webkit-font-smoothing:antialiased}
  body{background:var(--carbon);color:var(--ivory);font-family:'EB Garamond',Georgia,serif;line-height:1.6;
       min-height:100vh;display:flex;align-items:center;justify-content:center;padding:24px}
  .panel{width:92vw;max-width:520px;background:var(--charcoal);border-top:2px solid var(--ivory);padding:48px 40px 40px}
  .mark{display:block;width:112px;height:auto;margin-bottom:32px}
  .eyebrow{font-family:'Inter',sans-serif;font-size:11px;font-weight:500;letter-spacing:0.16em;
           text-transform:uppercase;color:var(--stone);margin-bottom:12px}
  h1{font-family:'Cormorant Garamond',Georgia,serif;font-weight:600;font-size:30px;line-height:1.2;margin-bottom:12px}
  p{font-size:13px;line-height:21px;color:var(--stone);max-width:46ch}
  form{margin-top:28px;padding-top:24px;border-top:1px solid var(--hairline)}
  label{display:block;font-family:'Inter',sans-serif;font-size:11px;font-weight:500;letter-spacing:0.14em;
        text-transform:uppercase;color:var(--platinum);margin-bottom:10px}
  input{width:100%;background:var(--carbon);border:1px solid var(--slate);border-radius:0;padding:12px 14px;
        font-family:'EB Garamond',Georgia,serif;font-size:16px;line-height:21px;color:var(--ivory)}
  input:focus{outline:none;border-color:var(--ivory)}
  button{margin-top:18px;width:100%;font-family:'Inter',sans-serif;font-size:12px;font-weight:500;
         letter-spacing:0.16em;text-transform:uppercase;color:var(--carbon);background:var(--ivory);
         border:1px solid var(--ivory);border-radius:0;padding:16px 24px;cursor:pointer}
  .error{font-family:'Inter',sans-serif;font-size:13px;line-height:20px;color:var(--ivory);
         background:rgba(168,71,75,0.14);border:1px solid var(--oxblood);padding:14px;margin-top:20px}
  .foot{margin-top:26px;font-family:'Inter',sans-serif;font-size:11px;line-height:20px;color:var(--stone)}
  .foot a{color:var(--platinum);text-decoration:none;border-bottom:1px solid rgba(191,195,199,0.28)}
</style></head>
<body>
  <main class="panel">
    <img class="mark" src="/assets/logo.svg" alt="The Gated Shifter">
    <p class="eyebrow">Private &middot; By Invitation</p>
    <h1>This site is not open.</h1>
    <p>Access is limited to people who have been sent a link directly. If you were expecting to be here, use the link from your invitation.</p>
    ${
      askForPassphrase
        ? `<form method="POST" action="/api/enter">
             <label for="k">Passphrase</label>
             <input id="k" name="key" type="password" autocomplete="current-password" autofocus>
             <button type="submit">Enter</button>
           </form>`
        : ''
    }
    ${failed ? '<div class="error">That link or passphrase is not valid. Check it and try again.</div>' : ''}
    <p class="foot">Written to <a href="mailto:private@gatedshifter.co">private@gatedshifter.co</a> if you need access.</p>
  </main>
</body></html>`;
}

/** Shown after SITE_ACCESS_UNTIL. Deliberately plain and unembarrassing —
 * it says the review window closed, not that anyone did anything wrong. */
function expiredPage() {
  return gatePage({ askForPassphrase: false, failed: false })
    .replace('This site is not open.', 'The review period has ended.')
    .replace(
      'Access is limited to people who have been sent a link directly. If you were expecting to be here, use the link from your invitation.',
      'This preview was available for review until ' +
        UNTIL +
        '. To continue, or to arrange launch, write to the address below.'
    );
}

/* ------------------------------------------------------------------ *
 * Middleware
 * ------------------------------------------------------------------ */
export const gateRouter = express.Router();

/** Passphrase form target. Kept out of the gate so it works in 'link' mode too. */
gateRouter.post('/api/enter', express.urlencoded({ extended: false }), (req, res) => {
  const key = matchKey(req.body?.key);
  if (!key) {
    console.warn('Site access refused: bad passphrase');
    return res.status(401).send(gatePage({ askForPassphrase: true, failed: true }));
  }
  issueCookie(req, res, key.label);
  console.log(`Site access granted to "${key.label}" by passphrase`);
  return res.redirect(302, '/');
});

/** True once the agreed review period has passed. */
function reviewPeriodOver() {
  if (!UNTIL) return false;
  const end = new Date(`${UNTIL}T23:59:59Z`);
  if (Number.isNaN(end.getTime())) return false;
  return Date.now() > end.getTime();
}

export function siteGate(req, res, next) {
  if (!gateEnabled) return next();

  // Keep a gated site out of search results even if a link leaks.
  res.setHeader('X-Robots-Tag', 'noindex, nofollow');

  if (isOpen(req.path)) return next();

  if (reviewPeriodOver()) {
    return res.status(403).send(expiredPage());
  }

  if (!KEYS.length) {
    console.error('SITE_ACCESS is on but SITE_ACCESS_KEYS is empty — nobody can get in. Refusing to serve.');
    return res.status(503).send(gatePage({ askForPassphrase: false, failed: false }));
  }

  // An invite link: swap the token for a cookie, then strip it from the URL so
  // it is not left in history or sent as a referrer.
  const supplied = req.query.key || req.query.k;
  if (supplied) {
    const key = matchKey(supplied);
    if (key) {
      issueCookie(req, res, key.label);
      console.log(`Site access granted to "${key.label}" via link`);
      const url = new URL(req.originalUrl, 'https://placeholder.local');
      url.searchParams.delete('key');
      url.searchParams.delete('k');
      const clean = `${url.pathname}${url.search}`;
      return res.redirect(302, clean || '/');
    }
    console.warn(`Site access refused: bad key on ${req.path}`);
    return res.status(401).send(gatePage({ askForPassphrase: MODE === 'password', failed: true }));
  }

  const label = admitted(req);
  if (label) {
    req.accessLabel = label;
    return next();
  }

  return res.status(401).send(gatePage({ askForPassphrase: MODE === 'password', failed: false }));
}

/** One line at boot, so the mode is never a mystery. */
export function describeGate() {
  if (!gateEnabled) return 'site access: public';
  const until = UNTIL ? `, review period ends ${UNTIL}${reviewPeriodOver() ? ' (ENDED — nobody can get in)' : ''}` : '';
  return `site access: ${MODE} — ${KEYS.length} key(s) [${KEYS.map((k) => k.label).join(', ')}], ${DAYS} day sessions${until}`;
}