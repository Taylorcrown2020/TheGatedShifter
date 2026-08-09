/**
 * Brevo email for The Gated Shifter.
 *
 * Four messages leave this file:
 *   1. Member confirmation, per application path, with an apparel CTA.
 *   2. Notification to private@gatedshifter.co that someone applied.
 *   3. Apparel interest confirmation.
 *   4. Confirmation that a deletion happened, with a link to apply again.
 *
 * Nothing here throws into a request handler. A failed send is logged and
 * recorded against the row; the member's record is already safe.
 *
 * ------------------------------------------------------------------
 * LAYOUT
 *
 * The email is the site, not a newsletter. Same structure as every page:
 *
 *   masthead      mark on carbon black, hairline rule beneath
 *   panel         heritage charcoal, 2px ivory rule across the top
 *     eyebrow     Inter, 11px, uppercase, 0.16em tracking, muted stone
 *     headline    Garamond, ~28px, ivory
 *     lede        13px / 21px, muted stone
 *     record      uppercase labels, ivory values, hairline row rules
 *     action      square ivory button — never rounded
 *     signature   the brand line, italic
 *   footer        11px Inter on carbon, deletion and privacy links
 *
 * No colour fields, no oxblood banner — the site never uses one. Oxblood
 * appears only as an accent rule, the way the asterisk works on a form.
 *
 * Constraints this respects: tables for layout, everything inline, no web
 * fonts (Georgia stands in for Cormorant and EB Garamond, Helvetica for
 * Inter), buttons as padded table cells so Outlook renders them, one
 * column at 600px, and a PNG mark because Outlook and Gmail will not
 * render the site's SVG.
 * ------------------------------------------------------------------
 */

const BREVO_API = 'https://api.brevo.com/v3';
const API_KEY = process.env.BREVO_API_KEY || '';
const LIST_ID = process.env.BREVO_LIST_ID ? Number(process.env.BREVO_LIST_ID) : null;

const SITE_URL = (process.env.SITE_URL || 'https://www.gatedshifter.co').replace(/\/+$/, '');
const FROM_EMAIL = process.env.MAIL_FROM_EMAIL || 'private@gatedshifter.co';
const FROM_NAME = process.env.MAIL_FROM_NAME || 'The Gated Shifter';
const NOTIFY_EMAIL = process.env.NOTIFY_EMAIL || 'private@gatedshifter.co';
const REPLY_TO = process.env.MAIL_REPLY_TO || 'private@gatedshifter.co';

// Raster mark: email clients do not render SVG. 368x176 @2x for a 184px slot.
const MARK_URL = `${SITE_URL}/assets/gated-shifter-logo.png`;

export const mailerConfigured = Boolean(API_KEY);

/* ------------------------------------------------------------------ *
 * Transport
 * ------------------------------------------------------------------ */
async function brevo(path, options = {}) {
  if (!API_KEY) throw new Error('BREVO_API_KEY is not set');

  const response = await fetch(`${BREVO_API}${path}`, {
    ...options,
    headers: {
      'api-key': API_KEY,
      'content-type': 'application/json',
      accept: 'application/json',
      ...(options.headers || {}),
    },
    signal: AbortSignal.timeout(10_000),
  });

  if (!response.ok) {
    const detail = await response.text().catch(() => '');
    throw new Error(`Brevo ${path} returned ${response.status}: ${detail.slice(0, 300)}`);
  }

  return response.status === 204 ? null : response.json().catch(() => null);
}

async function sendEmail({ to, toName, subject, html, text, tags }) {
  return brevo('/smtp/email', {
    method: 'POST',
    body: JSON.stringify({
      sender: { email: FROM_EMAIL, name: FROM_NAME },
      replyTo: { email: REPLY_TO, name: FROM_NAME },
      to: [{ email: to, ...(toName ? { name: toName } : {}) }],
      subject,
      htmlContent: html,
      textContent: text,
      tags,
    }),
  });
}

/* ------------------------------------------------------------------ *
 * Design tokens — the site's :root, verbatim
 * ------------------------------------------------------------------ */
const COLOR = {
  carbon: '#0B0C0E',
  charcoal: '#171A1F',
  slate: '#2A2E33',
  platinum: '#BFC3C7',
  ivory: '#EDEBE7',
  stone: '#A7ABB2',
  oxblood: '#A8474B',
  hairline: '#24272C', // rgba hairlines flattened for Outlook
  hairlineStrong: '#31353B',
};

const SERIF = "Georgia,'Times New Roman',serif"; // stands in for Cormorant / EB Garamond
const SANS = "Helvetica,Arial,sans-serif"; // stands in for Inter

const escapeHtml = (value) =>
  String(value ?? '')
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;');

const formatDate = (iso) => {
  const d = iso ? new Date(iso) : new Date();
  if (Number.isNaN(d.getTime())) return '';
  return d.toLocaleDateString('en-US', { month: 'long', day: 'numeric', year: 'numeric' });
};

/* Type styles, matched to the page stylesheet */
const EYEBROW = `font-family:${SANS};font-size:11px;font-weight:bold;letter-spacing:0.16em;text-transform:uppercase;color:${COLOR.stone};margin:0 0 14px;`;
const H1 = `font-family:${SERIF};font-size:28px;line-height:34px;color:${COLOR.ivory};margin:0 0 14px;font-weight:normal;`;
const LEDE = `font-family:${SERIF};font-size:15px;line-height:24px;color:${COLOR.stone};margin:0 0 26px;`;
const P = `font-family:${SERIF};font-size:15px;line-height:26px;color:${COLOR.stone};margin:0 0 14px;`;
const SIGNATURE = `font-family:${SERIF};font-style:italic;font-size:16px;line-height:26px;color:${COLOR.ivory};margin:0;`;
const LABEL = `font-family:${SANS};font-size:10px;font-weight:bold;letter-spacing:0.14em;text-transform:uppercase;color:${COLOR.platinum};padding:13px 18px 13px 0;vertical-align:top;white-space:nowrap;`;
const VALUE = `font-family:${SERIF};font-size:15px;line-height:22px;color:${COLOR.ivory};padding:13px 0;vertical-align:top;`;
const SECTION_LABEL = `font-family:${SANS};font-size:10px;font-weight:bold;letter-spacing:0.14em;text-transform:uppercase;color:${COLOR.platinum};margin:0 0 12px;`;

/* ------------------------------------------------------------------ *
 * Pieces
 * ------------------------------------------------------------------ */

/** Square ivory button. Padding lives on the cell so Outlook obeys it. */
const button = (href, label) => `
  <table role="presentation" cellpadding="0" cellspacing="0" border="0" style="margin:0;">
    <tr><td align="center" bgcolor="${COLOR.ivory}" style="background-color:${COLOR.ivory};padding:17px 34px;">
      <a href="${href}" style="font-family:${SANS};font-size:12px;font-weight:bold;letter-spacing:0.16em;text-transform:uppercase;color:${COLOR.carbon};text-decoration:none;display:block;">${escapeHtml(
        label
      )}</a>
    </td></tr>
  </table>`;

/** Outlined button, for a second, quieter action. */
const buttonQuiet = (href, label) => `
  <table role="presentation" cellpadding="0" cellspacing="0" border="0" style="margin:0;">
    <tr><td align="center" style="border:1px solid ${COLOR.slate};padding:16px 30px;">
      <a href="${href}" style="font-family:${SANS};font-size:12px;font-weight:bold;letter-spacing:0.16em;text-transform:uppercase;color:${COLOR.ivory};text-decoration:none;display:block;">${escapeHtml(
        label
      )}</a>
    </td></tr>
  </table>`;

/** A labelled record table. Rows arrive as [label, value] pairs. */
const recordTable = (rows) => {
  const kept = rows.filter(
    ([, value]) => !(value === null || value === undefined || value === '' || (Array.isArray(value) && !value.length))
  );
  if (!kept.length) return '';

  const cells = kept
    .map(([label, value], index) => {
      const border = index < kept.length - 1 ? `border-bottom:1px solid ${COLOR.hairline};` : '';
      const shown = Array.isArray(value) ? value.join(', ') : value;
      return `<tr>
        <td style="${LABEL}${border}">${escapeHtml(label)}</td>
        <td style="${VALUE}${border}">${escapeHtml(shown)}</td>
      </tr>`;
    })
    .join('');

  return `<table role="presentation" width="100%" cellpadding="0" cellspacing="0" border="0" style="margin:0 0 8px;border-top:1px solid ${COLOR.hairline};">${cells}</table>`;
};

/** Hairline rule inside the panel. */
const rule = (space = 28) =>
  `<table role="presentation" width="100%" cellpadding="0" cellspacing="0" border="0"><tr><td height="1" style="height:1px;line-height:1px;font-size:0;background-color:${COLOR.hairline};padding:0;">&nbsp;</td></tr></table><div style="height:${space}px;line-height:${space}px;font-size:0;">&nbsp;</div>`;

/** Short oxblood accent rule — the only place the colour appears. */
const accent = () =>
  `<table role="presentation" cellpadding="0" cellspacing="0" border="0"><tr><td width="34" height="2" style="width:34px;height:2px;line-height:2px;font-size:0;background-color:${COLOR.oxblood};">&nbsp;</td></tr></table><div style="height:22px;line-height:22px;font-size:0;">&nbsp;</div>`;

const gap = (h) => `<div style="height:${h}px;line-height:${h}px;font-size:0;">&nbsp;</div>`;

const footerLink = (href, label) =>
  `<a href="${href}" style="color:${COLOR.platinum};text-decoration:none;border-bottom:1px solid ${COLOR.hairlineStrong};">${escapeHtml(
    label
  )}</a>`;

/* ------------------------------------------------------------------ *
 * Shell — masthead, charcoal panel with the ivory top rule, footer
 * ------------------------------------------------------------------ */
function shell({ preheader, body, footer }) {
  return `<!DOCTYPE html>
<html lang="en" xmlns:v="urn:schemas-microsoft-com:vml" xmlns:o="urn:schemas-microsoft-com:office:office">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="x-apple-disable-message-reformatting">
<meta name="color-scheme" content="dark">
<meta name="supported-color-schemes" content="dark">
<title>The Gated Shifter</title>
<!--[if mso]><style>body,table,td,a{font-family:Georgia,'Times New Roman',serif !important;}</style><![endif]-->
<style>
  @media only screen and (max-width: 620px) {
    .panel { padding: 36px 24px 32px !important; }
    .stack { display: block !important; width: 100% !important; }
    .stack-gap { height: 12px !important; line-height: 12px !important; }
    .h1 { font-size: 24px !important; line-height: 30px !important; }
  }
</style>
</head>
<body style="margin:0;padding:0;background-color:${COLOR.carbon};">
<div style="display:none;font-size:1px;color:${COLOR.carbon};line-height:1px;max-height:0;max-width:0;opacity:0;overflow:hidden;">${escapeHtml(
    preheader
  )}</div>

<table role="presentation" width="100%" cellpadding="0" cellspacing="0" border="0" bgcolor="${COLOR.carbon}" style="background-color:${COLOR.carbon};">
  <tr><td align="center" style="padding:32px 16px 56px;">

    <table role="presentation" width="600" cellpadding="0" cellspacing="0" border="0" style="width:600px;max-width:600px;">

      <!-- Masthead: mark, hairline rule beneath, as on every page -->
      <tr><td style="padding:0 0 20px;">
        <a href="${SITE_URL}/" style="text-decoration:none;">
          <img src="${MARK_URL}" width="128" height="61" alt="The Gated Shifter"
               style="display:block;border:0;outline:none;width:128px;height:auto;">
        </a>
      </td></tr>
      <tr><td height="1" style="height:1px;line-height:1px;font-size:0;background-color:${COLOR.hairline};">&nbsp;</td></tr>

      <!-- Panel -->
      <tr><td class="panel" bgcolor="${COLOR.charcoal}" style="background-color:${COLOR.charcoal};border-top:2px solid ${COLOR.ivory};padding:44px 40px 40px;">
        ${body}
      </td></tr>

      <!-- Footer -->
      <tr><td style="padding:26px 4px 0;font-family:${SANS};font-size:11px;line-height:20px;letter-spacing:0.02em;color:${COLOR.stone};">
        ${footer}
      </td></tr>

    </table>
  </td></tr>
</table>
</body></html>`;
}

/** The footer every member-facing message shares. */
const memberFooter = (removeUrl) => `
  The Gated Shifter&trade; &middot; Private Ownership Platform &middot; In Development<br>
  Your details are held privately and never shared or sold.
  ${gap(14)}
  ${removeUrl ? `${footerLink(removeUrl, 'Delete my information from The Gated Shifter database')}<br>` : ''}
  ${footerLink(`${SITE_URL}/privacy`, 'Privacy')} &nbsp;&middot;&nbsp;
  ${footerLink(`mailto:${REPLY_TO}`, REPLY_TO)}
`;

/* ------------------------------------------------------------------ *
 * 1. Member confirmation — one per application path
 * ------------------------------------------------------------------ */

const LOT_BY_TYPE = {
  Collector: 'Lot 01 · Founding Collection',
  Specialist: 'Lot 02 · Accredited Specialist',
  Partner: 'Lot 03 · Institutional Partner',
  Apparel: 'Lot 04 · Apparel Register',
};

/** What each path had a chance to tell us, shown back to them. */
function applicationRows(record) {
  const common = [['Email', record.email]];

  if (record.member_type === 'Collector') {
    return common.concat([
      ['Location', record.city],
      ['Collection', record.collection_size],
      ['Marques', record.primary_marques],
      ['Defining automobile', record.defining_vehicle],
    ]);
  }
  if (record.member_type === 'Specialist') {
    return common.concat([
      ['Discipline', record.discipline || record.specialist_needs],
      ['Workshop', record.workshop_practice],
      ['Vouched by', record.vouch_referral],
    ]);
  }
  if (record.member_type === 'Partner') {
    return common.concat([
      ['Organization', record.organization || record.partner_specialty],
      ['Area', record.partner_area],
    ]);
  }
  return common.concat([['Looking for', record.looking_for_now]]);
}

const PATH_COPY = {
  Collector:
    'Founding Collections shape the registry before it opens. Yours is now in front of us, and a small number of numbered places will be offered.',
  Specialist:
    'The registry is only as good as the expertise inside it. Accreditation is deliberately rare, and every application is read by a person who knows the work.',
  Partner:
    'Partnership begins with a conversation, not a contract. If the fit is there, we will write to arrange one.',
};

export async function sendMemberConfirmation(record) {
  const removeUrl = `${SITE_URL}/remove?t=${encodeURIComponent(record.delete_token)}`;
  const apparelUrl = `${SITE_URL}/apparel?source=email&channel=email&placement=confirmation`;
  const firstName = record.first_name || 'there';
  const fullName = [record.first_name, record.last_name].filter(Boolean).join(' ');
  const lot = LOT_BY_TYPE[record.member_type] || 'Founding Access';
  const pathCopy = PATH_COPY[record.member_type] || PATH_COPY.Collector;

  const html = shell({
    preheader: `${fullName || 'Your'} application has been received — we read every one personally.`,
    body: `
      <p style="${EYEBROW}">${escapeHtml(lot)} &middot; Received</p>
      <h1 class="h1" style="${H1}">Your application has been received.</h1>
      <p style="${LEDE}">${escapeHtml(firstName)}, thank you. Nothing further is needed from you — you will hear back directly, from a person.</p>
      ${accent()}
      <p style="${P}">${escapeHtml(pathCopy)}</p>

      ${gap(14)}
      <p style="${SECTION_LABEL}">What we have on file</p>
      ${recordTable(applicationRows(record))}
      <p style="font-family:${SERIF};font-size:13px;line-height:21px;color:${COLOR.stone};margin:14px 0 0;">Received ${escapeHtml(
        formatDate(record.created_at)
      )}. If anything above is wrong, reply to this email and we will correct it.</p>

      ${gap(30)}
      ${rule(28)}

      <p style="${EYEBROW}margin-bottom:10px;">Lot 04 &middot; Apparel Register</p>
      <p style="font-family:${SERIF};font-size:17px;line-height:26px;color:${COLOR.ivory};margin:0 0 10px;">Before the first pieces are made, we are asking who would wear them.</p>
      <p style="font-family:${SERIF};font-size:14px;line-height:23px;color:${COLOR.stone};margin:0 0 22px;">No catalogue, no prices, nothing for sale. Tell us what you would actually wear and what size you take, and it will shape what gets made.</p>
      ${button(apparelUrl, 'Register your interest')}

      ${gap(32)}
      ${rule(26)}
      <p style="${SIGNATURE}">One trusted ecosystem. Every aspect of analog ownership.</p>
    `,
    footer: memberFooter(removeUrl),
  });

  const text = [
    `${lot} — received`,
    '',
    'Your application has been received.',
    '',
    `${firstName}, thank you. Nothing further is needed from you — you will hear back directly, from a person.`,
    '',
    pathCopy,
    '',
    'WHAT WE HAVE ON FILE',
    ...applicationRows(record)
      .filter(([, value]) => value && (!Array.isArray(value) || value.length))
      .map(([label, value]) => `${label}: ${Array.isArray(value) ? value.join(', ') : value}`),
    `Received ${formatDate(record.created_at)}.`,
    'If anything above is wrong, reply to this email and we will correct it.',
    '',
    '---',
    'LOT 04 — APPAREL REGISTER',
    'Before the first pieces are made, we are asking who would wear them. No catalogue,',
    'no prices, nothing for sale. Tell us what you would wear and what size you take:',
    apparelUrl,
    '',
    'One trusted ecosystem. Every aspect of analog ownership.',
    '',
    '---',
    'Delete my information from The Gated Shifter database:',
    removeUrl,
    `Privacy: ${SITE_URL}/privacy`,
    `Contact: ${REPLY_TO}`,
  ].join('\n');

  return sendEmail({
    to: record.email,
    toName: fullName || undefined,
    subject: `The Gated Shifter — your ${record.member_type || 'Founding Access'} application has been received`,
    html,
    text,
    tags: ['founding-access-confirmation'],
  });
}

/* ------------------------------------------------------------------ *
 * 2. Apparel interest confirmation
 * ------------------------------------------------------------------ */
export async function sendApparelConfirmation(record) {
  const removeUrl = `${SITE_URL}/remove?t=${encodeURIComponent(record.delete_token)}`;
  const firstName = record.first_name || 'there';
  const fullName = [record.first_name, record.last_name].filter(Boolean).join(' ');

  const html = shell({
    preheader: 'Your apparel interest is registered — an enquiry only, nothing purchased.',
    body: `
      <p style="${EYEBROW}">Lot 04 &middot; Apparel Register</p>
      <h1 class="h1" style="${H1}">Noted, and nothing purchased.</h1>
      <p style="${LEDE}">${escapeHtml(firstName)}, this is an interest register. No order has been placed, no payment taken, and no card details were ever asked for.</p>
      ${accent()}
      <p style="${P}">The first pieces are being drawn up now. What you have told us goes into deciding what actually gets made, and in which sizes. When there is something to show, you will hear from us before it is public.</p>

      ${gap(14)}
      <p style="${SECTION_LABEL}">What you told us</p>
      ${recordTable([
        ['Email', record.email],
        ['Interested in', record.apparel_items],
        ['Size', record.apparel_size],
        ['Notes', record.additional_notes],
      ])}
      <p style="font-family:${SERIF};font-size:13px;line-height:21px;color:${COLOR.stone};margin:14px 0 0;">Registered ${escapeHtml(
        formatDate(record.created_at)
      )}. Reply to this email to change any of it.</p>

      ${gap(30)}
      ${rule(28)}
      <p style="font-family:${SERIF};font-size:14px;line-height:23px;color:${COLOR.stone};margin:0 0 22px;">If you have not applied to the registry itself, the three founding paths are open now.</p>
      ${buttonQuiet(`${SITE_URL}/#apply`, 'See the three ways in')}

      ${gap(32)}
      ${rule(26)}
      <p style="${SIGNATURE}">One trusted ecosystem. Every aspect of analog ownership.</p>
    `,
    footer: memberFooter(removeUrl),
  });

  const text = [
    'Lot 04 — Apparel Register',
    '',
    'Noted, and nothing purchased.',
    '',
    `${firstName}, this is an interest register. No order has been placed, no payment taken,`,
    'and no card details were ever asked for.',
    '',
    'The first pieces are being drawn up now. What you have told us goes into deciding what',
    'gets made, and in which sizes.',
    '',
    'WHAT YOU TOLD US',
    `Email: ${record.email}`,
    record.apparel_items && record.apparel_items.length ? `Interested in: ${record.apparel_items.join(', ')}` : '',
    record.apparel_size ? `Size: ${record.apparel_size}` : '',
    record.additional_notes ? `Notes: ${record.additional_notes}` : '',
    `Registered ${formatDate(record.created_at)}. Reply to this email to change any of it.`,
    '',
    `The three founding paths: ${SITE_URL}/#apply`,
    '',
    'One trusted ecosystem. Every aspect of analog ownership.',
    '',
    '---',
    'Delete my information from The Gated Shifter database:',
    removeUrl,
    `Privacy: ${SITE_URL}/privacy`,
    `Contact: ${REPLY_TO}`,
  ]
    .filter((line) => line !== '')
    .join('\n');

  return sendEmail({
    to: record.email,
    toName: fullName || undefined,
    subject: 'The Gated Shifter — your apparel interest is registered',
    html,
    text,
    tags: ['apparel-interest-confirmation'],
  });
}

/* ------------------------------------------------------------------ *
 * 3. Internal notification
 * ------------------------------------------------------------------ */
export async function notifyPrivateInbox(record) {
  const name = [record.first_name, record.last_name].filter(Boolean).join(' ');
  const isApparel = record.member_type === 'Apparel';
  const lot = LOT_BY_TYPE[record.member_type] || 'Founding Access';
  const attribution = [record.source, record.channel, record.placement, record.campaign, record.captured_by]
    .filter(Boolean)
    .join(' / ');

  const detail = isApparel
    ? [
        ['Interested in', record.apparel_items],
        ['Size', record.apparel_size],
        ['Notes', record.additional_notes],
      ]
    : [
        ['Location', record.city],
        ['Collection', record.collection_size],
        ['Marques', record.primary_marques],
        ['Defining automobile', record.defining_vehicle],
        ['Discipline', record.discipline || record.specialist_needs],
        ['Workshop', record.workshop_practice],
        ['Proud work', record.proud_work],
        ['Vouched by', record.vouch_referral],
        ['Organization', record.organization || record.partner_specialty],
        ['Area', record.partner_area],
        ['Partnership notes', record.partnership_notes],
        ['Looking for', record.looking_for_now],
        ['Notes', record.additional_notes],
      ];

  const html = shell({
    preheader: `${lot} — ${name || record.email}${attribution ? ` (${attribution})` : ''}`,
    body: `
      <p style="${EYEBROW}">${escapeHtml(lot)} &middot; Record #${escapeHtml(record.id)}</p>
      <h1 class="h1" style="${H1}">${escapeHtml(name || record.email)}</h1>
      <p style="${LEDE}">${escapeHtml(
        isApparel ? 'Apparel interest registered.' : `New ${record.member_type || 'member'} application.`
      )} Status ${escapeHtml(record.status || 'NEW')}.</p>
      ${accent()}

      <p style="${SECTION_LABEL}">Applicant</p>
      ${recordTable([
        ['Name', name],
        ['Email', record.email],
        ['Phone', record.mobile_phone],
      ])}

      ${gap(24)}
      <p style="${SECTION_LABEL}">${isApparel ? 'Apparel' : 'Application'}</p>
      ${recordTable(detail)}

      ${gap(24)}
      <p style="${SECTION_LABEL}">Attribution</p>
      ${recordTable([
        ['Source', record.source],
        ['Channel', record.channel],
        ['Campaign', record.campaign],
        ['Placement', record.placement],
        ['Captured by', record.captured_by],
        ['Referral code', record.referral_code],
        ['Marketing opt-in', record.marketing_consent ? 'Yes' : 'No'],
        ['Received', `${new Date(record.created_at).toISOString().replace('T', ' ').slice(0, 19)} UTC`],
      ])}

      ${
        record.status === 'REVIEW'
          ? `${gap(26)}<table role="presentation" width="100%" cellpadding="0" cellspacing="0" border="0"><tr><td style="border-left:2px solid ${COLOR.oxblood};padding:2px 0 2px 16px;"><p style="font-family:${SERIF};font-size:14px;line-height:23px;color:${COLOR.stone};margin:0;">This email already exists in the database. The new submission was kept as its own record and flagged REVIEW so nothing is lost.</p></td></tr></table>`
          : ''
      }

      ${gap(32)}
      ${rule(26)}
      ${buttonQuiet(`${SITE_URL}/admin`, 'Open the admin portal')}
    `,
    footer: `Sent by the gatedshifter.co application forms. Internal — not seen by the applicant.`,
  });

  const text = [
    `${lot} — record #${record.id} (${record.status || 'NEW'})`,
    '',
    `Name: ${name}`,
    `Email: ${record.email}`,
    record.mobile_phone ? `Phone: ${record.mobile_phone}` : '',
    '',
    ...detail
      .filter(([, value]) => value && (!Array.isArray(value) || value.length))
      .map(([label, value]) => `${label}: ${Array.isArray(value) ? value.join(', ') : value}`),
    '',
    `Attribution: ${attribution || 'web'}`,
    `Marketing opt-in: ${record.marketing_consent ? 'Yes' : 'No'}`,
    `Received: ${new Date(record.created_at).toISOString().replace('T', ' ').slice(0, 19)} UTC`,
    '',
    `Admin portal: ${SITE_URL}/admin`,
  ]
    .filter((line) => line !== '')
    .join('\n');

  return sendEmail({
    to: NOTIFY_EMAIL,
    subject: `TGS ${isApparel ? 'apparel' : record.member_type || 'member'} — ${name || record.email}${
      record.placement ? ` (${record.placement})` : ''
    }`,
    html,
    text,
    tags: [isApparel ? 'apparel-interest-internal' : 'founding-access-internal'],
  });
}

/* ------------------------------------------------------------------ *
 * 4. Deletion confirmation
 * ------------------------------------------------------------------ */
export async function sendDeletionConfirmation({ email, first_name: firstName }) {
  const rejoinUrl = `${SITE_URL}/join?source=rejoin&channel=email`;

  const html = shell({
    preheader: 'Your information has been deleted from The Gated Shifter database.',
    body: `
      <p style="${EYEBROW}">Privacy &middot; Deletion</p>
      <h1 class="h1" style="${H1}">Your information has been deleted.</h1>
      <p style="${LEDE}">${escapeHtml(
        firstName || 'Thank you'
      )} — your record has been removed from our database and your contact record from our email system. Nothing was kept for later.</p>
      ${accent()}
      <p style="${P}">This is the last email you will receive from us. All we retain is a record that a deletion happened, which holds no personal information — a one-way hash instead of your address.</p>
      <p style="${P}">If you would like to be part of the Founders Registry another time, you are welcome to apply again.</p>

      ${gap(20)}
      ${button(rejoinUrl, 'Apply again')}

      ${gap(32)}
      ${rule(26)}
      <p style="${SIGNATURE}">One trusted ecosystem. Every aspect of analog ownership.</p>
    `,
    footer: `
      The Gated Shifter&trade; &middot; Private Ownership Platform
      ${gap(14)}
      ${footerLink(`${SITE_URL}/privacy`, 'Privacy')} &nbsp;&middot;&nbsp;
      ${footerLink(`mailto:${REPLY_TO}`, REPLY_TO)}
    `,
  });

  const text = [
    'Your information has been deleted.',
    '',
    'Your record has been removed from The Gated Shifter database and your contact record',
    'from our email system. Nothing was kept for later.',
    '',
    'This is the last email you will receive from us. All we retain is a record that a',
    'deletion happened, which holds no personal information.',
    '',
    'To apply again at any time:',
    rejoinUrl,
    '',
    `Privacy: ${SITE_URL}/privacy`,
    `Contact: ${REPLY_TO}`,
  ].join('\n');

  return sendEmail({
    to: email,
    subject: 'The Gated Shifter — your information has been deleted',
    html,
    text,
    tags: ['founding-access-deleted'],
  });
}

/* ------------------------------------------------------------------ *
 * Contact record. The marketing list is only touched when the member
 * asked for updates.
 * ------------------------------------------------------------------ */
export async function upsertBrevoContact(record) {
  return brevo('/contacts', {
    method: 'POST',
    body: JSON.stringify({
      email: record.email,
      updateEnabled: true,
      attributes: {
        FIRSTNAME: record.first_name || undefined,
        LASTNAME: record.last_name || undefined,
        SMS: record.mobile_phone || undefined,
        MEMBER_TYPE: record.member_type || undefined,
        CITY: record.city || undefined,
        MARQUES: record.primary_marques || undefined,
        LOOKING_FOR: (record.looking_for_now || []).join(', ') || undefined,
        APPAREL_ITEMS: (record.apparel_items || []).join(', ') || undefined,
        APPAREL_SIZE: record.apparel_size || undefined,
        SOURCE: record.source || undefined,
        CHANNEL: record.channel || undefined,
        PLACEMENT: record.placement || undefined,
        CAPTURED_BY: record.captured_by || undefined,
      },
      listIds: record.marketing_consent && LIST_ID ? [LIST_ID] : undefined,
    }),
  });
}

export async function deleteBrevoContact(email) {
  try {
    await brevo(`/contacts/${encodeURIComponent(email)}`, { method: 'DELETE' });
  } catch (err) {
    // A contact that was never created returns 404. Nothing to remove.
    if (!/returned 404/.test(err.message)) throw err;
  }
}