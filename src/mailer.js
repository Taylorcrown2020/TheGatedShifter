/**
 * Brevo email for The Gated Shifter.
 *
 * Three messages leave this file:
 *   1. Confirmation to the member, with a deletion link in the footer.
 *   2. Notification to private@gatedshifter.co that someone signed up.
 *   3. Confirmation that a deletion happened, with a link to sign up again.
 *
 * Nothing here throws into a request handler. A failed send is logged and
 * recorded against the row; the member's record is already safe.
 */

const BREVO_API = 'https://api.brevo.com/v3';
const API_KEY = process.env.BREVO_API_KEY || '';
const LIST_ID = process.env.BREVO_LIST_ID ? Number(process.env.BREVO_LIST_ID) : null;

const SITE_URL = (process.env.SITE_URL || 'https://www.gatedshifter.co').replace(/\/+$/, '');
const FROM_EMAIL = process.env.MAIL_FROM_EMAIL || 'private@gatedshifter.co';
const FROM_NAME = process.env.MAIL_FROM_NAME || 'The Gated Shifter';
const NOTIFY_EMAIL = process.env.NOTIFY_EMAIL || 'private@gatedshifter.co';
const REPLY_TO = process.env.MAIL_REPLY_TO || 'private@gatedshifter.co';

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
 * Shared email shell — dark, typeset, and readable with images blocked
 * ------------------------------------------------------------------ */
const escapeHtml = (value) =>
  String(value ?? '')
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;');

function shell({ preheader, body, footer }) {
  return `<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>The Gated Shifter</title></head>
<body style="margin:0;padding:0;background-color:#0B0C0E;">
<div style="display:none;font-size:1px;color:#0B0C0E;max-height:0;overflow:hidden;">${escapeHtml(preheader)}</div>
<table role="presentation" width="100%" cellpadding="0" cellspacing="0" style="background-color:#0B0C0E;padding:32px 16px;">
  <tr><td align="center">
    <table role="presentation" width="100%" cellpadding="0" cellspacing="0" style="max-width:560px;">
      <tr><td style="padding-bottom:28px;">
        <a href="${SITE_URL}/" style="text-decoration:none;">
          <img src="${SITE_URL}/assets/gated-shifter-logo.png" width="180" alt="The Gated Shifter"
               style="display:block;border:0;width:180px;max-width:60%;height:auto;">
        </a>
      </td></tr>
      <tr><td style="background-color:#171A1F;border:1px solid #2A2E33;border-radius:14px;padding:28px;">
        ${body}
      </td></tr>
      <tr><td style="padding-top:24px;font-family:Helvetica,Arial,sans-serif;font-size:12px;line-height:20px;color:#A7ABB2;">
        ${footer}
      </td></tr>
    </table>
  </td></tr>
</table>
</body></html>`;
}

const H1 = 'font-family:Georgia,\'Times New Roman\',serif;font-size:24px;line-height:32px;color:#EDEBE7;margin:0 0 14px;font-weight:normal;';
const P = 'font-family:Georgia,\'Times New Roman\',serif;font-size:15px;line-height:26px;color:#BFC3C7;margin:0 0 14px;';
const LABEL = 'font-family:Helvetica,Arial,sans-serif;font-size:11px;letter-spacing:0.14em;text-transform:uppercase;color:#A7ABB2;padding:0 12px 6px 0;vertical-align:top;white-space:nowrap;';
const VALUE = 'font-family:Georgia,\'Times New Roman\',serif;font-size:15px;line-height:24px;color:#EDEBE7;padding:0 0 6px;';

const button = (href, label) =>
  `<table role="presentation" cellpadding="0" cellspacing="0" style="margin:20px 0 4px;"><tr>
     <td style="background-color:#EDEBE7;border-radius:8px;">
       <a href="${href}" style="display:inline-block;padding:14px 26px;font-family:Helvetica,Arial,sans-serif;font-size:12px;font-weight:bold;letter-spacing:0.14em;text-transform:uppercase;color:#0B0C0E;text-decoration:none;">${escapeHtml(label)}</a>
     </td></tr></table>`;

/* ------------------------------------------------------------------ *
 * 1. Member confirmation
 * ------------------------------------------------------------------ */
export async function sendMemberConfirmation(record) {
  const removeUrl = `${SITE_URL}/remove?t=${encodeURIComponent(record.delete_token)}`;
  const firstName = record.first_name || 'there';

  const html = shell({
    preheader: 'The Gated Shifter has received your Founding Access request.',
    body: `
      <h1 style="${H1}">Your Founding Access request has been received.</h1>
      <p style="${P}">${escapeHtml(firstName)}, thank you. The Gated Shifter has your information and you will hear back directly.</p>
      <p style="${P}">The Founders Registry will include a limited number of Founding Collections, Founding Automobiles, Certified Specialists and Heritage Partners selected to help shape the platform. We read every request personally.</p>
      <table role="presentation" cellpadding="0" cellspacing="0" style="margin:20px 0 4px;">
        <tr><td style="${LABEL}">Registered as</td><td style="${VALUE}">${escapeHtml(record.member_type || '—')}</td></tr>
        <tr><td style="${LABEL}">Name</td><td style="${VALUE}">${escapeHtml([record.first_name, record.last_name].filter(Boolean).join(' '))}</td></tr>
        <tr><td style="${LABEL}">Email</td><td style="${VALUE}">${escapeHtml(record.email)}</td></tr>
        ${record.looking_for_now && record.looking_for_now.length
          ? `<tr><td style="${LABEL}">Looking for</td><td style="${VALUE}">${escapeHtml(record.looking_for_now.join(', '))}</td></tr>`
          : ''}
      </table>
      <p style="${P}">If anything above is wrong, reply to this email and we will correct it.</p>
      <p style="font-family:Georgia,'Times New Roman',serif;font-size:15px;line-height:26px;color:#EDEBE7;margin:18px 0 0;">One trusted ecosystem. Every aspect of analog ownership.</p>
    `,
    footer: `
      The Gated Shifter&trade; &middot; Private Ownership Platform &middot; In Development<br>
      Your details are held privately and never shared or sold.<br>
      <a href="${removeUrl}" style="color:#BFC3C7;">Delete my information from The Gated Shifter database</a><br>
      <a href="${SITE_URL}/privacy" style="color:#A7ABB2;">Privacy</a> &middot;
      <a href="mailto:${REPLY_TO}" style="color:#A7ABB2;">${REPLY_TO}</a>
    `,
  });

  const text = [
    'Your Founding Access request has been received.',
    '',
    `${firstName}, thank you. The Gated Shifter has your information and you will hear back directly.`,
    '',
    `Registered as: ${record.member_type || '-'}`,
    `Name: ${[record.first_name, record.last_name].filter(Boolean).join(' ')}`,
    `Email: ${record.email}`,
    record.looking_for_now && record.looking_for_now.length
      ? `Looking for: ${record.looking_for_now.join(', ')}`
      : '',
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
    toName: [record.first_name, record.last_name].filter(Boolean).join(' ') || undefined,
    subject: 'The Gated Shifter — your Founding Access request has been received',
    html,
    text,
    tags: ['founding-access-confirmation'],
  });
}

/* ------------------------------------------------------------------ *
 * 2. Internal notification
 * ------------------------------------------------------------------ */
export async function notifyPrivateInbox(record) {
  const row = (label, value) =>
    value === null || value === undefined || value === '' || (Array.isArray(value) && !value.length)
      ? ''
      : `<tr><td style="${LABEL}">${escapeHtml(label)}</td><td style="${VALUE}">${escapeHtml(
          Array.isArray(value) ? value.join(', ') : value
        )}</td></tr>`;

  const name = [record.first_name, record.last_name].filter(Boolean).join(' ');
  const attribution = [record.source, record.channel, record.placement, record.campaign, record.captured_by]
    .filter(Boolean)
    .join(' / ');

  const html = shell({
    preheader: `${record.member_type || 'Member'} — ${name} (${attribution})`,
    body: `
      <h1 style="${H1}">New Founding Access request</h1>
      <table role="presentation" cellpadding="0" cellspacing="0" style="margin:8px 0 0;">
        ${row('Record', `#${record.id}`)}
        ${row('Member type', record.member_type)}
        ${row('Name', name)}
        ${row('Email', record.email)}
        ${row('Mobile', record.mobile_phone)}
        ${row('City', record.city)}
        ${row('Marques of focus', record.primary_marques)}
        ${row('Collection size', record.collection_size)}
        ${row('Defining vehicle', record.defining_vehicle)}
        ${row('How they heard of us', record.referred_by)}
        ${row('Discipline', record.specialist_needs)}
        ${row('Workshop / practice', record.workshop_practice)}
        ${row('Proud work', record.proud_work)}
        ${row('Vouched for by', record.vouch_referral)}
        ${row('Organization', record.partner_specialty)}
        ${row('Partner area', record.partner_area)}
        ${row('Partnership notes', record.partnership_notes)}
        ${row('Looking for now', record.looking_for_now)}
        ${row('Notes', record.additional_notes)}
        ${row('Status', record.status)}
        ${row('Source', record.source)}
        ${row('Channel', record.channel)}
        ${row('Campaign', record.campaign)}
        ${row('Placement', record.placement)}
        ${row('Captured by', record.captured_by)}
        ${row('Referral code', record.referral_code)}
        ${row('Marketing opt-in', record.marketing_consent ? 'Yes' : 'No')}
        ${row('Founding access', record.founding_access ? 'Yes' : 'No')}
        ${row('Received', new Date(record.created_at).toISOString().replace('T', ' ').slice(0, 19) + ' UTC')}
      </table>
      ${record.status === 'REVIEW'
        ? `<p style="${P}">This email already exists in the database. The new submission was kept as its own record and flagged REVIEW so nothing is lost.</p>`
        : ''}
    `,
    footer: 'Sent by the gatedshifter.co enrollment form.',
  });

  const text = Object.entries({
    Record: `#${record.id}`,
    'Member type': record.member_type,
    Name: name,
    Email: record.email,
    Mobile: record.mobile_phone,
    City: record.city,
    'Marques / specialty': record.primary_marques,
    'Looking for now': (record.looking_for_now || []).join(', '),
    Notes: record.additional_notes,
    Status: record.status,
    Source: record.source,
    Channel: record.channel,
    Campaign: record.campaign,
    Placement: record.placement,
    'Captured by': record.captured_by,
    'Marketing opt-in': record.marketing_consent ? 'Yes' : 'No',
  })
    .filter(([, v]) => v)
    .map(([k, v]) => `${k}: ${v}`)
    .join('\n');

  return sendEmail({
    to: NOTIFY_EMAIL,
    subject: `TGS signup — ${record.member_type || 'Member'}: ${name || record.email}${
      record.placement ? ` (${record.placement})` : ''
    }`,
    html,
    text,
    tags: ['founding-access-internal'],
  });
}

/* ------------------------------------------------------------------ *
 * 3. Deletion confirmation
 * ------------------------------------------------------------------ */
export async function sendDeletionConfirmation({ email, first_name: firstName }) {
  const rejoinUrl = `${SITE_URL}/join?source=rejoin&channel=email`;

  const html = shell({
    preheader: 'Your information has been deleted from The Gated Shifter database.',
    body: `
      <h1 style="${H1}">Your information has been deleted.</h1>
      <p style="${P}">${escapeHtml(firstName || 'Thank you')} — your record has been removed from The Gated Shifter database and your contact record has been removed from our email system. Nothing was kept for later.</p>
      <p style="${P}">This is the last email you will receive from us.</p>
      <p style="${P}">If you would like to be part of the Founders Registry another time, you are welcome to sign up again.</p>
      ${button(rejoinUrl, 'Sign up again')}
    `,
    footer: `
      The Gated Shifter&trade; &middot; Private Ownership Platform<br>
      <a href="${SITE_URL}/privacy" style="color:#A7ABB2;">Privacy</a> &middot;
      <a href="mailto:${REPLY_TO}" style="color:#A7ABB2;">${REPLY_TO}</a>
    `,
  });

  const text = [
    'Your information has been deleted.',
    '',
    'Your record has been removed from The Gated Shifter database and your contact record has been removed from our email system.',
    'This is the last email you will receive from us.',
    '',
    'To sign up again at any time:',
    rejoinUrl,
    '',
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
 * ticked the optional updates box.
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