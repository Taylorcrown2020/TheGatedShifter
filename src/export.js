// CSV dump of member_intake. Run with:
//   DATABASE_URL="<external url>" npm run export > member_intake.csv
import { pool, query } from './db.js';

const { rows } = await query(
  `select id,
          to_char(created_at, 'YYYY-MM-DD HH24:MI:SS') as created_at_utc,
          member_type, first_name, last_name, email, mobile_phone,
          city, state_region, country,
          primary_marques, collection_size, defining_vehicle, referred_by,
          specialist_needs as discipline, workshop_practice, proud_work, vouch_referral,
          partner_specialty as organization, partner_area, partnership_notes,
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

if (rows.length) {
  console.log(Object.keys(rows[0]).join(','));
  for (const row of rows) console.log(Object.values(row).map(escape).join(','));
} else {
  console.error('No rows in member_intake.');
}

await pool.end();