// One-off CSV dump of member_intake. Run with:
//   DATABASE_URL="<external url>" npm run export > intake.csv
import { pool, query } from './db.js';

const { rows } = await query(
  `select id,
          to_char(created_at, 'YYYY-MM-DD HH24:MI:SS') as created_at_utc,
          full_name, email, phone, referred_by,
          marques, message, consent, source, status
     from member_intake
    order by created_at desc`
);

const escape = (v) => `"${String(v ?? '').replace(/"/g, '""')}"`;
if (rows.length) {
  console.log(Object.keys(rows[0]).join(','));
  for (const row of rows) console.log(Object.values(row).map(escape).join(','));
} else {
  console.error('No rows in member_intake.');
}
await pool.end();