import pg from 'pg';

const { Pool } = pg;

if (!process.env.DATABASE_URL) {
  console.error('DATABASE_URL is not set. The app cannot store introduction requests.');
}

/**
 * SSL notes:
 *  - Render's INTERNAL database URL (same region, private network) does not require SSL.
 *  - Render's EXTERNAL URL, Supabase, Neon, etc. all require SSL.
 *  - Managed providers use certs that Node won't validate against its default CA bundle,
 *    so rejectUnauthorized:false is the standard setting here.
 * Set DATABASE_SSL=disable to turn SSL off entirely (local Postgres).
 */
const sslDisabled =
  process.env.DATABASE_SSL === 'disable' ||
  /localhost|127\.0\.0\.1/.test(process.env.DATABASE_URL || '');

export const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: sslDisabled ? false : { rejectUnauthorized: false },
  max: Number(process.env.PG_POOL_MAX || 5),
  idleTimeoutMillis: 30_000,
  connectionTimeoutMillis: 10_000,
});

pool.on('error', (err) => {
  console.error('Unexpected Postgres pool error:', err.message);
});

export async function query(text, params) {
  const started = Date.now();
  const res = await pool.query(text, params);
  const ms = Date.now() - started;
  if (ms > 500) console.warn(`Slow query (${ms}ms): ${text.slice(0, 80)}`);
  return res;
}

export async function healthcheck() {
  const { rows } = await query('select now() as now');
  return rows[0].now;
}