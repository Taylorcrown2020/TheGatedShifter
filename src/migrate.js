import { readdir, readFile } from 'node:fs/promises';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { pool, query } from './db.js';

const migrationsDir = join(dirname(fileURLToPath(import.meta.url)), '..', 'migrations');

export async function runMigrations() {
  await query(`
    create table if not exists schema_migrations (
      filename   text primary key,
      applied_at timestamptz not null default now()
    )
  `);

  const files = (await readdir(migrationsDir)).filter((f) => f.endsWith('.sql')).sort();
  const { rows } = await query('select filename from schema_migrations');
  const applied = new Set(rows.map((r) => r.filename));

  for (const file of files) {
    if (applied.has(file)) continue;
    const sql = await readFile(join(migrationsDir, file), 'utf8');
    const client = await pool.connect();
    try {
      await client.query('begin');
      await client.query(sql);
      await client.query('insert into schema_migrations (filename) values ($1)', [file]);
      await client.query('commit');
      console.log(`Migration applied: ${file}`);
    } catch (err) {
      await client.query('rollback');
      throw new Error(`Migration failed (${file}): ${err.message}`);
    } finally {
      client.release();
    }
  }
}

// Allow `npm run migrate` as a standalone command.
if (process.argv[1] && process.argv[1].endsWith('migrate.js')) {
  runMigrations()
    .then(() => {
      console.log('Migrations up to date.');
      return pool.end();
    })
    .catch((err) => {
      console.error(err.message);
      process.exit(1);
    });
}