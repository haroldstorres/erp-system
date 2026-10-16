// Applies one SQL file to the database in DATABASE_URL (no psql needed).
// Usage: node migrate.js db/migrations/001_hardening.sql
import 'dotenv/config';
import fs from 'node:fs';
import pg from 'pg';

const file = process.argv[2];
if (!file || !fs.existsSync(file)) {
  console.error('Usage: node migrate.js <path-to-sql-file>');
  process.exit(1);
}
if (!process.env.DATABASE_URL) {
  console.error('DATABASE_URL is not set (check your .env)');
  process.exit(1);
}

const client = new pg.Client({ connectionString: process.env.DATABASE_URL });
await client.connect();
try {
  await client.query('BEGIN');
  await client.query(fs.readFileSync(file, 'utf8'));
  await client.query('COMMIT');
  console.log('Migration applied: ' + file);
} catch (e) {
  await client.query('ROLLBACK').catch(() => {});
  console.error('Migration failed, nothing was changed: ' + e.message);
  process.exitCode = 1;
} finally {
  await client.end();
}
