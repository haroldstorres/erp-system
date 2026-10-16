// Resets a user's password (and re-activates the account).
// Usage: node reset-admin.js <email> <new-password>
import 'dotenv/config';
import pg from 'pg';
import bcrypt from 'bcryptjs';

const [email, password] = process.argv.slice(2);
if (!email || !password || password.length < 8) {
  console.error('Usage: node reset-admin.js <email> <new-password (min. 8 characters)>');
  process.exit(1);
}

const pool = new pg.Pool({ connectionString: process.env.DATABASE_URL });
const result = await pool.query(
  'UPDATE users SET password_hash = $1, is_active = TRUE WHERE email = $2',
  [await bcrypt.hash(password, 10), email.toLowerCase()]
);
console.log(result.rowCount ? 'Password reset for ' + email : 'No user found with that email');
await pool.end();
