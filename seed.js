// Seeds base roles, the overtime rule, and a first admin account.
import 'dotenv/config';
import pg from 'pg';
import bcrypt from 'bcryptjs';

const pool = new pg.Pool({ connectionString: process.env.DATABASE_URL });

for (const [code, name] of [['ADMIN', 'Administrator'], ['HR', 'HR Officer'], ['PAYROLL', 'Payroll Officer'], ['SUPERVISOR', 'Supervisor'], ['EMPLOYEE', 'Employee']]) {
  await pool.query('INSERT INTO roles (code, name) VALUES ($1, $2) ON CONFLICT (code) DO NOTHING', [code, name]);
}
await pool.query(`INSERT INTO pay_rules (code, multiplier, description) VALUES ('OT_REGULAR', 1.25, 'Regular day overtime') ON CONFLICT (code) DO NOTHING`);

const emp = await pool.query(
  `INSERT INTO employees (employee_no, first_name, last_name, date_hired, pay_basis, basic_rate)
   VALUES ('EMP-001', 'System', 'Admin', CURRENT_DATE, 'MONTHLY', 20000)
   ON CONFLICT (employee_no) DO UPDATE SET employee_no = EXCLUDED.employee_no RETURNING id`
);
const hash = await bcrypt.hash('admin123', 10);
await pool.query(
  `INSERT INTO users (email, password_hash, role_id, employee_id)
   VALUES ('admin@plant.local', $1, (SELECT id FROM roles WHERE code = 'ADMIN'), $2)
   ON CONFLICT (email) DO NOTHING`,
  [hash, emp.rows[0].id]
);
console.log('Seeded. Login: admin@plant.local / admin123 (change this password).');
await pool.end();
