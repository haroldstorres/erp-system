import 'dotenv/config';
import express from 'express';
import pg from 'pg';
import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';

const pool = new pg.Pool({ connectionString: process.env.DATABASE_URL });
const app = express();
app.use(express.json());
app.use(express.static('public'));

// Verify the JWT, re-check the account in the database (so deactivation and
// role changes take effect immediately), and optionally restrict by role
const auth = (...roles) => async (req, res, next) => {
  try {
    const token = (req.headers.authorization || '').replace('Bearer ', '');
    const payload = jwt.verify(token, process.env.JWT_SECRET);
    const { rows } = await pool.query(
      `SELECT u.is_active, u.employee_id, r.code AS role
       FROM users u JOIN roles r ON r.id = u.role_id WHERE u.id = $1`, [payload.id]);
    if (!rows[0] || !rows[0].is_active) return res.status(401).json({ error: 'Unauthorized' });
    req.user = { id: payload.id, role: rows[0].role, employeeId: rows[0].employee_id };
    if (roles.length && !roles.includes(req.user.role)) return res.status(403).json({ error: 'Forbidden' });
    next();
  } catch {
    res.status(401).json({ error: 'Unauthorized' });
  }
};

// Catch async errors so a failed query never crashes the server
const wrap = (fn) => (req, res) =>
  fn(req, res).catch((e) => {
    console.error(e);
    res.status(500).json({ error: 'Server error' });
  });

app.post('/api/login', wrap(async (req, res) => {
  const { email, password } = req.body;
  const { rows } = await pool.query(
    `SELECT u.id, u.password_hash, u.employee_id, r.code AS role
     FROM users u JOIN roles r ON r.id = u.role_id
     WHERE u.email = $1 AND u.is_active`, [email]);
  const u = rows[0];
  if (!u || !(await bcrypt.compare(password, u.password_hash))) {
    return res.status(401).json({ error: 'Invalid email or password' });
  }
  await pool.query('UPDATE users SET last_login_at = now() WHERE id = $1', [u.id]);
  const token = jwt.sign({ id: u.id, role: u.role, employeeId: u.employee_id }, process.env.JWT_SECRET, { expiresIn: '8h' });
  res.json({ token, role: u.role });
}));

app.get('/api/employees', auth('ADMIN', 'HR', 'PAYROLL'), wrap(async (_req, res) => {
  const { rows } = await pool.query(
    `SELECT id, employee_no, first_name, last_name, status, pay_basis, basic_rate, date_hired
     FROM employees ORDER BY employee_no`);
  res.json(rows);
}));

app.post('/api/employees', auth('ADMIN', 'HR'), wrap(async (req, res) => {
  const { employee_no, first_name, last_name, date_hired, pay_basis, basic_rate } = req.body;
  const { rows } = await pool.query(
    `INSERT INTO employees (employee_no, first_name, last_name, date_hired, pay_basis, basic_rate)
     VALUES ($1, $2, $3, $4, $5, $6) RETURNING id`,
    [employee_no, first_name, last_name, date_hired, pay_basis, basic_rate]);
  res.status(201).json(rows[0]);
}));

// Time in / time out for the logged-in employee
app.post('/api/attendance/punch', auth(), wrap(async (req, res) => {
  const { direction } = req.body;
  const emp = req.user.employeeId;
  if (!emp || !['IN', 'OUT'].includes(direction)) return res.status(400).json({ error: 'Invalid request' });

  await pool.query(
    `INSERT INTO attendance_logs (employee_id, punched_at, direction, source) VALUES ($1, now(), $2, 'WEB')`,
    [emp, direction]);

  if (direction === 'IN') {
    await pool.query(
      `INSERT INTO attendance_daily (employee_id, work_date, time_in)
       VALUES ($1, CURRENT_DATE, now()) ON CONFLICT (employee_id, work_date) DO NOTHING`, [emp]);
  } else {
    const { rows } = await pool.query(
      'SELECT time_in FROM attendance_daily WHERE employee_id = $1 AND work_date = CURRENT_DATE', [emp]);
    if (!rows[0]) return res.status(400).json({ error: 'No time-in found for today' });
    let hours = (Date.now() - new Date(rows[0].time_in)) / 36e5;
    if (hours > 5) hours -= 1; // unpaid one-hour break
    const regular = Math.min(hours, 8);
    const overtime = Math.max(hours - 8, 0);
    await pool.query(
      `UPDATE attendance_daily SET time_out = now(), regular_hours = $2, overtime_hours = $3
       WHERE employee_id = $1 AND work_date = CURRENT_DATE`,
      [emp, regular.toFixed(2), overtime.toFixed(2)]);
  }
  res.json({ ok: true });
}));

app.get('/api/attendance/me', auth(), wrap(async (req, res) => {
  const { rows } = await pool.query(
    `SELECT work_date, time_in, time_out, regular_hours, overtime_hours
     FROM attendance_daily WHERE employee_id = $1 ORDER BY work_date DESC LIMIT 14`,
    [req.user.employeeId]);
  res.json(rows);
}));

// Gross pay preview only (no statutory deductions yet)
app.get('/api/payroll/preview', auth('ADMIN', 'PAYROLL'), wrap(async (req, res) => {
  const { from, to } = req.query;
  if (!from || !to) return res.status(400).json({ error: 'Select a date range' });

  const rule = await pool.query(`SELECT multiplier FROM pay_rules WHERE code = 'OT_REGULAR'`);
  const otMultiplier = Number(rule.rows[0]?.multiplier ?? 1.25);

  const { rows } = await pool.query(
    `SELECT e.employee_no, e.first_name || ' ' || e.last_name AS name, e.pay_basis, e.basic_rate,
            COUNT(a.id) FILTER (WHERE a.time_out IS NOT NULL) AS days,
            COALESCE(SUM(a.regular_hours), 0) AS reg_hours,
            COALESCE(SUM(a.overtime_hours), 0) AS ot_hours
     FROM employees e
     LEFT JOIN attendance_daily a ON a.employee_id = e.id AND a.work_date BETWEEN $1 AND $2
     WHERE e.status IN ('PROBATIONARY', 'REGULAR', 'CONTRACTUAL')
     GROUP BY e.id ORDER BY e.employee_no`, [from, to]);

  res.json(rows.map((r) => {
    const rate = Number(r.basic_rate);
    const days = Number(r.days), reg = Number(r.reg_hours), ot = Number(r.ot_hours);
    // Semi-monthly pay for monthly staff; 313-day factor for the hourly equivalent
    const hourly = r.pay_basis === 'MONTHLY' ? (rate * 12) / 313 / 8 : r.pay_basis === 'DAILY' ? rate / 8 : rate;
    const basic = r.pay_basis === 'MONTHLY' ? rate / 2 : r.pay_basis === 'DAILY' ? rate * days : rate * reg;
    const otPay = ot * hourly * otMultiplier;
    return { employee_no: r.employee_no, name: r.name, days, reg_hours: reg, ot_hours: ot,
             basic_pay: +basic.toFixed(2), ot_pay: +otPay.toFixed(2), gross_pay: +(basic + otPay).toFixed(2) };
  }));
}));

// ---- Account and user management ----
const MIN_PASSWORD = 8;
const ROLE_CODES = ['ADMIN', 'HR', 'PAYROLL', 'SUPERVISOR', 'EMPLOYEE'];

// Any logged-in user can change their own password
app.post('/api/me/password', auth(), wrap(async (req, res) => {
  const { current_password, new_password } = req.body;
  if (!new_password || new_password.length < MIN_PASSWORD) {
    return res.status(400).json({ error: `New password must be at least ${MIN_PASSWORD} characters` });
  }
  const { rows } = await pool.query('SELECT password_hash FROM users WHERE id = $1', [req.user.id]);
  if (!rows[0] || !(await bcrypt.compare(current_password || '', rows[0].password_hash))) {
    return res.status(400).json({ error: 'Current password is incorrect' });
  }
  await pool.query('UPDATE users SET password_hash = $1 WHERE id = $2', [await bcrypt.hash(new_password, 10), req.user.id]);
  res.json({ ok: true });
}));

app.get('/api/users', auth('ADMIN'), wrap(async (_req, res) => {
  const { rows } = await pool.query(
    `SELECT u.id, u.email, u.is_active, u.last_login_at, r.code AS role,
            e.employee_no, e.first_name || ' ' || e.last_name AS employee_name
     FROM users u JOIN roles r ON r.id = u.role_id
     LEFT JOIN employees e ON e.id = u.employee_id
     ORDER BY u.email`);
  res.json(rows);
}));

app.post('/api/users', auth('ADMIN'), wrap(async (req, res) => {
  const { email, password, role, employee_id } = req.body;
  if (!email || !ROLE_CODES.includes(role)) return res.status(400).json({ error: 'Email and a valid role are required' });
  if (!password || password.length < MIN_PASSWORD) {
    return res.status(400).json({ error: `Password must be at least ${MIN_PASSWORD} characters` });
  }
  try {
    const { rows } = await pool.query(
      `INSERT INTO users (email, password_hash, role_id, employee_id)
       VALUES ($1, $2, (SELECT id FROM roles WHERE code = $3), $4) RETURNING id`,
      [email.trim().toLowerCase(), await bcrypt.hash(password, 10), role, employee_id || null]);
    res.status(201).json(rows[0]);
  } catch (e) {
    if (e.code === '23505') return res.status(409).json({ error: 'That email is already in use' });
    throw e;
  }
}));

// Change a user's role or active status
app.patch('/api/users/:id', auth('ADMIN'), wrap(async (req, res) => {
  const { role, is_active } = req.body;
  if (role !== undefined && !ROLE_CODES.includes(role)) return res.status(400).json({ error: 'Invalid role' });
  // Prevent an admin from locking themselves out
  if (req.params.id === req.user.id && (is_active === false || (role !== undefined && role !== 'ADMIN'))) {
    return res.status(400).json({ error: 'You cannot deactivate or demote your own account' });
  }
  await pool.query(
    `UPDATE users SET
       role_id = COALESCE((SELECT id FROM roles WHERE code = $2), role_id),
       is_active = COALESCE($3, is_active)
     WHERE id = $1`, [req.params.id, role ?? null, is_active ?? null]);
  res.json({ ok: true });
}));

app.post('/api/users/:id/reset-password', auth('ADMIN'), wrap(async (req, res) => {
  const { new_password } = req.body;
  if (!new_password || new_password.length < MIN_PASSWORD) {
    return res.status(400).json({ error: `Password must be at least ${MIN_PASSWORD} characters` });
  }
  await pool.query('UPDATE users SET password_hash = $1 WHERE id = $2', [await bcrypt.hash(new_password, 10), req.params.id]);
  res.json({ ok: true });
}));

app.listen(process.env.PORT || 3000, () => console.log('Server running'));
