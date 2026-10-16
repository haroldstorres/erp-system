import 'dotenv/config';
import express from 'express';
import pg from 'pg';
import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';

const pool = new pg.Pool({ connectionString: process.env.DATABASE_URL });
const app = express();
app.use(express.json());
app.use(express.static('public'));

// Verify the JWT and optionally restrict access to the given roles
const auth = (...roles) => (req, res, next) => {
  try {
    const token = (req.headers.authorization || '').replace('Bearer ', '');
    req.user = jwt.verify(token, process.env.JWT_SECRET);
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

app.listen(process.env.PORT || 3000, () => console.log('Server running'));
