import 'dotenv/config';
import express from 'express';
import pg from 'pg';
import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';

if (!process.env.JWT_SECRET || process.env.JWT_SECRET.length < 32) {
  const msg = 'JWT_SECRET must be set and at least 32 characters long';
  if (process.env.NODE_ENV === 'production') { console.error(msg); process.exit(1); }
  console.warn('WARNING: ' + msg);
}

const pool = new pg.Pool({ connectionString: process.env.DATABASE_URL });
const app = express();
// Number of proxies in front of the app (Firebase Hosting -> Cloud Run). Used for req.ip.
app.set('trust proxy', Number(process.env.TRUST_PROXY ?? 1));
app.disable('x-powered-by');
app.use((_req, res, next) => {
  res.set({
    'X-Content-Type-Options': 'nosniff',
    'X-Frame-Options': 'DENY',
    'Referrer-Policy': 'no-referrer',
    'Strict-Transport-Security': 'max-age=15552000; includeSubDomains',
  });
  next();
});
app.use(express.json({ limit: '100kb' }));
app.use(express.static('public'));

// ---- Audit log (append-only; the database also blocks edits and deletes) ----
// Never pass passwords, hashes or tokens in oldV / newV.
const audit = (db, req, action, table, recordId, oldV = null, newV = null) =>
  db.query(
    `INSERT INTO audit_logs (user_id, action, table_name, record_id, old_values, new_values, ip_address)
     VALUES ($1, $2, $3, $4, $5, $6, $7)`,
    [req.user?.id ?? null, action, table, String(recordId),
     oldV && JSON.stringify(oldV), newV && JSON.stringify(newV), req.ip || null]);

// ---- Login throttling (stored in the database so it works across several instances) ----
const LOGIN_WINDOW = '15 minutes';
const MAX_FAILS_PER_EMAIL = 5;
const MAX_FAILS_PER_IP = 20;

async function loginBlocked(email, ip) {
  const { rows } = await pool.query(
    `SELECT COUNT(*) FILTER (WHERE record_id = $1) AS by_email,
            COUNT(*) FILTER (WHERE ip_address = $2::inet) AS by_ip
     FROM audit_logs
     WHERE action = 'LOGIN_FAILED' AND created_at > now() - interval '${LOGIN_WINDOW}'`,
    [email, ip || null]);
  return Number(rows[0].by_email) >= MAX_FAILS_PER_EMAIL || Number(rows[0].by_ip) >= MAX_FAILS_PER_IP;
}

// Verify the JWT, re-check the account in the database (so deactivation and
// role changes take effect immediately), and optionally restrict by role
const auth = (...roles) => async (req, res, next) => {
  try {
    const token = (req.headers.authorization || '').replace('Bearer ', '');
    const payload = jwt.verify(token, process.env.JWT_SECRET, { algorithms: ['HS256'] });
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
    // Raised by the payroll-lock triggers in db/migrations/001_hardening.sql
    if (e.code === 'P0001') return res.status(423).json({ error: e.message });
    console.error(e);
    res.status(500).json({ error: 'Server error' });
  });

app.post('/api/login', wrap(async (req, res) => {
  const email = typeof req.body.email === 'string' ? req.body.email.trim().toLowerCase() : '';
  const password = typeof req.body.password === 'string' ? req.body.password : '';
  if (!email || !password) return res.status(400).json({ error: 'Email and password are required' });

  if (await loginBlocked(email, req.ip)) {
    return res.status(429).json({ error: 'Too many failed attempts. Try again in 15 minutes.' });
  }
  const { rows } = await pool.query(
    `SELECT u.id, u.password_hash, u.employee_id, r.code AS role
     FROM users u JOIN roles r ON r.id = u.role_id
     WHERE lower(u.email) = $1 AND u.is_active`, [email]);
  const u = rows[0];
  if (!u || !(await bcrypt.compare(password, u.password_hash))) {
    await audit(pool, req, 'LOGIN_FAILED', 'users', email);
    return res.status(401).json({ error: 'Invalid email or password' });
  }
  await pool.query('UPDATE users SET last_login_at = now() WHERE id = $1', [u.id]);
  await audit(pool, { user: { id: u.id }, ip: req.ip }, 'LOGIN', 'users', u.id);
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
  await audit(pool, req, 'CREATE', 'employees', rows[0].id, null,
    { employee_no, first_name, last_name, date_hired, pay_basis, basic_rate });
  res.status(201).json(rows[0]);
}));

// Time in / time out for the logged-in employee
app.post('/api/attendance/punch', auth(), wrap(async (req, res) => {
  const { direction } = req.body;
  const emp = req.user.employeeId;
  if (!emp) return res.status(400).json({ error: 'Your account is not linked to an employee record. Ask an admin to link it.' });
  if (!['IN', 'OUT'].includes(direction)) return res.status(400).json({ error: 'Invalid request' });

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

// Gross pay for a date range (no statutory deductions yet). Shared by the
// preview and by payroll runs so both always show the same figures.
async function computePayroll(db, from, to) {
  const rule = await db.query(`SELECT multiplier FROM pay_rules WHERE code = 'OT_REGULAR'`);
  const otMultiplier = Number(rule.rows[0]?.multiplier ?? 1.25);

  const { rows } = await db.query(
    `SELECT e.id, e.employee_no, e.first_name || ' ' || e.last_name AS name, e.pay_basis, e.basic_rate,
            COUNT(a.id) FILTER (WHERE a.time_out IS NOT NULL) AS days,
            COALESCE(SUM(a.regular_hours), 0) AS reg_hours,
            COALESCE(SUM(a.overtime_hours), 0) AS ot_hours
     FROM employees e
     LEFT JOIN attendance_daily a ON a.employee_id = e.id AND a.work_date BETWEEN $1 AND $2
     WHERE e.status IN ('PROBATIONARY', 'REGULAR', 'CONTRACTUAL')
     GROUP BY e.id ORDER BY e.employee_no`, [from, to]);

  return rows.map((r) => {
    const rate = Number(r.basic_rate);
    const days = Number(r.days), reg = Number(r.reg_hours), ot = Number(r.ot_hours);
    // Semi-monthly pay for monthly staff; 313-day factor for the hourly equivalent
    const hourly = r.pay_basis === 'MONTHLY' ? (rate * 12) / 313 / 8 : r.pay_basis === 'DAILY' ? rate / 8 : rate;
    const basic = r.pay_basis === 'MONTHLY' ? rate / 2 : r.pay_basis === 'DAILY' ? rate * days : rate * reg;
    const otPay = ot * hourly * otMultiplier;
    return { employee_id: r.id, employee_no: r.employee_no, name: r.name, pay_basis: r.pay_basis,
             rate, hourly, ot_multiplier: otMultiplier,
             days, reg_hours: reg, ot_hours: ot,
             basic_pay: +basic.toFixed(2), ot_pay: +otPay.toFixed(2), gross_pay: +(basic + otPay).toFixed(2) };
  });
}

const isDate = (v) => typeof v === 'string' && /^\d{4}-\d{2}-\d{2}$/.test(v) && !Number.isNaN(Date.parse(v));

app.get('/api/payroll/preview', auth('ADMIN', 'PAYROLL'), wrap(async (req, res) => {
  const { from, to } = req.query;
  if (!isDate(from) || !isDate(to)) return res.status(400).json({ error: 'Select a date range' });
  const rows = await computePayroll(pool, from, to);
  res.json(rows.map(({ employee_id, pay_basis, rate, hourly, ot_multiplier, ...r }) => r));
}));

// ---- Payroll runs: DRAFT -> FOR_APPROVAL -> APPROVED -> LOCKED -> PAID ----
// Once a run is APPROVED, its attendance and payslips are frozen by the database.
// The person who prepared a run cannot approve it.

// Create (or rebuild, while still DRAFT) the payroll run for a period
app.post('/api/payroll/runs', auth('ADMIN', 'PAYROLL'), wrap(async (req, res) => {
  const { from, to, label } = req.body;
  const payDate = req.body.pay_date || to;
  if (![from, to, payDate].every(isDate) || from > to) return res.status(400).json({ error: 'Valid from, to and pay date are required' });

  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    const nextDay = new Date(Date.parse(to) + 864e5);
    const period = await client.query(
      `INSERT INTO pay_periods (label, date_from, date_to, pay_date, is_last_of_month)
       VALUES ($1, $2, $3, $4, $5)
       ON CONFLICT (date_from, date_to) DO UPDATE SET pay_date = EXCLUDED.pay_date
       RETURNING id`,
      [label || `${from} to ${to}`, from, to, payDate, nextDay.getUTCDate() === 1]);
    const periodId = period.rows[0].id;

    let run = (await client.query(
      'SELECT id, status FROM payroll_runs WHERE pay_period_id = $1 FOR UPDATE', [periodId])).rows[0];
    if (run && run.status !== 'DRAFT') {
      await client.query('ROLLBACK');
      return res.status(409).json({ error: `A payroll run for this period already exists and is ${run.status}` });
    }
    if (run) {
      await client.query('DELETE FROM payslips WHERE payroll_run_id = $1', [run.id]);
      await client.query('UPDATE payroll_runs SET prepared_by = $2 WHERE id = $1', [run.id, req.user.id]);
    } else {
      run = (await client.query(
        `INSERT INTO payroll_runs (pay_period_id, prepared_by) VALUES ($1, $2) RETURNING id, status`,
        [periodId, req.user.id])).rows[0];
    }

    const lines = await computePayroll(client, from, to);
    let total = 0;
    for (const l of lines) {
      const slip = await client.query(
        `INSERT INTO payslips (payroll_run_id, employee_id, gross_pay, total_deductions, net_pay, taxable_income)
         VALUES ($1, $2, $3, 0, $3, $3) RETURNING id`, [run.id, l.employee_id, l.gross_pay]);
      const qty = l.pay_basis === 'MONTHLY' ? null : l.pay_basis === 'DAILY' ? l.days : l.reg_hours;
      await client.query(
        `INSERT INTO payslip_lines (payslip_id, line_type, code, description, quantity, rate, amount)
         VALUES ($1, 'EARNING', 'BASIC', 'Basic pay', $2, $3, $4)`, [slip.rows[0].id, qty, l.rate, l.basic_pay]);
      if (l.ot_hours > 0) {
        await client.query(
          `INSERT INTO payslip_lines (payslip_id, line_type, code, description, quantity, rate, amount)
           VALUES ($1, 'EARNING', 'OT', 'Overtime', $2, $3, $4)`,
          [slip.rows[0].id, l.ot_hours, +(l.hourly * l.ot_multiplier).toFixed(4), l.ot_pay]);
      }
      total += l.gross_pay;
    }
    await audit(client, req, 'CREATE', 'payroll_runs', run.id, null,
      { from, to, employees: lines.length, gross_total: +total.toFixed(2) });
    await client.query('COMMIT');
    res.status(201).json({ id: run.id, status: 'DRAFT', employees: lines.length, gross_total: +total.toFixed(2) });
  } catch (e) {
    await client.query('ROLLBACK').catch(() => {});
    throw e;
  } finally {
    client.release();
  }
}));

app.get('/api/payroll/runs', auth('ADMIN', 'PAYROLL'), wrap(async (_req, res) => {
  const { rows } = await pool.query(
    `SELECT r.id, r.status, r.created_at, r.locked_at, pp.label, pp.date_from::text, pp.date_to::text, pp.pay_date::text,
            COUNT(s.id) AS employees, COALESCE(SUM(s.gross_pay), 0) AS gross_total
     FROM payroll_runs r JOIN pay_periods pp ON pp.id = r.pay_period_id
     LEFT JOIN payslips s ON s.payroll_run_id = r.id
     GROUP BY r.id, pp.id ORDER BY pp.date_from DESC`);
  res.json(rows);
}));

app.get('/api/payroll/runs/:id', auth('ADMIN', 'PAYROLL'), wrap(async (req, res) => {
  if (!/^\d+$/.test(req.params.id)) return res.status(404).json({ error: 'Not found' });
  const run = await pool.query(
    `SELECT r.id, r.status, r.prepared_by, r.approved_by, r.locked_at, pp.label, pp.date_from::text, pp.date_to::text, pp.pay_date::text
     FROM payroll_runs r JOIN pay_periods pp ON pp.id = r.pay_period_id WHERE r.id = $1`, [req.params.id]);
  if (!run.rows[0]) return res.status(404).json({ error: 'Not found' });
  const slips = await pool.query(
    `SELECT s.id, e.employee_no, e.first_name || ' ' || e.last_name AS name, s.gross_pay, s.total_deductions, s.net_pay
     FROM payslips s JOIN employees e ON e.id = s.employee_id
     WHERE s.payroll_run_id = $1 ORDER BY e.employee_no`, [req.params.id]);
  res.json({ ...run.rows[0], payslips: slips.rows });
}));

const RUN_STEPS = {
  submit:  { from: 'DRAFT',        to: 'FOR_APPROVAL', roles: ['ADMIN', 'PAYROLL'] },
  reject:  { from: 'FOR_APPROVAL', to: 'DRAFT',        roles: ['ADMIN'] },
  approve: { from: 'FOR_APPROVAL', to: 'APPROVED',     roles: ['ADMIN'], notPreparer: true },
  lock:    { from: 'APPROVED',     to: 'LOCKED',       roles: ['ADMIN', 'PAYROLL'] },
  pay:     { from: 'LOCKED',       to: 'PAID',         roles: ['ADMIN'] },
};

app.post('/api/payroll/runs/:id/:step', auth('ADMIN', 'PAYROLL'), wrap(async (req, res) => {
  const step = RUN_STEPS[req.params.step];
  if (!step || !/^\d+$/.test(req.params.id)) return res.status(404).json({ error: 'Not found' });
  if (!step.roles.includes(req.user.role)) return res.status(403).json({ error: 'Forbidden' });

  const { rows } = await pool.query(
    `UPDATE payroll_runs SET status = $3::payroll_status,
       approved_by = CASE WHEN $3::text = 'APPROVED' THEN $4::uuid ELSE approved_by END,
       locked_at   = CASE WHEN $3::text = 'LOCKED' THEN now() ELSE locked_at END
     WHERE id = $1 AND status = $2::payroll_status AND ($5::boolean = false OR prepared_by IS DISTINCT FROM $4::uuid)
     RETURNING id, status`,
    [req.params.id, step.from, step.to, req.user.id, !!step.notPreparer]);
  if (!rows[0]) {
    const cur = await pool.query('SELECT status, prepared_by FROM payroll_runs WHERE id = $1', [req.params.id]);
    if (!cur.rows[0]) return res.status(404).json({ error: 'Not found' });
    if (cur.rows[0].status === step.from && step.notPreparer) {
      return res.status(403).json({ error: 'The person who prepared this payroll cannot approve it' });
    }
    return res.status(409).json({ error: `Run is ${cur.rows[0].status}; it must be ${step.from} for this step` });
  }
  await audit(pool, req, req.params.step.toUpperCase(), 'payroll_runs', req.params.id, { status: step.from }, { status: step.to });
  res.json(rows[0]);
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
  await audit(pool, req, 'PASSWORD_CHANGE', 'users', req.user.id);
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
    await audit(pool, req, 'CREATE', 'users', rows[0].id, null, { email: email.trim().toLowerCase(), role, employee_id: employee_id || null });
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
  const before = await pool.query(
    'SELECT r.code AS role, u.is_active FROM users u JOIN roles r ON r.id = u.role_id WHERE u.id = $1', [req.params.id]);
  if (!before.rows[0]) return res.status(404).json({ error: 'User not found' });
  await pool.query(
    `UPDATE users SET
       role_id = COALESCE((SELECT id FROM roles WHERE code = $2), role_id),
       is_active = COALESCE($3, is_active)
     WHERE id = $1`, [req.params.id, role ?? null, is_active ?? null]);
  await audit(pool, req, 'UPDATE', 'users', req.params.id, before.rows[0],
    { role: role ?? before.rows[0].role, is_active: is_active ?? before.rows[0].is_active });
  res.json({ ok: true });
}));

app.post('/api/users/:id/reset-password', auth('ADMIN'), wrap(async (req, res) => {
  const { new_password } = req.body;
  if (!new_password || new_password.length < MIN_PASSWORD) {
    return res.status(400).json({ error: `Password must be at least ${MIN_PASSWORD} characters` });
  }
  const r = await pool.query('UPDATE users SET password_hash = $1 WHERE id = $2', [await bcrypt.hash(new_password, 10), req.params.id]);
  if (!r.rowCount) return res.status(404).json({ error: 'User not found' });
  await audit(pool, req, 'PASSWORD_RESET', 'users', req.params.id);
  res.json({ ok: true });
}));

app.listen(process.env.PORT || 3000, () => console.log('Server running'));
