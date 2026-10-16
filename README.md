# Plant ERP - HR, Attendance & Payroll

Early-stage web app for a plant that manufactures RS alcohol, bioethanol and
liquid CO2. This repository currently contains the HR, attendance and payroll
slice. Production, inventory and QC modules are planned.

**Status:** work in progress. Not ready for real payroll use.

## Stack

- Node.js + Express (API)
- PostgreSQL
- React (served as a static page from `public/`)

## Setup

1. Create a PostgreSQL database and apply the schema:
   ```
   psql "$DATABASE_URL" -f db/schema.sql
   ```
2. Apply the hardening migration (audit log protection, payroll lock). Safe to run again:
   ```
   psql "$DATABASE_URL" -f db/migrations/001_hardening.sql
   ```
3. Copy `.env.example` to `.env` and fill in `DATABASE_URL` and `JWT_SECRET`.
4. Install dependencies and seed the base data:
   ```
   npm install
   npm run seed
   ```
5. Start the server and open http://localhost:3000:
   ```
   npm start
   ```

The seed script creates a development admin account (`admin@plant.local`).
Change its password immediately and never deploy it as-is.

## Current features

- Login with role-based access (Admin, HR, Payroll, Employee)
- Employee list and creation
- Web time in / time out with regular and overtime hours
- Gross pay preview for a date range
- Payroll runs: DRAFT -> FOR_APPROVAL -> APPROVED -> LOCKED -> PAID. The person who
  prepared a run cannot approve it (use two accounts). From APPROVED onward the database
  blocks changes to the payslips and to attendance inside that period.
- Audit log (append-only) for logins, failed logins, user and employee changes, payroll steps
- Login throttling: 5 failed attempts per email or 20 per IP in 15 minutes returns 429

## Not yet implemented

- Statutory deductions, loans, holiday and night differential pay
- Overnight shifts, attendance corrections and overtime approval
- Leave management, payslip PDFs
- Audit log viewer screen and encryption of government IDs
- Frontend screens for payroll runs (API only for now: `/api/payroll/runs`)

## Security notes

- Never commit `.env` or real employee data.
- Use fake data for development and testing.
- Set a strong `JWT_SECRET` (32+ characters; the server exits in production if shorter) and use HTTPS.
- Set `TRUST_PROXY` to the number of proxies in front of the app (default 1) so the login throttle sees real client IPs.
- A locked-out email can be retried after 15 minutes; an attacker can also keep a known email locked out. Add a captcha or MFA later if that matters.
