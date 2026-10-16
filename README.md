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
2. Copy `.env.example` to `.env` and fill in `DATABASE_URL` and `JWT_SECRET`.
3. Install dependencies and seed the base data:
   ```
   npm install
   npm run seed
   ```
4. Start the server and open http://localhost:3000:
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

## Not yet implemented

- Statutory deductions, loans, holiday and night differential pay
- Overnight shifts, attendance corrections and overtime approval
- Leave management, payslip PDFs, payroll run locking
- Audit logging and encryption of government IDs

## Security notes

- Never commit `.env` or real employee data.
- Use fake data for development and testing.
- Set a strong `JWT_SECRET` and use HTTPS in production.
