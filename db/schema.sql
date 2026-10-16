-- =====================================================================
-- HR, Attendance & Payroll module (PostgreSQL)
-- Part of the plant ERP (RS alcohol, bioethanol, liquid CO2)
-- =====================================================================

CREATE EXTENSION IF NOT EXISTS "pgcrypto";

-- ---------------------------------------------------------------------
-- 1. Access control
-- ---------------------------------------------------------------------
CREATE TABLE roles (
    id          SMALLSERIAL PRIMARY KEY,
    code        TEXT UNIQUE NOT NULL,          -- ADMIN, HR, PAYROLL, SUPERVISOR, EMPLOYEE
    name        TEXT NOT NULL
);

CREATE TABLE users (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    email           TEXT UNIQUE NOT NULL,
    password_hash   TEXT NOT NULL,
    role_id         SMALLINT NOT NULL REFERENCES roles(id),
    employee_id     UUID,                       -- linked below after employees is created
    is_active       BOOLEAN NOT NULL DEFAULT TRUE,
    last_login_at   TIMESTAMPTZ,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- ---------------------------------------------------------------------
-- 2. Organization and employees (201 file)
-- ---------------------------------------------------------------------
CREATE TABLE departments (
    id      SERIAL PRIMARY KEY,
    code    TEXT UNIQUE NOT NULL,               -- PRODUCTION, LAB, WAREHOUSE, CO2_PLANT, ADMIN
    name    TEXT NOT NULL
);

CREATE TABLE positions (
    id              SERIAL PRIMARY KEY,
    title           TEXT NOT NULL,
    department_id   INT REFERENCES departments(id)
);

CREATE TYPE pay_basis AS ENUM ('MONTHLY', 'DAILY', 'HOURLY');
CREATE TYPE employment_status AS ENUM ('PROBATIONARY', 'REGULAR', 'CONTRACTUAL', 'RESIGNED', 'TERMINATED');

CREATE TABLE employees (
    id                  UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    employee_no         TEXT UNIQUE NOT NULL,
    first_name          TEXT NOT NULL,
    middle_name         TEXT,
    last_name           TEXT NOT NULL,
    birth_date          DATE,
    mobile              TEXT,
    email               TEXT,
    address             TEXT,
    department_id       INT REFERENCES departments(id),
    position_id         INT REFERENCES positions(id),
    supervisor_id       UUID REFERENCES employees(id),
    status              employment_status NOT NULL DEFAULT 'PROBATIONARY',
    date_hired          DATE NOT NULL,
    date_separated      DATE,
    pay_basis           pay_basis NOT NULL,
    basic_rate          NUMERIC(12,2) NOT NULL,   -- per month, per day or per hour depending on pay_basis
    -- Government IDs: encrypt at the application level before saving
    sss_no_enc          BYTEA,
    philhealth_no_enc   BYTEA,
    pagibig_no_enc      BYTEA,
    tin_enc             BYTEA,
    bank_account_enc    BYTEA,
    badge_code          TEXT UNIQUE,              -- QR / ID card / biometric ID
    created_at          TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at          TIMESTAMPTZ NOT NULL DEFAULT now()
);

ALTER TABLE users
    ADD CONSTRAINT fk_users_employee FOREIGN KEY (employee_id) REFERENCES employees(id);

-- Rate history so past payrolls can always be reproduced
CREATE TABLE employee_rate_history (
    id              BIGSERIAL PRIMARY KEY,
    employee_id     UUID NOT NULL REFERENCES employees(id),
    basic_rate      NUMERIC(12,2) NOT NULL,
    pay_basis       pay_basis NOT NULL,
    effective_from  DATE NOT NULL,
    reason          TEXT,
    created_by      UUID REFERENCES users(id)
);

CREATE TABLE employee_documents (
    id              BIGSERIAL PRIMARY KEY,
    employee_id     UUID NOT NULL REFERENCES employees(id),
    doc_type        TEXT NOT NULL,                -- CONTRACT, MEDICAL, CERTIFICATE, MEMO
    file_url        TEXT NOT NULL,
    uploaded_at     TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- ---------------------------------------------------------------------
-- 3. Shifts, holidays and attendance
-- ---------------------------------------------------------------------
CREATE TABLE shifts (
    id                  SERIAL PRIMARY KEY,
    code                TEXT UNIQUE NOT NULL,     -- DAY, MID, NIGHT
    start_time          TIME NOT NULL,
    end_time            TIME NOT NULL,
    crosses_midnight    BOOLEAN NOT NULL DEFAULT FALSE,
    break_minutes       INT NOT NULL DEFAULT 60,
    grace_minutes       INT NOT NULL DEFAULT 0
);

CREATE TABLE shift_assignments (
    id              BIGSERIAL PRIMARY KEY,
    employee_id     UUID NOT NULL REFERENCES employees(id),
    shift_id        INT NOT NULL REFERENCES shifts(id),
    work_date       DATE NOT NULL,
    is_rest_day     BOOLEAN NOT NULL DEFAULT FALSE,
    UNIQUE (employee_id, work_date)
);

CREATE TYPE holiday_type AS ENUM ('REGULAR', 'SPECIAL_NON_WORKING', 'SPECIAL_WORKING');

CREATE TABLE holidays (
    holiday_date    DATE PRIMARY KEY,
    name            TEXT NOT NULL,
    type            holiday_type NOT NULL
);

-- Raw punches (from web, QR, mobile geofence or imported biometric logs)
CREATE TYPE punch_source AS ENUM ('WEB', 'QR', 'MOBILE', 'BIOMETRIC', 'MANUAL');

CREATE TABLE attendance_logs (
    id              BIGSERIAL PRIMARY KEY,
    employee_id     UUID NOT NULL REFERENCES employees(id),
    punched_at      TIMESTAMPTZ NOT NULL,
    direction       TEXT NOT NULL CHECK (direction IN ('IN', 'OUT')),
    source          punch_source NOT NULL,
    latitude        NUMERIC(9,6),
    longitude       NUMERIC(9,6),
    device_id       TEXT,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX idx_att_logs_emp_time ON attendance_logs (employee_id, punched_at);

-- Computed daily summary, this is what payroll reads
CREATE TABLE attendance_daily (
    id                  BIGSERIAL PRIMARY KEY,
    employee_id         UUID NOT NULL REFERENCES employees(id),
    work_date           DATE NOT NULL,
    shift_id            INT REFERENCES shifts(id),
    time_in             TIMESTAMPTZ,
    time_out            TIMESTAMPTZ,
    regular_hours       NUMERIC(5,2) NOT NULL DEFAULT 0,
    overtime_hours      NUMERIC(5,2) NOT NULL DEFAULT 0,
    night_diff_hours    NUMERIC(5,2) NOT NULL DEFAULT 0,
    late_minutes        INT NOT NULL DEFAULT 0,
    undertime_minutes   INT NOT NULL DEFAULT 0,
    is_absent           BOOLEAN NOT NULL DEFAULT FALSE,
    is_rest_day_work    BOOLEAN NOT NULL DEFAULT FALSE,
    holiday_type        holiday_type,
    remarks             TEXT,
    approved_by         UUID REFERENCES users(id),
    UNIQUE (employee_id, work_date)
);

-- Manual corrections and overtime filings that need approval
CREATE TYPE request_status AS ENUM ('PENDING', 'APPROVED', 'REJECTED', 'CANCELLED');

CREATE TABLE attendance_requests (
    id              BIGSERIAL PRIMARY KEY,
    employee_id     UUID NOT NULL REFERENCES employees(id),
    request_type    TEXT NOT NULL CHECK (request_type IN ('CORRECTION', 'OVERTIME', 'OFFICIAL_BUSINESS')),
    work_date       DATE NOT NULL,
    requested_in    TIMESTAMPTZ,
    requested_out   TIMESTAMPTZ,
    overtime_hours  NUMERIC(5,2),
    reason          TEXT NOT NULL,
    status          request_status NOT NULL DEFAULT 'PENDING',
    reviewed_by     UUID REFERENCES users(id),
    reviewed_at     TIMESTAMPTZ,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- ---------------------------------------------------------------------
-- 4. Leave management
-- ---------------------------------------------------------------------
CREATE TABLE leave_types (
    id              SERIAL PRIMARY KEY,
    code            TEXT UNIQUE NOT NULL,         -- VL, SL, SIL, ML, PL
    name            TEXT NOT NULL,
    is_paid         BOOLEAN NOT NULL DEFAULT TRUE,
    annual_credits  NUMERIC(5,2) NOT NULL DEFAULT 0,
    is_convertible  BOOLEAN NOT NULL DEFAULT FALSE
);

CREATE TABLE leave_balances (
    employee_id     UUID NOT NULL REFERENCES employees(id),
    leave_type_id   INT NOT NULL REFERENCES leave_types(id),
    year            INT NOT NULL,
    credits         NUMERIC(5,2) NOT NULL DEFAULT 0,
    used            NUMERIC(5,2) NOT NULL DEFAULT 0,
    PRIMARY KEY (employee_id, leave_type_id, year)
);

CREATE TABLE leave_requests (
    id              BIGSERIAL PRIMARY KEY,
    employee_id     UUID NOT NULL REFERENCES employees(id),
    leave_type_id   INT NOT NULL REFERENCES leave_types(id),
    date_from       DATE NOT NULL,
    date_to         DATE NOT NULL,
    days            NUMERIC(5,2) NOT NULL,
    reason          TEXT,
    status          request_status NOT NULL DEFAULT 'PENDING',
    reviewed_by     UUID REFERENCES users(id),
    reviewed_at     TIMESTAMPTZ,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- ---------------------------------------------------------------------
-- 5. Statutory tables (configurable, never hardcode rates)
-- ---------------------------------------------------------------------
CREATE TYPE statutory_type AS ENUM ('SSS', 'PHILHEALTH', 'PAGIBIG', 'WITHHOLDING_TAX');

CREATE TABLE statutory_tables (
    id              SERIAL PRIMARY KEY,
    type            statutory_type NOT NULL,
    effective_from  DATE NOT NULL,
    effective_to    DATE,
    notes           TEXT
);

CREATE TABLE statutory_brackets (
    id                  BIGSERIAL PRIMARY KEY,
    table_id            INT NOT NULL REFERENCES statutory_tables(id) ON DELETE CASCADE,
    range_from          NUMERIC(14,2) NOT NULL,
    range_to            NUMERIC(14,2),
    employee_fixed      NUMERIC(12,2) NOT NULL DEFAULT 0,
    employee_rate       NUMERIC(8,6)  NOT NULL DEFAULT 0,
    employer_fixed      NUMERIC(12,2) NOT NULL DEFAULT 0,
    employer_rate       NUMERIC(8,6)  NOT NULL DEFAULT 0,
    excess_over         NUMERIC(14,2) NOT NULL DEFAULT 0     -- used by tax brackets
);

-- Payroll rule multipliers (overtime, night diff, holiday pay, etc.)
CREATE TABLE pay_rules (
    code            TEXT PRIMARY KEY,             -- OT_REGULAR, OT_REST_DAY, NIGHT_DIFF, REGULAR_HOLIDAY
    multiplier      NUMERIC(6,4) NOT NULL,
    description     TEXT
);

-- ---------------------------------------------------------------------
-- 6. Loans and recurring adjustments
-- ---------------------------------------------------------------------
CREATE TABLE loans (
    id                  BIGSERIAL PRIMARY KEY,
    employee_id         UUID NOT NULL REFERENCES employees(id),
    loan_type           TEXT NOT NULL,            -- CASH_ADVANCE, SSS_LOAN, PAGIBIG_LOAN, COMPANY_LOAN
    principal           NUMERIC(12,2) NOT NULL,
    amortization        NUMERIC(12,2) NOT NULL,   -- deducted per payroll period
    balance             NUMERIC(12,2) NOT NULL,
    start_period_date   DATE NOT NULL,
    is_active           BOOLEAN NOT NULL DEFAULT TRUE,
    created_at          TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE recurring_items (                    -- allowances and fixed deductions
    id              BIGSERIAL PRIMARY KEY,
    employee_id     UUID NOT NULL REFERENCES employees(id),
    item_type       TEXT NOT NULL CHECK (item_type IN ('EARNING', 'DEDUCTION')),
    name            TEXT NOT NULL,
    amount          NUMERIC(12,2) NOT NULL,
    is_taxable      BOOLEAN NOT NULL DEFAULT TRUE,
    is_active       BOOLEAN NOT NULL DEFAULT TRUE
);

-- ---------------------------------------------------------------------
-- 7. Payroll processing
-- ---------------------------------------------------------------------
CREATE TYPE payroll_status AS ENUM ('DRAFT', 'FOR_APPROVAL', 'APPROVED', 'LOCKED', 'PAID');

CREATE TABLE pay_periods (
    id              SERIAL PRIMARY KEY,
    label           TEXT NOT NULL,                -- e.g. "2026-10 First Half"
    date_from       DATE NOT NULL,
    date_to         DATE NOT NULL,
    pay_date        DATE NOT NULL,
    is_last_of_month BOOLEAN NOT NULL DEFAULT FALSE,   -- when monthly contributions are deducted
    UNIQUE (date_from, date_to)
);

CREATE TABLE payroll_runs (
    id              BIGSERIAL PRIMARY KEY,
    pay_period_id   INT NOT NULL REFERENCES pay_periods(id),
    status          payroll_status NOT NULL DEFAULT 'DRAFT',
    prepared_by     UUID REFERENCES users(id),
    approved_by     UUID REFERENCES users(id),
    locked_at       TIMESTAMPTZ,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE payslips (
    id                  BIGSERIAL PRIMARY KEY,
    payroll_run_id      BIGINT NOT NULL REFERENCES payroll_runs(id) ON DELETE CASCADE,
    employee_id         UUID NOT NULL REFERENCES employees(id),
    gross_pay           NUMERIC(14,2) NOT NULL DEFAULT 0,
    total_deductions    NUMERIC(14,2) NOT NULL DEFAULT 0,
    net_pay             NUMERIC(14,2) NOT NULL DEFAULT 0,
    taxable_income      NUMERIC(14,2) NOT NULL DEFAULT 0,
    withholding_tax     NUMERIC(14,2) NOT NULL DEFAULT 0,
    UNIQUE (payroll_run_id, employee_id)
);

-- One row per earning or deduction line so every figure is explainable
CREATE TABLE payslip_lines (
    id              BIGSERIAL PRIMARY KEY,
    payslip_id      BIGINT NOT NULL REFERENCES payslips(id) ON DELETE CASCADE,
    line_type       TEXT NOT NULL CHECK (line_type IN ('EARNING', 'DEDUCTION', 'EMPLOYER_SHARE')),
    code            TEXT NOT NULL,                -- BASIC, OT, NIGHT_DIFF, HOLIDAY, SSS, PHILHEALTH, PAGIBIG, TAX, LOAN
    description     TEXT NOT NULL,
    quantity        NUMERIC(8,2),                 -- hours or days
    rate            NUMERIC(12,4),
    amount          NUMERIC(14,2) NOT NULL
);

-- ---------------------------------------------------------------------
-- 8. Audit log (every sensitive change)
-- ---------------------------------------------------------------------
CREATE TABLE audit_logs (
    id              BIGSERIAL PRIMARY KEY,
    user_id         UUID REFERENCES users(id),
    action          TEXT NOT NULL,                -- CREATE, UPDATE, DELETE, APPROVE, LOCK, EXPORT
    table_name      TEXT NOT NULL,
    record_id       TEXT NOT NULL,
    old_values      JSONB,
    new_values      JSONB,
    ip_address      INET,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX idx_audit_table_record ON audit_logs (table_name, record_id);
