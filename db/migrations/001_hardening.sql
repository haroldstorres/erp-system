-- =====================================================================
-- 001 Hardening: audit log protection, payroll lock, one run per period
-- Safe to run more than once. Apply after db/schema.sql:
--   psql "$DATABASE_URL" -f db/migrations/001_hardening.sql
-- =====================================================================

-- Login throttling reads recent LOGIN_FAILED rows by email and by IP
CREATE INDEX IF NOT EXISTS idx_audit_action_time ON audit_logs (action, created_at);
CREATE INDEX IF NOT EXISTS idx_audit_ip_time ON audit_logs (ip_address, created_at);

-- One payroll run per pay period (also stops two people creating it at once)
CREATE UNIQUE INDEX IF NOT EXISTS ux_payroll_runs_period ON payroll_runs (pay_period_id);

-- ---------------------------------------------------------------------
-- 1. The audit log can only be added to, never edited or deleted
-- ---------------------------------------------------------------------
CREATE OR REPLACE FUNCTION audit_logs_immutable() RETURNS trigger AS $$
BEGIN
    RAISE EXCEPTION 'audit_logs is append-only';
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS trg_audit_logs_immutable ON audit_logs;
CREATE TRIGGER trg_audit_logs_immutable
    BEFORE UPDATE OR DELETE ON audit_logs
    FOR EACH ROW EXECUTE FUNCTION audit_logs_immutable();

-- ---------------------------------------------------------------------
-- 2. Payroll lock: once a run leaves DRAFT/FOR_APPROVAL review, the
--    payslips and the attendance behind them cannot change.
--    "Frozen" statuses: APPROVED, LOCKED, PAID
-- ---------------------------------------------------------------------

-- Payslips and their lines: frozen once the run is FOR_APPROVAL or later
CREATE OR REPLACE FUNCTION payslips_guard() RETURNS trigger AS $$
DECLARE
    run_id BIGINT;
    run_status payroll_status;
BEGIN
    IF TG_OP = 'DELETE' THEN run_id := OLD.payroll_run_id; ELSE run_id := NEW.payroll_run_id; END IF;
    SELECT status INTO run_status FROM payroll_runs WHERE id = run_id;
    -- run_status is NULL when the whole run is being deleted (cascade); that is
    -- only possible for a DRAFT run, see payroll_runs_guard
    IF run_status IS NOT NULL AND run_status <> 'DRAFT' THEN
        RAISE EXCEPTION 'Payslips are frozen: payroll run % is %', run_id, run_status;
    END IF;
    IF TG_OP = 'DELETE' THEN RETURN OLD; END IF;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS trg_payslips_guard ON payslips;
CREATE TRIGGER trg_payslips_guard
    BEFORE INSERT OR UPDATE OR DELETE ON payslips
    FOR EACH ROW EXECUTE FUNCTION payslips_guard();

CREATE OR REPLACE FUNCTION payslip_lines_guard() RETURNS trigger AS $$
DECLARE
    slip_id BIGINT;
    run_status payroll_status;
BEGIN
    IF TG_OP = 'DELETE' THEN slip_id := OLD.payslip_id; ELSE slip_id := NEW.payslip_id; END IF;
    SELECT r.status INTO run_status
      FROM payslips p JOIN payroll_runs r ON r.id = p.payroll_run_id
     WHERE p.id = slip_id;
    IF run_status IS NOT NULL AND run_status <> 'DRAFT' THEN
        RAISE EXCEPTION 'Payslip lines are frozen: payroll run is %', run_status;
    END IF;
    IF TG_OP = 'DELETE' THEN RETURN OLD; END IF;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS trg_payslip_lines_guard ON payslip_lines;
CREATE TRIGGER trg_payslip_lines_guard
    BEFORE INSERT OR UPDATE OR DELETE ON payslip_lines
    FOR EACH ROW EXECUTE FUNCTION payslip_lines_guard();

-- A run can only be deleted while it is still a DRAFT, and its period cannot be changed
CREATE OR REPLACE FUNCTION payroll_runs_guard() RETURNS trigger AS $$
BEGIN
    IF TG_OP = 'DELETE' THEN
        IF OLD.status <> 'DRAFT' THEN
            RAISE EXCEPTION 'Only a DRAFT payroll run can be deleted';
        END IF;
        RETURN OLD;
    END IF;
    IF NEW.pay_period_id <> OLD.pay_period_id THEN
        RAISE EXCEPTION 'The pay period of a payroll run cannot be changed';
    END IF;
    -- LOCKED and PAID can only move forward (LOCKED -> PAID), never back
    IF OLD.status IN ('LOCKED', 'PAID') AND NEW.status <> OLD.status
       AND NOT (OLD.status = 'LOCKED' AND NEW.status = 'PAID') THEN
        RAISE EXCEPTION 'A % payroll run cannot be changed to %', OLD.status, NEW.status;
    END IF;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS trg_payroll_runs_guard ON payroll_runs;
CREATE TRIGGER trg_payroll_runs_guard
    BEFORE UPDATE OR DELETE ON payroll_runs
    FOR EACH ROW EXECUTE FUNCTION payroll_runs_guard();

-- Attendance inside an APPROVED / LOCKED / PAID period cannot be added, edited or removed
CREATE OR REPLACE FUNCTION attendance_daily_guard() RETURNS trigger AS $$
DECLARE
    d DATE;
    hit TEXT;
BEGIN
    IF TG_OP = 'DELETE' THEN d := OLD.work_date; ELSE d := NEW.work_date; END IF;
    SELECT pp.label || ' (' || r.status || ')' INTO hit
      FROM payroll_runs r JOIN pay_periods pp ON pp.id = r.pay_period_id
     WHERE r.status IN ('APPROVED', 'LOCKED', 'PAID')
       AND d BETWEEN pp.date_from AND pp.date_to
     LIMIT 1;
    IF hit IS NOT NULL THEN
        RAISE EXCEPTION 'Attendance for % is locked by payroll period %', d, hit;
    END IF;
    IF TG_OP = 'DELETE' THEN RETURN OLD; END IF;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS trg_attendance_daily_guard ON attendance_daily;
CREATE TRIGGER trg_attendance_daily_guard
    BEFORE INSERT OR UPDATE OR DELETE ON attendance_daily
    FOR EACH ROW EXECUTE FUNCTION attendance_daily_guard();
