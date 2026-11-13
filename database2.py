import os
import re
import sys
import json
import calendar
import pyodbc
from datetime import datetime, timedelta
from werkzeug.security import generate_password_hash, check_password_hash

# ============================================================
# SQL Server connection (Integrated Security = Windows Auth)
# ============================================================
DB_SERVER   = r'DESKTOP-L6AHHGQ\MSQL2014'
DB_NAME     = 'PayrollDB'
DB_DRIVER   = 'ODBC Driver 17 for SQL Server'

def _conn_str(db_name=DB_NAME):
    return (
        f'DRIVER={{{DB_DRIVER}}};'
        f'SERVER={DB_SERVER};'
        f'DATABASE={db_name};'
        f'Trusted_Connection=yes;'
        f'Encrypt=no;'
        f'TrustServerCertificate=yes;'
    )

def _master_conn_str():
    return (
        f'DRIVER={{{DB_DRIVER}}};'
        f'SERVER={DB_SERVER};'
        f'DATABASE=master;'
        f'Trusted_Connection=yes;'
        f'Encrypt=no;'
        f'TrustServerCertificate=yes;'
    )


# ============================================================
# Compatibility layer: cursor wrapper
# - Accepts SQLite-style '?' placeholders, converts to '?' (pyodbc uses '?' too)
# - Auto-translates a small set of SQLite-only syntax to SQL Server
# - Returns dict-like rows (supports r['col'] and dict(r))
# ============================================================
class _Row(dict):
    """dict subclass that also supports positional indexing like sqlite3.Row."""
    def __getitem__(self, key):
        if isinstance(key, int):
            return list(self.values())[key]
        return super().__getitem__(key)


class _Cursor:
    def __init__(self, cur, conn):
        self._cur = cur
        self._conn = conn

    # ---- SQL translation (SQLite -> SQL Server) ----
    @staticmethod
    def _translate(sql: str) -> str:
        s = sql

        # INSERT OR REPLACE -> MERGE (only used for attendance, payroll_proof, payroll_signatures)
        # We handle the three cases explicitly, because MERGE needs the key columns.
        if re.search(r'INSERT\s+OR\s+REPLACE\s+INTO\s+attendance', s, re.I):
            return '''
                MERGE attendance AS t
                USING (SELECT ? AS employee_id, ? AS date) AS src
                  ON t.employee_id = src.employee_id AND t.date = src.date
                WHEN MATCHED THEN UPDATE SET
                    check_in=?, check_out=?, status=?, note=?, month=?
                WHEN NOT MATCHED THEN INSERT
                    (employee_id, date, check_in, check_out, status, note, month)
                    VALUES (?, ?, ?, ?, ?, ?, ?);
            '''

        if re.search(r'INSERT\s+OR\s+REPLACE\s+INTO\s+payroll_proof', s, re.I):
            return '''
                MERGE payroll_proof AS t
                USING (SELECT ? AS employee_id, ? AS month) AS src
                  ON t.employee_id = src.employee_id AND t.month = src.month
                WHEN MATCHED THEN UPDATE SET
                    gross_salary=?, total_allowances=?, overtime_amount=?, commission_amount=?,
                    total_earnings=?, social_insurance_employee=?, social_insurance_employer=?,
                    income_tax=?, advance_installments=?, absence_deduction=?, late_deduction=?,
                    other_deductions=?, total_deductions=?, net_salary=?, days_worked=?, status=?
                WHEN NOT MATCHED THEN INSERT
                    (employee_id, month, gross_salary, total_allowances, overtime_amount, commission_amount,
                     total_earnings, social_insurance_employee, social_insurance_employer, income_tax,
                     advance_installments, absence_deduction, late_deduction, other_deductions,
                     total_deductions, net_salary, days_worked, status)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);
            '''

        if re.search(r'INSERT\s+OR\s+REPLACE\s+INTO\s+payroll_signatures', s, re.I):
            return '''
                MERGE payroll_signatures AS t
                USING (SELECT ? AS employee_id, ? AS month) AS src
                  ON t.employee_id = src.employee_id AND t.month = src.month
                WHEN MATCHED THEN UPDATE SET
                    slip_number=?, gross_salary=?, net_salary=?, signature_data=?,
                    sign_date=?, signed_by_ip=?, notes=?
                WHEN NOT MATCHED THEN INSERT
                    (employee_id, month, slip_number, gross_salary, net_salary,
                     signature_data, sign_date, signed_by_ip, notes)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?);
            '''

        # SQLite time/date helpers -> T-SQL
        s = re.sub(r"date\('now',\s*'localtime'\)", "CAST(GETDATE() AS date)", s, flags=re.I)
        s = re.sub(r"date\('now'\)", "CAST(GETDATE() AS date)", s, flags=re.I)
        s = re.sub(r"datetime\('now',\s*'localtime'\)", "GETDATE()", s, flags=re.I)
        s = re.sub(r"datetime\('now'\)", "GETDATE()", s, flags=re.I)

        # substr(x,1,7) -> LEFT(x,7), substr(x,1,10) -> LEFT(x,10)
        s = re.sub(r"substr\(\s*([^,]+?)\s*,\s*1\s*,\s*(\d+)\s*\)", r"LEFT(\1,\2)", s, flags=re.I)

        # AUTOINCREMENT not needed here (we use IDENTITY in DDL)

        return s

    def execute(self, sql, params=()):
        sql2 = self._translate(sql) if isinstance(sql, str) else sql
        if params:
            self._cur.execute(sql2, params)
        else:
            self._cur.execute(sql2)
        return self

    def executemany(self, sql, seq_of_params):
        sql2 = self._translate(sql) if isinstance(sql, str) else sql
        self._cur.executemany(sql2, seq_of_params)
        return self

    def fetchone(self):
        row = self._cur.fetchone()
        if row is None:
            return None
        cols = [d[0] for d in self._cur.description]
        return _Row(zip(cols, row))

    def fetchall(self):
        rows = self._cur.fetchall()
        cols = [d[0] for d in self._cur.description]
        return [_Row(zip(cols, r)) for r in rows]

    @property
    def lastrowid(self):
        # SQL Server: SCOPE_IDENTITY() after INSERT
        try:
            self._cur.execute("SELECT CAST(SCOPE_IDENTITY() AS BIGINT)")
            v = self._cur.fetchone()[0]
            return int(v) if v is not None else None
        except Exception:
            return None

    def close(self):
        try:
            self._cur.close()
        except Exception:
            pass


class _Conn:
    """Thin wrapper around pyodbc connection to mimic sqlite3.Connection API."""
    def __init__(self, odbc_conn):
        self._conn = odbc_conn
        self._conn.autocommit = False

    def cursor(self):
        return _Cursor(self._conn.cursor(), self)

    def execute(self, sql, params=()):
        cur = self.cursor()
        cur.execute(sql, params)
        return cur

    def executemany(self, sql, seq):
        cur = self.cursor()
        cur.executemany(sql, seq)
        return cur

    def executescript(self, script):
        # Split on GO-like batches (we don't use GO here, so just run whole script)
        cur = self._conn.cursor()
        # Split on semicolons that end a statement — pyodbc can handle multi-statement in one call
        cur.execute(script)
        cur.close()

    def commit(self):
        self._conn.commit()

    def rollback(self):
        self._conn.rollback()

    def close(self):
        try:
            self._conn.close()
        except Exception:
            pass

    def backup(self, dest_conn):
        # Not used with SQL Server; kept for API compatibility.
        pass


# ============================================================
# DDL for SQL Server (translated from SQLite schema)
# ============================================================
_DDL = '''
IF OBJECT_ID('users','U') IS NULL
CREATE TABLE users (
    id INT IDENTITY(1,1) PRIMARY KEY,
    username NVARCHAR(100) NOT NULL UNIQUE,
    password NVARCHAR(255) NOT NULL,
    full_name NVARCHAR(200) DEFAULT '',
    role NVARCHAR(50) DEFAULT 'user',
    active INT DEFAULT 1,
    created_at DATETIME DEFAULT GETDATE()
);

IF OBJECT_ID('departments','U') IS NULL
CREATE TABLE departments (
    id INT IDENTITY(1,1) PRIMARY KEY,
    name NVARCHAR(200) NOT NULL UNIQUE,
    manager NVARCHAR(200) DEFAULT '',
    cost_center NVARCHAR(100) DEFAULT '',
    active INT DEFAULT 1,
    created_at DATETIME DEFAULT GETDATE()
);

IF OBJECT_ID('employees','U') IS NULL
CREATE TABLE employees (
    id INT IDENTITY(1,1) PRIMARY KEY,
    emp_code NVARCHAR(50) NOT NULL UNIQUE,
    name NVARCHAR(200) NOT NULL,
    national_id NVARCHAR(50) DEFAULT '',
    department_id INT NULL,
    position NVARCHAR(200) DEFAULT '',
    phone NVARCHAR(50) DEFAULT '',
    email NVARCHAR(200) DEFAULT '',
    address NVARCHAR(500) DEFAULT '',
    gender NVARCHAR(20) DEFAULT 'male',
    birth_date NVARCHAR(20) DEFAULT '',
    hire_date NVARCHAR(20) DEFAULT '',
    termination_date NVARCHAR(20) DEFAULT '',
    marital_status NVARCHAR(50) DEFAULT '',
    bank_name NVARCHAR(200) DEFAULT '',
    bank_account NVARCHAR(100) DEFAULT '',
    pay_type NVARCHAR(20) DEFAULT 'monthly',
    base_salary FLOAT DEFAULT 0,
    daily_rate FLOAT DEFAULT 0,
    hourly_rate FLOAT DEFAULT 0,
    commission_rate FLOAT DEFAULT 0,
    housing_allowance FLOAT DEFAULT 0,
    transport_allowance FLOAT DEFAULT 0,
    food_allowance FLOAT DEFAULT 0,
    other_allowances FLOAT DEFAULT 0,
    danger_allowance FLOAT DEFAULT 0,
    phone_allowance FLOAT DEFAULT 0,
    social_insurance_enabled INT DEFAULT 1,
    social_insurance_employee_ratio FLOAT DEFAULT 11,
    social_insurance_employer_ratio FLOAT DEFAULT 18.75,
    income_tax_enabled INT DEFAULT 1,
    tax_exempt_amount FLOAT DEFAULT 0,
    status NVARCHAR(20) DEFAULT 'active',
    remarks NVARCHAR(MAX) DEFAULT '',
    created_at DATETIME DEFAULT GETDATE(),
    CONSTRAINT FK_emp_dept FOREIGN KEY (department_id) REFERENCES departments(id)
);

IF OBJECT_ID('attendance','U') IS NULL
CREATE TABLE attendance (
    id INT IDENTITY(1,1) PRIMARY KEY,
    employee_id INT NOT NULL,
    date NVARCHAR(20) NOT NULL,
    check_in NVARCHAR(20) DEFAULT '',
    check_out NVARCHAR(20) DEFAULT '',
    status NVARCHAR(20) DEFAULT 'present',
    note NVARCHAR(500) DEFAULT '',
    month NVARCHAR(10) DEFAULT '',
    CONSTRAINT UQ_att_emp_date UNIQUE (employee_id, date),
    CONSTRAINT FK_att_emp FOREIGN KEY (employee_id) REFERENCES employees(id) ON DELETE CASCADE
);

IF OBJECT_ID('leave_requests','U') IS NULL
CREATE TABLE leave_requests (
    id INT IDENTITY(1,1) PRIMARY KEY,
    employee_id INT NOT NULL,
    leave_type NVARCHAR(50) NOT NULL,
    start_date NVARCHAR(20) NOT NULL,
    end_date NVARCHAR(20) NOT NULL,
    days FLOAT DEFAULT 0,
    reason NVARCHAR(500) DEFAULT '',
    status NVARCHAR(20) DEFAULT 'pending',
    approved_by NVARCHAR(100) DEFAULT '',
    approved_date NVARCHAR(30) DEFAULT '',
    created_at DATETIME DEFAULT GETDATE(),
    CONSTRAINT FK_lv_emp FOREIGN KEY (employee_id) REFERENCES employees(id) ON DELETE CASCADE
);

IF OBJECT_ID('overtime','U') IS NULL
CREATE TABLE overtime (
    id INT IDENTITY(1,1) PRIMARY KEY,
    employee_id INT NOT NULL,
    date NVARCHAR(20) NOT NULL,
    hours FLOAT DEFAULT 0,
    rate_type NVARCHAR(20) DEFAULT 'auto',
    multiplier FLOAT DEFAULT 1.5,
    hourly_rate FLOAT DEFAULT 0,
    amount FLOAT DEFAULT 0,
    confirmed INT DEFAULT 0,
    note NVARCHAR(500) DEFAULT '',
    month NVARCHAR(10) DEFAULT '',
    CONSTRAINT FK_ot_emp FOREIGN KEY (employee_id) REFERENCES employees(id) ON DELETE CASCADE
);

IF OBJECT_ID('commissions','U') IS NULL
CREATE TABLE commissions (
    id INT IDENTITY(1,1) PRIMARY KEY,
    employee_id INT NOT NULL,
    date NVARCHAR(20) NOT NULL,
    sales_amount FLOAT DEFAULT 0,
    rate FLOAT DEFAULT 0,
    amount FLOAT DEFAULT 0,
    note NVARCHAR(500) DEFAULT '',
    month NVARCHAR(10) DEFAULT '',
    CONSTRAINT FK_cm_emp FOREIGN KEY (employee_id) REFERENCES employees(id) ON DELETE CASCADE
);

IF OBJECT_ID('deduction_types','U') IS NULL
CREATE TABLE deduction_types (
    id INT IDENTITY(1,1) PRIMARY KEY,
    name NVARCHAR(200) NOT NULL UNIQUE,
    category NVARCHAR(50) DEFAULT 'other',
    description NVARCHAR(500) DEFAULT '',
    active INT DEFAULT 1
);

IF OBJECT_ID('deductions','U') IS NULL
CREATE TABLE deductions (
    id INT IDENTITY(1,1) PRIMARY KEY,
    employee_id INT NOT NULL,
    date NVARCHAR(20) NOT NULL,
    deduction_type NVARCHAR(100) DEFAULT '',
    amount FLOAT DEFAULT 0,
    note NVARCHAR(500) DEFAULT '',
    month NVARCHAR(10) DEFAULT '',
    CONSTRAINT FK_dd_emp FOREIGN KEY (employee_id) REFERENCES employees(id) ON DELETE CASCADE
);

IF OBJECT_ID('advances','U') IS NULL
CREATE TABLE advances (
    id INT IDENTITY(1,1) PRIMARY KEY,
    employee_id INT NOT NULL,
    date NVARCHAR(20) NOT NULL,
    amount FLOAT DEFAULT 0,
    installment_count INT DEFAULT 1,
    installment_amount FLOAT DEFAULT 0,
    current_installment INT DEFAULT 0,
    remaining FLOAT DEFAULT 0,
    status NVARCHAR(20) DEFAULT 'active',
    note NVARCHAR(500) DEFAULT '',
    created_at DATETIME DEFAULT GETDATE(),
    CONSTRAINT FK_adv_emp FOREIGN KEY (employee_id) REFERENCES employees(id) ON DELETE CASCADE
);

IF OBJECT_ID('payroll_proof','U') IS NULL
CREATE TABLE payroll_proof (
    id INT IDENTITY(1,1) PRIMARY KEY,
    employee_id INT NOT NULL,
    month NVARCHAR(10) NOT NULL,
    gross_salary FLOAT DEFAULT 0,
    total_allowances FLOAT DEFAULT 0,
    overtime_amount FLOAT DEFAULT 0,
    commission_amount FLOAT DEFAULT 0,
    total_earnings FLOAT DEFAULT 0,
    social_insurance_employee FLOAT DEFAULT 0,
    social_insurance_employer FLOAT DEFAULT 0,
    income_tax FLOAT DEFAULT 0,
    advance_installments FLOAT DEFAULT 0,
    absence_deduction FLOAT DEFAULT 0,
    late_deduction FLOAT DEFAULT 0,
    other_deductions FLOAT DEFAULT 0,
    total_deductions FLOAT DEFAULT 0,
    net_salary FLOAT DEFAULT 0,
    days_worked FLOAT DEFAULT 0,
    status NVARCHAR(20) DEFAULT 'draft',
    paid_date NVARCHAR(30) DEFAULT '',
    note NVARCHAR(500) DEFAULT '',
    CONSTRAINT UQ_pp_emp_month UNIQUE (employee_id, month),
    CONSTRAINT FK_pp_emp FOREIGN KEY (employee_id) REFERENCES employees(id) ON DELETE CASCADE
);

IF OBJECT_ID('salary_history','U') IS NULL
CREATE TABLE salary_history (
    id INT IDENTITY(1,1) PRIMARY KEY,
    employee_id INT NOT NULL,
    old_salary FLOAT DEFAULT 0,
    new_salary FLOAT DEFAULT 0,
    change_date NVARCHAR(30) DEFAULT '',
    reason NVARCHAR(500) DEFAULT '',
    created_by NVARCHAR(100) DEFAULT '',
    created_at DATETIME DEFAULT GETDATE(),
    CONSTRAINT FK_sh_emp FOREIGN KEY (employee_id) REFERENCES employees(id) ON DELETE CASCADE
);

IF OBJECT_ID('contracts','U') IS NULL
CREATE TABLE contracts (
    id INT IDENTITY(1,1) PRIMARY KEY,
    employee_id INT NOT NULL,
    contract_type NVARCHAR(50) DEFAULT 'permanent',
    contract_number NVARCHAR(100) DEFAULT '',
    start_date NVARCHAR(20) NOT NULL,
    end_date NVARCHAR(20) DEFAULT '',
    salary FLOAT DEFAULT 0,
    allowance_details NVARCHAR(MAX) DEFAULT '',
    notes NVARCHAR(MAX) DEFAULT '',
    status NVARCHAR(20) DEFAULT 'active',
    created_at DATETIME DEFAULT GETDATE(),
    CONSTRAINT FK_ct_emp FOREIGN KEY (employee_id) REFERENCES employees(id) ON DELETE CASCADE
);

IF OBJECT_ID('payroll_signatures','U') IS NULL
CREATE TABLE payroll_signatures (
    id INT IDENTITY(1,1) PRIMARY KEY,
    employee_id INT NOT NULL,
    month NVARCHAR(10) NOT NULL,
    slip_number NVARCHAR(100) DEFAULT '',
    gross_salary FLOAT DEFAULT 0,
    net_salary FLOAT DEFAULT 0,
    signature_data NVARCHAR(MAX) DEFAULT '',
    sign_date NVARCHAR(30) DEFAULT '',
    signed_by_ip NVARCHAR(50) DEFAULT '',
    notes NVARCHAR(500) DEFAULT '',
    CONSTRAINT UQ_ps_emp_month UNIQUE (employee_id, month),
    CONSTRAINT FK_ps_emp FOREIGN KEY (employee_id) REFERENCES employees(id) ON DELETE CASCADE
);

IF OBJECT_ID('audit_log','U') IS NULL
CREATE TABLE audit_log (
    id INT IDENTITY(1,1) PRIMARY KEY,
    user_id INT NULL,
    username NVARCHAR(100) DEFAULT '',
    action NVARCHAR(100) DEFAULT '',
    entity NVARCHAR(100) DEFAULT '',
    entity_id INT NULL,
    details NVARCHAR(MAX) DEFAULT '',
    ip_address NVARCHAR(50) DEFAULT '',
    created_at DATETIME DEFAULT GETDATE()
);

IF OBJECT_ID('bulk_incentives','U') IS NULL
CREATE TABLE bulk_incentives (
    id INT IDENTITY(1,1) PRIMARY KEY,
    month NVARCHAR(10) NOT NULL,
    kind NVARCHAR(20) NOT NULL,
    description NVARCHAR(500) DEFAULT '',
    per_employee_amount FLOAT DEFAULT 0,
    specific_employees NVARCHAR(MAX) DEFAULT '',
    applied INT DEFAULT 0,
    created_by NVARCHAR(100) DEFAULT '',
    created_at DATETIME DEFAULT GETDATE()
);

IF OBJECT_ID('tax_brackets','U') IS NULL
CREATE TABLE tax_brackets (
    id INT IDENTITY(1,1) PRIMARY KEY,
    from_amount FLOAT NOT NULL,
    to_amount FLOAT NULL,
    rate FLOAT NOT NULL,
    fixed_deduction FLOAT DEFAULT 0
);

IF OBJECT_ID('settings','U') IS NULL
CREATE TABLE settings (
    id INT IDENTITY(1,1) PRIMARY KEY,
    company_name NVARCHAR(200) DEFAULT '',
    company_address NVARCHAR(500) DEFAULT '',
    company_phone NVARCHAR(50) DEFAULT '',
    company_tax_id NVARCHAR(50) DEFAULT '',
    company_insurance_no NVARCHAR(50) DEFAULT '',
    currency NVARCHAR(10) DEFAULT 'EGP',
    weekly_holidays NVARCHAR(20) DEFAULT '6',
    working_days_monthly FLOAT DEFAULT 26,
    working_hours_daily FLOAT DEFAULT 8,
    overtime_weekday FLOAT DEFAULT 1.5,
    overtime_weekend FLOAT DEFAULT 2.0,
    overtime_holiday FLOAT DEFAULT 3.0,
    insurance_floor FLOAT DEFAULT 2200,
    insurance_ceiling FLOAT DEFAULT 14700,
    insurance_employee_ratio FLOAT DEFAULT 11,
    insurance_employer_ratio FLOAT DEFAULT 18.75,
    tax_exempt_default FLOAT DEFAULT 0,
    absence_deduction_percent FLOAT DEFAULT 100,
    late_minutes_tolerance INT DEFAULT 15,
    late_deduction_per_hour FLOAT DEFAULT 0,
    count_missing_as_absent INT DEFAULT 1,
    admin_password_changed INT DEFAULT 0,
    last_backup NVARCHAR(30) DEFAULT ''
);
'''


class Database:
    def __init__(self):
        # Make sure the database exists; create it if not
        try:
            master = pyodbc.connect(_master_conn_str(), autocommit=True)
            cur = master.cursor()
            cur.execute(f"IF DB_ID('{DB_NAME}') IS NULL CREATE DATABASE [{DB_NAME}]")
            cur.close()
            master.close()
        except Exception as e:
            raise RuntimeError(f'فشل الاتصال بـ SQL Server: {e}')

        self.conn = _Conn(pyodbc.connect(_conn_str()))
        self._enable_cascade()
        self.create_tables()
        self._migrate()
        self.seed_defaults()

    # SQL Server: enable cascade delete (SQLite had ON DELETE CASCADE in FK)
    def _enable_cascade(self):
        cur = self.conn.cursor()
        for fk in [
            ('attendance', 'FK_att_emp'),
            ('leave_requests', 'FK_lv_emp'),
            ('overtime', 'FK_ot_emp'),
            ('commissions', 'FK_cm_emp'),
            ('deductions', 'FK_dd_emp'),
            ('advances', 'FK_adv_emp'),
            ('payroll_proof', 'FK_pp_emp'),
            ('salary_history', 'FK_sh_emp'),
            ('contracts', 'FK_ct_emp'),
            ('payroll_signatures', 'FK_ps_emp'),
        ]:
            try:
                cur.execute(f"""
                    IF EXISTS (SELECT 1 FROM sys.foreign_keys WHERE name = '{fk[1]}')
                    BEGIN
                        ALTER TABLE {fk[0]} DROP CONSTRAINT {fk[1]};
                        ALTER TABLE {fk[0]} ADD CONSTRAINT {fk[1]}
                            FOREIGN KEY (employee_id) REFERENCES employees(id) ON DELETE CASCADE;
                    END
                """)
            except Exception:
                pass
        self.conn.commit()

    def _cur(self):
        return self.conn.cursor()

    def _checkbox(self, d, key):
        return 1 if str((d or {}).get(key, '')).strip().lower() in ('1', 'on', 'true', 'yes') else 0

    def _setting_on(self, settings, key, default=1):
        v = (settings or {}).get(key, default)
        if v is None:
            v = default
        if isinstance(v, str):
            return v.strip().lower() in ('1', 'on', 'true', 'yes')
        return bool(v)

    def create_tables(self):
        cur = self.conn.cursor()
        # pyodbc can run multi-statement scripts
        for stmt in _DDL.split(';'):
            stmt = stmt.strip()
            if stmt:
                try:
                    cur.execute(stmt)
                except Exception:
                    # Some IF OBJECT_ID guards may fail harmlessly in odd batches
                    pass
        self.conn.commit()

    def _migrate(self):
        cur = self._cur()
        # ensure the extra columns exist (for old DBs)
        for col, definition in [
            ('admin_password_changed', 'INT DEFAULT 0'),
            ('last_backup', "NVARCHAR(30) DEFAULT ''"),
            ('count_missing_as_absent', 'INT DEFAULT 1'),
        ]:
            try:
                cur.execute(f"""
                    IF COL_LENGTH('settings','{col}') IS NULL
                        ALTER TABLE settings ADD {col} {definition}
                """)
            except Exception:
                pass
        self.conn.commit()

    def seed_defaults(self):
        cur = self._cur()
        cur.execute("SELECT COUNT(*) AS cnt FROM users")
        if cur.fetchone()['cnt'] == 0:
            users = [
                ('admin', 'admin123', 'مدير النظام', 'admin'),
                ('supervisor', 'super123', 'محمد المشرف', 'supervisor'),
                ('user', 'user123', 'سارة المستخدمة', 'user'),
                ('viewer', 'viewer123', 'خالد المشاهد', 'viewer'),
            ]
            for uname, pwd, fname, role in users:
                cur.execute(
                    "INSERT INTO users (username,password,full_name,role) VALUES (?,?,?,?)",
                    (uname, generate_password_hash(pwd), fname, role))

        cur.execute("SELECT COUNT(*) AS cnt FROM settings")
        if cur.fetchone()['cnt'] == 0:
            cur.execute("INSERT INTO settings DEFAULT VALUES")

        cur.execute("SELECT COUNT(*) AS cnt FROM tax_brackets")
        if cur.fetchone()['cnt'] == 0:
            brackets = [
                (0, 15000, 0, 0),
                (15000, 30000, 2.5, 0),
                (30000, 45000, 10, 375),
                (45000, 60000, 15, 2625),
                (60000, 200000, 20, 5625),
                (200000, 400000, 22.5, 10625),
                (400000, 500000, 25, 20625),
                (500000, 900000, 30, 45625),
                (900000, None, 32.5, 68125),
            ]
            for b in brackets:
                cur.execute(
                    "INSERT INTO tax_brackets (from_amount,to_amount,rate,fixed_deduction) VALUES (?,?,?,?)", b)

        cur.execute("SELECT COUNT(*) AS cnt FROM deduction_types")
        if cur.fetchone()['cnt'] == 0:
            types = [
                ('جزاء إداري', 'penalty', 'خصم بسبب مخالفة'),
                ('قرض', 'loan', 'أقساط قرض'),
                ('تلفيات', 'damage', 'خصم أضرار'),
                ('سلفة', 'advance', 'أقساط سلفة'),
                ('طعام', 'food', 'اشتراك وجبات'),
                ('موبايل', 'social', 'فاتورة موبايل'),
                ('خصم آخر', 'other', 'أي خصم آخر'),
            ]
            for t in types:
                cur.execute("INSERT INTO deduction_types (name,category,description) VALUES (?,?,?)", t)
        self.conn.commit()

    # ==================================================================
    # Everything below is UNCHANGED from your original database.py.
    # The cursor wrapper translates the few SQLite-only bits above.
    # ==================================================================

    def authenticate(self, username, password):
        c = self._cur()
        c.execute("SELECT * FROM users WHERE username=?", (username,))
        row = c.fetchone()
        if row and check_password_hash(row['password'], password):
            return dict(row)
        return None

    def verify_password(self, stored_hash, password):
        return check_password_hash(stored_hash, password)

    def change_password(self, uid, new_password):
        c = self._cur()
        c.execute("UPDATE users SET password=? WHERE id=?", (generate_password_hash(new_password), uid))
        self.conn.commit()

    def toggle_user(self, uid):
        c = self._cur()
        c.execute("SELECT active FROM users WHERE id=?", (uid,))
        r = c.fetchone()
        if r:
            c.execute("UPDATE users SET active=? WHERE id=?", (0 if r['active'] else 1, uid))
            self.conn.commit()

    def get_user_by_id(self, uid):
        c = self._cur()
        c.execute("SELECT * FROM users WHERE id=?", (uid,))
        r = c.fetchone()
        return dict(r) if r else None

    def get_all_users(self):
        c = self._cur()
        c.execute("SELECT id,username,full_name,role,active,created_at FROM users ORDER BY username")
        return [dict(r) for r in c.fetchall()]

    def add_user(self, data):
        c = self._cur()
        c.execute("INSERT INTO users (username,password,full_name,role) VALUES (?,?,?,?)",
            (data['username'], generate_password_hash(data['password']), data.get('full_name',''), data.get('role','user')))
        self.conn.commit()

    def delete_user(self, uid):
        c = self._cur()
        c.execute("DELETE FROM users WHERE id=?", (uid,))
        self.conn.commit()

    def get_departments(self, active_only=False):
        c = self._cur()
        q = """SELECT d.*, COUNT(e.id) as emp_count
               FROM departments d LEFT JOIN employees e ON d.id=e.department_id AND e.status='active'"""
        if active_only:
            q += " WHERE d.active=1"
        q += " GROUP BY d.id, d.name, d.manager, d.cost_center, d.active, d.created_at ORDER BY d.name"
        c.execute(q)
        return [dict(r) for r in c.fetchall()]

    def add_department(self, name, manager='', cost_center=''):
        c = self._cur()
        c.execute("INSERT INTO departments (name,manager,cost_center) VALUES (?,?,?)", (name,manager,cost_center))
        self.conn.commit()

    def delete_department(self, dep_id):
        c = self._cur()
        c.execute("SELECT COUNT(*) as cnt FROM employees WHERE department_id=?", (dep_id,))
        if c.fetchone()['cnt'] > 0:
            return False
        c.execute("DELETE FROM departments WHERE id=?", (dep_id,))
        self.conn.commit()
        return True

    def get_employees(self, department=None, status='active', search='', sort='name'):
        c = self._cur()
        q = """SELECT e.*, d.name as dept_name
               FROM employees e LEFT JOIN departments d ON e.department_id=d.id WHERE 1=1"""
        params = []
        if status and status != 'all':
            q += " AND e.status=?"
            params.append(status)
        if department:
            q += " AND e.department_id=?"
            params.append(department)
        if search:
            q += " AND (e.name LIKE ? OR e.emp_code LIKE ? OR e.national_id LIKE ? OR e.position LIKE ?)"
            params += [f"%{search}%"]*4
        allowed = {'name': 'e.name', 'emp_code': 'e.emp_code', 'base_salary': 'e.base_salary',
                   'department': 'd.name'}
        order = allowed.get(sort, 'e.name')
        q += f" ORDER BY {order}"
        c.execute(q, params)
        return [dict(r) for r in c.fetchall()]

    def get_employee(self, emp_id):
        c = self._cur()
        c.execute("""SELECT e.*, d.name as dept_name
                     FROM employees e LEFT JOIN departments d ON e.department_id=d.id WHERE e.id=?""", (emp_id,))
        r = c.fetchone()
        return dict(r) if r else None

    def next_emp_code(self):
        c = self._cur()
        c.execute("SELECT TOP 1 emp_code FROM employees ORDER BY id DESC")
        r = c.fetchone()
        if not r:
            return "EMP001"
        try:
            n = int(r['emp_code'].replace('EMP','')) + 1
        except Exception:
            return "EMP001"
        return f"EMP{n:03d}"

    def add_employee(self, d):
        c = self._cur()
        dept_id = d.get('department_id') or None
        c.execute("""INSERT INTO employees (emp_code,name,national_id,department_id,position,phone,email,address,
            gender,birth_date,hire_date,marital_status,bank_name,bank_account,
            pay_type,base_salary,daily_rate,hourly_rate,commission_rate,
            housing_allowance,transport_allowance,food_allowance,other_allowances,danger_allowance,phone_allowance,
            social_insurance_enabled,social_insurance_employee_ratio,social_insurance_employer_ratio,
            income_tax_enabled,tax_exempt_amount,status,remarks)
            VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
            (d['emp_code'],d['name'],d.get('national_id',''),dept_id,d.get('position',''),
             d.get('phone',''),d.get('email',''),d.get('address',''),d.get('gender','male'),
             d.get('birth_date',''),d.get('hire_date',''),d.get('marital_status',''),
             d.get('bank_name',''),d.get('bank_account',''),
             d.get('pay_type','monthly'),d.get('base_salary',0),d.get('daily_rate',0),
             d.get('hourly_rate',0),d.get('commission_rate',0),
             d.get('housing_allowance',0),d.get('transport_allowance',0),d.get('food_allowance',0),
             d.get('other_allowances',0),d.get('danger_allowance',0),d.get('phone_allowance',0),
             d.get('social_insurance_enabled',1),d.get('social_insurance_employee_ratio',11),
             d.get('social_insurance_employer_ratio',18.75),d.get('income_tax_enabled',1),
             d.get('tax_exempt_amount',0),d.get('status','active'),d.get('remarks','')))
        self.conn.commit()
        return c.lastrowid

    def update_employee(self, emp_id, d):
        c = self._cur()
        dept_id = d.get('department_id') or None
        c.execute("""UPDATE employees SET emp_code=?,name=?,national_id=?,department_id=?,position=?,phone=?,email=?,
            address=?,gender=?,birth_date=?,hire_date=?,marital_status=?,bank_name=?,bank_account=?,
            pay_type=?,base_salary=?,daily_rate=?,hourly_rate=?,commission_rate=?,
            housing_allowance=?,transport_allowance=?,food_allowance=?,other_allowances=?,danger_allowance=?,phone_allowance=?,
            social_insurance_enabled=?,social_insurance_employee_ratio=?,social_insurance_employer_ratio=?,
            income_tax_enabled=?,tax_exempt_amount=?,status=?,remarks=? WHERE id=?""",
            (d['emp_code'],d['name'],d.get('national_id',''),dept_id,d.get('position',''),
             d.get('phone',''),d.get('email',''),d.get('address',''),d.get('gender','male'),
             d.get('birth_date',''),d.get('hire_date',''),d.get('marital_status',''),
             d.get('bank_name',''),d.get('bank_account',''),
             d.get('pay_type','monthly'),d.get('base_salary',0),d.get('daily_rate',0),
             d.get('hourly_rate',0),d.get('commission_rate',0),
             d.get('housing_allowance',0),d.get('transport_allowance',0),d.get('food_allowance',0),
             d.get('other_allowances',0),d.get('danger_allowance',0),d.get('phone_allowance',0),
             d.get('social_insurance_enabled',1),d.get('social_insurance_employee_ratio',11),
             d.get('social_insurance_employer_ratio',18.75),d.get('income_tax_enabled',1),
             d.get('tax_exempt_amount',0),d.get('status','active'),d.get('remarks',''), emp_id))
        self.conn.commit()

    def delete_employee(self, emp_id):
        c = self._cur()
        c.execute("DELETE FROM employees WHERE id=?", (emp_id,))
        self.conn.commit()

    def record_salary_change(self, emp_id, old_salary, new_salary, reason, user):
        c = self._cur()
        c.execute("INSERT INTO salary_history (employee_id,old_salary,new_salary,reason,created_by) VALUES (?,?,?,?,?)",
            (emp_id, old_salary, new_salary, reason, user))
        self.conn.commit()

    def get_salary_history(self, emp_id):
        c = self._cur()
        c.execute("SELECT * FROM salary_history WHERE employee_id=? ORDER BY change_date DESC, id DESC", (emp_id,))
        return [dict(r) for r in c.fetchall()]

    def get_attendance(self, month):
        c = self._cur()
        c.execute("""SELECT a.*, e.name as emp_name, e.emp_code
            FROM attendance a JOIN employees e ON a.employee_id=e.id
            WHERE a.month=? ORDER BY e.name, a.date""", (month,))
        return [dict(r) for r in c.fetchall()]

    def bulk_save_attendance(self, month, records):
        c = self._cur()
        for r in records:
            # Uses MERGE via _Cursor._translate
            c.execute("""INSERT OR REPLACE INTO attendance (employee_id,date,check_in,check_out,status,note,month)
                VALUES (?,?,?,?,?,?,?)""",
                (r['employee_id'], r['date'], r.get('check_in',''), r.get('check_out',''),
                 r.get('status','present'), r.get('note',''), month))
        self.conn.commit()

    def get_leaves(self, **filters):
        c = self._cur()
        q = """SELECT l.*, e.name as emp_name, e.emp_code
               FROM leave_requests l JOIN employees e ON l.employee_id=e.id WHERE 1=1"""
        params = []
        if filters.get('status'):
            q += " AND l.status=?"
            params.append(filters['status'])
        q += " ORDER BY l.created_at DESC"
        c.execute(q, params)
        return [dict(r) for r in c.fetchall()]

    def add_leave(self, d):
        c = self._cur()
        c.execute("""INSERT INTO leave_requests (employee_id,leave_type,start_date,end_date,days,reason)
            VALUES (?,?,?,?,?,?)""",
            (d['employee_id'], d['leave_type'], d['start_date'], d['end_date'], d['days'], d.get('reason','')))
        self.conn.commit()

    def update_leave_status(self, leave_id, status, user):
        c = self._cur()
        c.execute("UPDATE leave_requests SET status=?,approved_by=?,approved_date=? WHERE id=?",
            (status, user, datetime.now().strftime('%Y-%m-%d %H:%M:%S'), leave_id))
        self.conn.commit()

    def get_overtime(self, month):
        c = self._cur()
        c.execute("""SELECT o.*, e.name as emp_name, e.emp_code
            FROM overtime o JOIN employees e ON o.employee_id=e.id
            WHERE o.month=? ORDER BY e.name, o.date""", (month,))
        return [dict(r) for r in c.fetchall()]

    def bulk_save_overtime(self, month, records):
        c = self._cur()
        for r in records:
            c.execute("""INSERT INTO overtime (employee_id,date,hours,rate_type,multiplier,hourly_rate,amount,note,month)
                VALUES (?,?,?,?,?,?,?,?,?)""",
                (r['employee_id'], r['date'], r.get('hours',0), r.get('rate_type','auto'),
                 r.get('multiplier',1.5), r.get('hourly_rate',0), r.get('amount',0),
                 r.get('note',''), month))
        self.conn.commit()

    def get_commissions(self, month):
        c = self._cur()
        c.execute("""SELECT co.*, e.name as emp_name, e.emp_code
            FROM commissions co JOIN employees e ON co.employee_id=e.id
            WHERE co.month=? ORDER BY e.name, co.date""", (month,))
        return [dict(r) for r in c.fetchall()]

    def bulk_save_commissions(self, month, records):
        c = self._cur()
        for r in records:
            c.execute("""INSERT INTO commissions (employee_id,date,sales_amount,rate,amount,note,month)
                VALUES (?,?,?,?,?,?,?)""",
                (r['employee_id'], r.get('date', month+'-01'), r.get('sales_amount',0),
                 r.get('rate',0), r.get('amount',0), r.get('note',''), month))
        self.conn.commit()

    def get_deduction_types(self):
        c = self._cur()
        c.execute("SELECT * FROM deduction_types WHERE active=1 ORDER BY name")
        return [dict(r) for r in c.fetchall()]

    def get_deductions(self, month):
        c = self._cur()
        c.execute("""SELECT dd.*, e.name as emp_name, e.emp_code
            FROM deductions dd JOIN employees e ON dd.employee_id=e.id
            WHERE dd.month=? ORDER BY e.name, dd.date""", (month,))
        return [dict(r) for r in c.fetchall()]

    def bulk_save_deductions(self, month, records):
        c = self._cur()
        for r in records:
            c.execute("""INSERT INTO deductions (employee_id,date,deduction_type,amount,note,month)
                VALUES (?,?,?,?,?,?)""",
                (r['employee_id'], r.get('date', month+'-01'), r.get('deduction_type','other'),
                 r.get('amount',0), r.get('note',''), month))
        self.conn.commit()

    def get_advances(self, month=None):
        c = self._cur()
        q = """SELECT a.*, e.name as emp_name, e.emp_code
               FROM advances a JOIN employees e ON a.employee_id=e.id WHERE 1=1"""
        params = []
        if month:
            q += " AND LEFT(a.date,7)=?"
            params.append(month)
        q += " ORDER BY a.created_at DESC"
        c.execute(q, params)
        return [dict(r) for r in c.fetchall()]

    def add_advance(self, d):
        c = self._cur()
        installment_amount = d['amount']/d['installment_count'] if d['installment_count'] > 0 else d['amount']
        c.execute("""INSERT INTO advances (employee_id,date,amount,installment_count,installment_amount,remaining,status,note)
            VALUES (?,?,?,?,?,?,?,?)""",
            (d['employee_id'], d.get('date', datetime.now().strftime('%Y-%m-%d')),
             d['amount'], d['installment_count'], installment_amount, d['amount'], 'active', d.get('note','')))
        self.conn.commit()
        return c.lastrowid

    def delete_advance(self, adv_id):
        c = self._cur()
        c.execute("DELETE FROM advances WHERE id=?", (adv_id,))
        self.conn.commit()

    def calc_income_tax(self, annual_income, exempt=0):
        c = self._cur()
        c.execute("SELECT * FROM tax_brackets ORDER BY from_amount")
        brackets = [dict(r) for r in c.fetchall()]
        taxable = annual_income - exempt
        if taxable <= 0:
            return 0
        tax = 0
        for i, b in enumerate(brackets):
            if taxable <= b['from_amount']:
                break
            upper = b['to_amount']
            if upper is None:
                upper = taxable
            if taxable <= (upper if upper else taxable):
                segment = taxable - b['from_amount'] if taxable > b['from_amount'] else 0
                if b['fixed_deduction']:
                    tax = (taxable * b['rate']/100) - b['fixed_deduction']
                    break
                else:
                    tax = segment * b['rate']/100
                    break
        return max(0, round(tax, 2))

    def get_settings(self):
        c = self._cur()
        c.execute("SELECT TOP 1 * FROM settings")
        r = c.fetchone()
        return dict(r) if r else {}

    def save_settings(self, d):
        c = self._cur()
        if d and 'count_missing_as_absent' in d:
            count_missing = self._checkbox(d, 'count_missing_as_absent')
        else:
            count_missing = 1 if self._setting_on(self.get_settings(), 'count_missing_as_absent') else 0
        c.execute("""UPDATE settings SET company_name=?,company_address=?,company_phone=?,company_tax_id=?,
            company_insurance_no=?,currency=?,weekly_holidays=?,working_days_monthly=?,working_hours_daily=?,
            overtime_weekday=?,overtime_weekend=?,overtime_holiday=?,
            insurance_floor=?,insurance_ceiling=?,insurance_employee_ratio=?,insurance_employer_ratio=?,
            tax_exempt_default=?,absence_deduction_percent=?,late_minutes_tolerance=?,late_deduction_per_hour=?,
            count_missing_as_absent=? WHERE id=1""",
            (d.get('company_name',''),d.get('company_address',''),d.get('company_phone',''),d.get('company_tax_id',''),
             d.get('company_insurance_no',''),d.get('currency','EGP'),d.get('weekly_holidays','6'),
             d.get('working_days_monthly',26),d.get('working_hours_daily',8),
             d.get('overtime_weekday',1.5),d.get('overtime_weekend',2.0),d.get('overtime_holiday',3.0),
             d.get('insurance_floor',2200),d.get('insurance_ceiling',14700),
             d.get('insurance_employee_ratio',11),d.get('insurance_employer_ratio',18.75),
             d.get('tax_exempt_default',0),d.get('absence_deduction_percent',100),
             d.get('late_minutes_tolerance',15),d.get('late_deduction_per_hour',0),
             count_missing))
        self.conn.commit()

    # ---- Backups: SQL Server uses BACKUP DATABASE ----
    def create_backup(self):
        stamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        backups_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'backups')
        os.makedirs(backups_dir, exist_ok=True)
        dest = os.path.join(backups_dir, f'backup_{stamp}.bak')
        c = self._cur()
        # NOTE: SQL Server service account must have write access to this folder.
        c.execute(f"BACKUP DATABASE [{DB_NAME}] TO DISK = N'{dest}' WITH INIT")
        now = datetime.now().strftime('%Y-%m-%d %H:%M')
        c.execute("UPDATE settings SET last_backup=? WHERE id=1", (now,))
        self.conn.commit()
        return dest, now

    def list_backups(self):
        backups_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'backups')
        if not os.path.isdir(backups_dir):
            return []
        out = []
        for f in sorted(os.listdir(backups_dir), reverse=True):
            if f.startswith('backup_') and f.endswith('.bak'):
                p = os.path.join(backups_dir, f)
                out.append({'filename': f, 'path': p,
                            'size': os.path.getsize(p),
                            'created': datetime.fromtimestamp(os.path.getmtime(p)).strftime('%Y-%m-%d %H:%M')})
        return out

    def delete_backup(self, filename):
        backups_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'backups')
        p = os.path.join(backups_dir, filename)
        if os.path.isfile(p) and filename.startswith('backup_') and filename.endswith('.bak'):
            os.remove(p)
            return True
        return False

    def restore_backup(self, filename):
        backups_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'backups')
        p = os.path.join(backups_dir, filename)
        if not (os.path.isfile(p) and filename.startswith('backup_') and filename.endswith('.bak')):
            raise ValueError('ملف نسخة احتياطية غير صالح')
        # Force single-user mode, restore, return to multi-user
        master = pyodbc.connect(_master_conn_str(), autocommit=True)
        cur = master.cursor()
        cur.execute(f"ALTER DATABASE [{DB_NAME}] SET SINGLE_USER WITH ROLLBACK IMMEDIATE")
        cur.execute(f"RESTORE DATABASE [{DB_NAME}] FROM DISK = N'{p}' WITH REPLACE")
        cur.execute(f"ALTER DATABASE [{DB_NAME}] SET MULTI_USER")
        cur.close()
        master.close()
        # Reconnect
        self.conn.close()
        self.conn = _Conn(pyodbc.connect(_conn_str()))
        return True

    def run_auto_backup_if_due(self):
        sett = self.get_settings()
        last = (sett.get('last_backup') or '')
        if not last.startswith(datetime.now().strftime('%Y-%m')):
            try:
                self.create_backup()
                return True
            except Exception:
                return False
        return False

    def mark_password_changed(self):
        c = self._cur()
        c.execute("UPDATE settings SET admin_password_changed=1 WHERE id=1")
        self.conn.commit()

    def admin_must_change_password(self, user):
        if not user or user.get('role') != 'admin':
            return False
        sett = self.get_settings()
        return not bool(sett.get('admin_password_changed'))

    def get_tax_brackets(self):
        c = self._cur()
        c.execute("SELECT * FROM tax_brackets ORDER BY from_amount")
        return [dict(r) for r in c.fetchall()]

    def _weekly_holiday_weekdays(self, settings):
        raw = str((settings or {}).get('weekly_holidays') or '').strip()
        days = set()
        for part in re.split(r'[,\s;/]+', raw):
            if not part:
                continue
            try:
                n = int(float(part))
            except Exception:
                continue
            if 0 <= n <= 6:
                days.add((n - 2) % 7)
        return days

    def get_working_days(self, month, settings=None, upto_today=True):
        settings = settings if settings is not None else self.get_settings()
        try:
            parts = str(month).split('-')
            year, mon = int(parts[0]), int(parts[1])
            ndays = calendar.monthrange(year, mon)[1]
        except Exception:
            return int(round(float(settings.get('working_days_monthly') or 26)))
        limit = ndays
        if upto_today:
            today = datetime.now()
            if (year, mon) > (today.year, today.month):
                limit = 0
            elif (year, mon) == (today.year, today.month):
                limit = min(ndays, today.day)
        weekend = self._weekly_holiday_weekdays(settings)
        return sum(1 for day in range(1, limit + 1) if datetime(year, mon, day).weekday() not in weekend)

    def get_approved_leave_dates(self, emp_id, month):
        if not emp_id:
            return set()
        try:
            parts = str(month).split('-')
            year, mon = int(parts[0]), int(parts[1])
            first = datetime(year, mon, 1)
            last = datetime(year, mon, calendar.monthrange(year, mon)[1])
        except Exception:
            return set()
        c = self._cur()
        c.execute("""SELECT start_date, end_date FROM leave_requests
                     WHERE employee_id=? AND status='approved' AND start_date<=? AND end_date>=?""",
                  (emp_id, last.strftime('%Y-%m-%d'), first.strftime('%Y-%m-%d')))
        dates = set()
        for r in c.fetchall():
            try:
                s = datetime.strptime(str(r['start_date'])[:10], '%Y-%m-%d')
                e = datetime.strptime(str(r['end_date'])[:10], '%Y-%m-%d')
            except Exception:
                continue
            d = max(s, first)
            end = min(e, last)
            while d <= end:
                dates.add(d.strftime('%Y-%m-%d'))
                d += timedelta(days=1)
        return dates

    def calculate_payroll(self, month):
        settings = self.get_settings()
        c = self._cur()
        employees = self.get_employees(status='active')
        monthly_days = settings['working_days_monthly']
        payable_days = self.get_working_days(month, settings)
        count_missing = self._setting_on(settings, 'count_missing_as_absent')

        results = []
        for emp in employees:
            emp_id = emp['id']
            if emp['pay_type'] == 'monthly':
                base = emp['base_salary']
                daily = base / monthly_days if monthly_days > 0 else 0
                hourly = daily / settings['working_hours_daily'] if settings['working_hours_daily'] > 0 else 0
            elif emp['pay_type'] == 'daily':
                daily = emp['daily_rate']
                base = daily * monthly_days
                hourly = daily / settings['working_hours_daily'] if settings['working_hours_daily'] > 0 else 0
            elif emp['pay_type'] == 'hourly':
                hourly = emp['hourly_rate']
                daily = hourly * settings['working_hours_daily']
                base = daily * monthly_days
            else:
                daily = 0; hourly = 0; base = 0

            allowances = (emp['housing_allowance'] + emp['transport_allowance'] + emp['food_allowance'] +
                          emp['other_allowances'] + emp['danger_allowance'] + emp['phone_allowance'])

            c.execute("SELECT * FROM attendance WHERE employee_id=? AND month=?", (emp_id, month))
            att_records = [dict(r) for r in c.fetchall()]
            present_days = sum(1 for a in att_records if a['status'] in ('present','late'))
            late_days = sum(1 for a in att_records if a['status'] == 'late')
            sick_days = sum(1 for a in att_records if a['status'] == 'sick')
            leave_days = sum(1 for a in att_records if a['status'] == 'leave')

            absent_dates = {a['date'] for a in att_records if a['status'] == 'absent'}
            recorded_dates = {a['date'] for a in att_records if a['status'] in ('present','late','leave','sick')}
            absent_days = len(absent_dates)
            missing_days = 0
            if count_missing:
                known_dates = recorded_dates | (self.get_approved_leave_dates(emp_id, month) - absent_dates)
                missing_days = max(0, int(payable_days) - (len(known_dates) + absent_days))
                absent_days += missing_days

            c.execute("""SELECT COALESCE(SUM(hours),0) as hrs, COALESCE(SUM(amount),0) as amt
                         FROM overtime WHERE employee_id=? AND month=?""", (emp_id, month))
            ot = dict(c.fetchone())
            overtime_amt = ot['amt']

            c.execute("""SELECT COALESCE(SUM(amount),0) as amt FROM commissions WHERE employee_id=? AND month=?""", (emp_id, month))
            commissions = float(c.fetchone()['amt'])

            base_allowances = base + allowances
            gross = base_allowances + overtime_amt + commissions

            si_employee = 0; si_employer = 0
            if emp['social_insurance_enabled']:
                ins_floor = settings['insurance_floor']
                ins_ceiling = settings['insurance_ceiling']
                ins_base = min(max(base, ins_floor), ins_ceiling) if ins_ceiling else max(base, ins_floor)
                emp_ratio = emp['social_insurance_employee_ratio'] if emp['social_insurance_employee_ratio'] else settings['insurance_employee_ratio']
                empl_ratio = emp['social_insurance_employer_ratio'] if emp['social_insurance_employer_ratio'] else settings['insurance_employer_ratio']
                si_employee = ins_base * emp_ratio / 100
                si_employer = ins_base * empl_ratio / 100

            income_tax = 0
            if emp['income_tax_enabled']:
                annual = gross * 12
                exempt = emp['tax_exempt_amount'] if emp['tax_exempt_amount'] else settings['tax_exempt_default']
                income_tax = self.calc_income_tax(annual, exempt)

            advance_installments = 0.0
            c.execute("""SELECT installment_amount, installment_count, current_installment, remaining, date
                         FROM advances WHERE employee_id=? AND status='active'""", (emp_id,))
            for adv in c.fetchall():
                start_month = (adv['date'] or '')[:7]
                if not start_month or start_month > month:
                    continue
                if int(adv['current_installment'] or 0) >= int(adv['installment_count'] or 0):
                    continue
                adv_remaining = float(adv['remaining'] or 0)
                if adv_remaining <= 0:
                    continue
                advance_installments += min(float(adv['installment_amount'] or 0), adv_remaining)

            absence_deduction = absent_days * daily * (settings['absence_deduction_percent']/100)
            c.execute("""SELECT COALESCE(SUM(days),0) as d FROM leave_requests
                         WHERE employee_id=? AND leave_type='unpaid' AND status='approved' AND LEFT(start_date,7)=?""", (emp_id, month))
            unpaid_days = float(c.fetchone()['d'])
            absence_deduction += unpaid_days * daily

            late_deduction = late_days * settings['late_deduction_per_hour'] * settings['working_hours_daily']

            c.execute("""SELECT COALESCE(SUM(amount),0) as amt FROM deductions WHERE employee_id=? AND month=?""", (emp_id, month))
            other_deductions = float(c.fetchone()['amt'])
            manual_earnings = 0

            c.execute("SELECT * FROM bulk_incentives WHERE month=?", (month,))
            for bi in c.fetchall():
                spe = []
                if bi['specific_employees']:
                    try:
                        spe = json.loads(bi['specific_employees'])
                    except Exception:
                        spe = []
                if spe and str(emp_id) not in [str(s) for s in spe]:
                    continue
                amt = bi['per_employee_amount'] or 0
                if bi['kind'] == 'bonus':
                    manual_earnings += amt
                else:
                    other_deductions += amt

            gross = gross + manual_earnings

            total_deductions = (si_employee + income_tax/12 + advance_installments + absence_deduction +
                                late_deduction + other_deductions)
            net = gross - total_deductions

            results.append({
                'employee_id': emp_id,
                'emp_code': emp['emp_code'],
                'name': emp['name'],
                'dept_name': emp.get('dept_name',''),
                'position': emp['position'],
                'pay_type': emp['pay_type'],
                'base': round(base,2),
                'daily': round(daily,2),
                'hourly': round(hourly,2),
                'allowances': round(allowances,2),
                'overtime_amt': round(overtime_amt,2),
                'commissions': round(commissions,2),
                'bonus': round(manual_earnings,2),
                'gross': round(gross,2),
                'si_employee': round(si_employee,2),
                'si_employer': round(si_employer,2),
                'income_tax': round(income_tax/12,2),
                'advance_installments': round(advance_installments,2),
                'absence_deduction': round(absence_deduction,2),
                'late_deduction': round(late_deduction,2),
                'other_deductions': round(other_deductions,2),
                'total_deductions': round(total_deductions,2),
                'net': round(net,2),
                'present_days': present_days,
                'absent_days': absent_days,
                'late_days': late_days,
                'sick_days': sick_days,
                'leave_days': leave_days,
                'payable_days': int(payable_days),
                'missing_days': missing_days,
                'overtime_hours': ot['hrs']
            })
        return results

    def save_payroll(self, month, records):
        c = self._cur()
        for r in records:
            c.execute("""INSERT OR REPLACE INTO payroll_proof
                (employee_id,month,gross_salary,total_allowances,overtime_amount,commission_amount,
                 total_earnings,social_insurance_employee,social_insurance_employer,income_tax,
                 advance_installments,absence_deduction,late_deduction,other_deductions,total_deductions,
                 net_salary,days_worked,status)
                VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                (r['employee_id'], month, r['base'], r['allowances'], r['overtime_amt'], r['commissions'],
                 r['gross'], r['si_employee'], r['si_employer'], r['income_tax']*12,
                 r['advance_installments'], r['absence_deduction'], r['late_deduction'],
                 r['other_deductions'], r['total_deductions'], r['net'],
                 r['present_days'], 'draft'))
        self.conn.commit()

    def confirm_payroll(self, month, user):
        c = self._cur()
        c.execute("SELECT employee_id FROM payroll_proof WHERE month=? AND status='draft'", (month,))
        draft_ids = [r['employee_id'] for r in c.fetchall()]
        c.execute("SELECT COUNT(*) AS n FROM payroll_proof WHERE month=?", (month,))
        has_saved = int(c.fetchone()['n']) > 0
        c.execute("UPDATE payroll_proof SET status='confirmed' WHERE month=?", (month,))

        if has_saved and draft_ids:
            ph = ','.join('?' * len(draft_ids))
            c.execute(f"""SELECT id, installment_amount, installment_count, current_installment, remaining
                          FROM advances
                          WHERE status='active' AND LEFT(date,7) <= ?
                            AND employee_id IN ({ph})""", (month, *draft_ids))
            rows = c.fetchall()
        else:
            rows = []

        for adv in rows:
            count = int(adv['installment_count'] or 0)
            cur_inst = int(adv['current_installment'] or 0)
            remaining = float(adv['remaining'] or 0)
            if count <= 0 or cur_inst >= count or remaining <= 0:
                continue
            paid = min(float(adv['installment_amount'] or 0), remaining)
            if paid <= 0:
                continue
            cur_inst += 1
            finished = cur_inst >= count
            new_remaining = 0.0 if finished else max(0.0, round(remaining - paid, 2))
            new_status = 'done' if (finished or new_remaining <= 0) else 'active'
            c.execute("""UPDATE advances SET current_installment=?, remaining=?, status=?
                         WHERE id=?""", (cur_inst, new_remaining, new_status, adv['id']))
        self.conn.commit()

    def get_saved_payroll(self, month):
        c = self._cur()
        c.execute("""SELECT p.*, e.name, e.emp_code, e.pay_type, d.name as dept_name
            FROM payroll_proof p JOIN employees e ON p.employee_id=e.id
            LEFT JOIN departments d ON e.department_id=d.id
            WHERE p.month=? ORDER BY e.name""", (month,))
        return [dict(r) for r in c.fetchall()]

    def get_dashboard_stats(self):
        c = self._cur()
        stats = {}
        c.execute("SELECT COUNT(*) cnt FROM employees WHERE status='active'")
        stats['employees'] = c.fetchone()['cnt']
        c.execute("SELECT COUNT(*) cnt FROM departments WHERE active=1")
        stats['departments'] = c.fetchone()['cnt']
        c.execute("SELECT COALESCE(SUM(base_salary),0) s FROM employees WHERE status='active'")
        stats['total_monthly_salary'] = c.fetchone()['s']
        c.execute("SELECT COUNT(*) cnt FROM leave_requests WHERE status='pending'")
        stats['pending_leaves'] = c.fetchone()['cnt']
        c.execute("SELECT COALESCE(SUM(remaining),0) s FROM advances WHERE status='active'")
        stats['active_advances'] = c.fetchone()['s']
        c.execute("SELECT COALESCE(SUM(amount),0) s FROM overtime WHERE month=?", (datetime.now().strftime('%Y-%m'),))
        stats['month_overtime'] = c.fetchone()['s']
        return stats

    def log_audit(self, action, entity='', entity_id=None, details=''):
        try:
            c = self._cur()
            c.execute("""INSERT INTO audit_log (user_id,username,action,entity,entity_id,details,ip_address)
                VALUES (?,?,?,?,?,?,?)""",
                (getattr(self, '_uid', None), getattr(self, '_uname', ''),
                 action, entity, entity_id, details[:2000], getattr(self, '_ip', '')))
            self.conn.commit()
        except Exception:
            pass

    def get_audit_log(self, limit=200, day=''):
        c = self._cur()
        if day:
            c.execute("SELECT TOP (?) * FROM audit_log WHERE LEFT(CAST(created_at AS NVARCHAR(30)),10)=? ORDER BY created_at DESC, id DESC", (limit, day))
        else:
            c.execute("SELECT TOP (?) * FROM audit_log ORDER BY created_at DESC, id DESC", (limit,))
        return [dict(r) for r in c.fetchall()]

    def add_contract(self, d):
        c = self._cur()
        c.execute("""INSERT INTO contracts (employee_id,contract_type,contract_number,start_date,end_date,
            salary,allowance_details,notes,status) VALUES (?,?,?,?,?,?,?,?,?)""",
            (d['employee_id'], d.get('contract_type','permanent'), d.get('contract_number',''),
             d['start_date'], d.get('end_date',''), d.get('salary',0),
             d.get('allowance_details',''), d.get('notes',''), d.get('status','active')))
        self.conn.commit()
        return c.lastrowid

    def update_contract(self, cid, d):
        c = self._cur()
        c.execute("""UPDATE contracts SET contract_type=?,contract_number=?,start_date=?,end_date=?,
            salary=?,allowance_details=?,notes=?,status=? WHERE id=?""",
            (d.get('contract_type','permanent'), d.get('contract_number',''), d['start_date'],
             d.get('end_date',''), d.get('salary',0), d.get('allowance_details',''),
             d.get('notes',''), d.get('status','active'), cid))
        self.conn.commit()

    def get_contracts(self, emp_id=None):
        c = self._cur()
        q = """SELECT co.*, e.name as emp_name, e.emp_code
               FROM contracts co JOIN employees e ON co.employee_id=e.id WHERE 1=1"""
        params = []
        if emp_id:
            q += " AND co.employee_id=?"
            params.append(emp_id)
        q += " ORDER BY co.start_date DESC"
        c.execute(q, params)
        return [dict(r) for r in c.fetchall()]

    def get_expiring_contracts(self, days=30):
        c = self._cur()
        q = """SELECT co.*, e.name as emp_name, e.emp_code
               FROM contracts co JOIN employees e ON co.employee_id=e.id
               WHERE co.end_date IS NOT NULL AND co.end_date!='' AND co.status='active'
               AND TRY_CAST(co.end_date AS date) BETWEEN CAST(GETDATE() AS date)
                   AND DATEADD(day, ?, CAST(GETDATE() AS date))
               ORDER BY co.end_date"""
        c.execute(q, (days,))
        return [dict(r) for r in c.fetchall()]

    def delete_contract(self, cid):
        c = self._cur()
        c.execute("DELETE FROM contracts WHERE id=?", (cid,))
        self.conn.commit()

    def sign_payroll(self, emp_id, month, slip_number, gross, net, signature_data, ip='', notes=''):
        c = self._cur()
        c.execute("""INSERT OR REPLACE INTO payroll_signatures
            (employee_id,month,slip_number,gross_salary,net_salary,signature_data,sign_date,signed_by_ip,notes)
            VALUES (?,?,?,?,?,?,?,?,?)""",
            (emp_id, month, slip_number, gross, net, signature_data,
             datetime.now().strftime('%Y-%m-%d %H:%M:%S'), ip, notes))
        self.conn.commit()

    def get_signatures(self, month=None, emp_id=None):
        c = self._cur()
        q = """SELECT s.*, e.name as emp_name, e.emp_code
               FROM payroll_signatures s JOIN employees e ON s.employee_id=e.id WHERE 1=1"""
        params = []
        if month:
            q += " AND s.month=?"
            params.append(month)
        if emp_id:
            q += " AND s.employee_id=?"
            params.append(emp_id)
        q += " ORDER BY s.sign_date DESC"
        c.execute(q, params)
        return [dict(r) for r in c.fetchall()]

    def has_signed(self, emp_id, month):
        c = self._cur()
        c.execute("SELECT COUNT(*) cnt FROM payroll_signatures WHERE employee_id=? AND month=?", (emp_id, month))
        return c.fetchone()['cnt'] > 0

    def add_bulk_incentive(self, d, by_user=''):
        c = self._cur()
        c.execute("""INSERT INTO bulk_incentives (month,kind,description,per_employee_amount,specific_employees,created_by)
            VALUES (?,?,?,?,?,?)""",
            (d['month'], d.get('kind','bonus'), d.get('description',''), d.get('per_employee_amount',0),
             d.get('specific_employees',''), by_user))
        self.conn.commit()
        return c.lastrowid

    def get_bulk_incentives(self, month=None):
        c = self._cur()
        q = "SELECT * FROM bulk_incentives WHERE 1=1"
        params = []
        if month:
            q += " AND month=?"
            params.append(month)
        q += " ORDER BY created_at DESC"
        c.execute(q, params)
        return [dict(r) for r in c.fetchall()]

    def delete_bulk_incentive(self, bid):
        c = self._cur()
        c.execute("DELETE FROM bulk_incentives WHERE id=?", (bid,))
        self.conn.commit()

    def get_pay_type_distribution(self):
        c = self._cur()
        c.execute("""SELECT pay_type as type, COUNT(*) cnt, COALESCE(SUM(base_salary),0) base
                     FROM employees WHERE status='active' GROUP BY pay_type""")
        return [dict(r) for r in c.fetchall()]

    def get_monthly_budget(self, month):
        data = self.calculate_payroll(month)
        return {
            'net': round(sum(r['net'] for r in data), 2),
            'gross': round(sum(r['gross'] for r in data), 2),
            'deductions': round(sum(r['total_deductions'] for r in data), 2),
            'count': len(data),
            'si_employer': round(sum(r['si_employer'] for r in data), 2),
        }

    def apply_bulk_to_payroll(self, month):
        return True