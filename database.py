import sqlite3
import os
import re
import sys
import json
import calendar
from datetime import datetime, timedelta
from werkzeug.security import generate_password_hash, check_password_hash

# في وضع PyInstaller: قاعدة البيانات تكون بجوار الـ exe (وليس في مجلد التحميل المؤقت)
if getattr(sys, 'frozen', False):
    _BASE_DIR = os.path.dirname(sys.executable)
else:
    _BASE_DIR = os.path.dirname(os.path.abspath(__file__))

DB_PATH = os.path.join(_BASE_DIR, 'payroll.db')

class Database:
    def __init__(self):
        self.conn = sqlite3.connect(DB_PATH, check_same_thread=False, timeout=30)
        self.conn.row_factory = sqlite3.Row
        self.conn.execute("PRAGMA foreign_keys = ON")
        self.conn.execute("PRAGMA journal_mode = WAL")
        self.create_tables()
        self._migrate()
        self.seed_defaults()

    def _cur(self):
        return self.conn.cursor()

    def _checkbox(self, d, key):
        """قراءة قيمة مربع اختيار من بيانات النموذج (1 عند التحديد، 0 عند عدمه)."""
        return 1 if str((d or {}).get(key, '')).strip().lower() in ('1', 'on', 'true', 'yes') else 0

    def _setting_on(self, settings, key, default=1):
        """هل الإعداد المذكور مفعّل؟ (يتعامل مع 1/0 والقيم النصية)"""
        v = (settings or {}).get(key, default)
        if v is None:
            v = default
        if isinstance(v, str):
            return v.strip().lower() in ('1', 'on', 'true', 'yes')
        return bool(v)

    def create_tables(self):
        c = self._cur()
        c.executescript('''
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT NOT NULL UNIQUE,
                password TEXT NOT NULL,
                full_name TEXT DEFAULT '',
                role TEXT DEFAULT 'user',
                active INTEGER DEFAULT 1,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            );

            CREATE TABLE IF NOT EXISTS departments (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL UNIQUE,
                manager TEXT DEFAULT '',
                cost_center TEXT DEFAULT '',
                active INTEGER DEFAULT 1,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            );

            CREATE TABLE IF NOT EXISTS employees (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                emp_code TEXT NOT NULL UNIQUE,
                name TEXT NOT NULL,
                national_id TEXT DEFAULT '',
                department_id INTEGER,
                position TEXT DEFAULT '',
                phone TEXT DEFAULT '',
                email TEXT DEFAULT '',
                address TEXT DEFAULT '',
                gender TEXT DEFAULT 'male',
                birth_date TEXT DEFAULT '',
                hire_date TEXT DEFAULT '',
                termination_date TEXT DEFAULT '',
                marital_status TEXT DEFAULT '',
                bank_name TEXT DEFAULT '',
                bank_account TEXT DEFAULT '',
                -- نوع الأجر: monthly / daily / hourly / commission
                pay_type TEXT DEFAULT 'monthly',
                base_salary REAL DEFAULT 0,
                daily_rate REAL DEFAULT 0,
                hourly_rate REAL DEFAULT 0,
                commission_rate REAL DEFAULT 0,
                -- البدلات
                housing_allowance REAL DEFAULT 0,
                transport_allowance REAL DEFAULT 0,
                food_allowance REAL DEFAULT 0,
                other_allowances REAL DEFAULT 0,
                danger_allowance REAL DEFAULT 0,
                phone_allowance REAL DEFAULT 0,
                -- التأمين والضرائب
                social_insurance_enabled INTEGER DEFAULT 1,
                social_insurance_employee_ratio REAL DEFAULT 11,
                social_insurance_employer_ratio REAL DEFAULT 18.75,
                income_tax_enabled INTEGER DEFAULT 1,
                tax_exempt_amount REAL DEFAULT 0,
                -- حالة
                status TEXT DEFAULT 'active',
                remarks TEXT DEFAULT '',
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (department_id) REFERENCES departments(id) ON DELETE SET NULL
            );

            CREATE TABLE IF NOT EXISTS attendance (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                employee_id INTEGER NOT NULL,
                date TEXT NOT NULL,
                check_in TEXT DEFAULT '',
                check_out TEXT DEFAULT '',
                status TEXT DEFAULT 'present', -- present/absent/late/leave/sick
                note TEXT DEFAULT '',
                month TEXT DEFAULT '',
                source TEXT DEFAULT 'manual', -- manual/device
                UNIQUE(employee_id, date),
                FOREIGN KEY (employee_id) REFERENCES employees(id) ON DELETE CASCADE
            );

            CREATE TABLE IF NOT EXISTS devices (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL,
                device_type TEXT DEFAULT 'zkteco',
                ip_address TEXT NOT NULL,
                port INTEGER DEFAULT 4370,
                serial_number TEXT DEFAULT '',
                location TEXT DEFAULT '',
                status TEXT DEFAULT 'disconnected', -- connected/disconnected/error
                last_sync TEXT DEFAULT '',
                total_records INTEGER DEFAULT 0,
                active INTEGER DEFAULT 1,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            );

            CREATE TABLE IF NOT EXISTS device_logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                device_id INTEGER NOT NULL,
                action TEXT NOT NULL, -- connect/disconnect/download/sync/apply/error
                description TEXT DEFAULT '',
                records_count INTEGER DEFAULT 0,
                success INTEGER DEFAULT 1,
                error_message TEXT DEFAULT '',
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (device_id) REFERENCES devices(id) ON DELETE CASCADE
            );

            CREATE TABLE IF NOT EXISTS biometric_attendance (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                device_id INTEGER NOT NULL,
                device_uid TEXT NOT NULL,
                check_date TEXT NOT NULL,
                check_time TEXT NOT NULL,
                check_type TEXT DEFAULT 'check_in', -- check_in/check_out
                status INTEGER DEFAULT 0, -- device raw status
                processed INTEGER DEFAULT 0, -- 0=pending, 1=processed, 2=skipped
                employee_id INTEGER DEFAULT NULL,
                note TEXT DEFAULT '',
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (device_id) REFERENCES devices(id) ON DELETE CASCADE,
                FOREIGN KEY (employee_id) REFERENCES employees(id) ON DELETE SET NULL,
                UNIQUE(device_id, device_uid, check_date, check_time)
            );

            CREATE TABLE IF NOT EXISTS device_employee_mapping (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                device_id INTEGER NOT NULL,
                device_uid TEXT NOT NULL,
                employee_id INTEGER NOT NULL,
                mapped_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (device_id) REFERENCES devices(id) ON DELETE CASCADE,
                FOREIGN KEY (employee_id) REFERENCES employees(id) ON DELETE CASCADE,
                UNIQUE(device_id, device_uid)
            );

            CREATE TABLE IF NOT EXISTS leave_requests (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                employee_id INTEGER NOT NULL,
                leave_type TEXT NOT NULL, -- annual/sick/emergency/unpaid/maternity
                start_date TEXT NOT NULL,
                end_date TEXT NOT NULL,
                days REAL DEFAULT 0,
                reason TEXT DEFAULT '',
                status TEXT DEFAULT 'pending', -- pending/approved/rejected
                approved_by TEXT DEFAULT '',
                approved_date TEXT DEFAULT '',
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (employee_id) REFERENCES employees(id) ON DELETE CASCADE
            );

            CREATE TABLE IF NOT EXISTS overtime (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                employee_id INTEGER NOT NULL,
                date TEXT NOT NULL,
                hours REAL DEFAULT 0,
                rate_type TEXT DEFAULT 'auto', -- auto/manual
                multiplier REAL DEFAULT 1.5,
                hourly_rate REAL DEFAULT 0,
                amount REAL DEFAULT 0,
                confirmed INTEGER DEFAULT 0,
                note TEXT DEFAULT '',
                month TEXT DEFAULT '',
                FOREIGN KEY (employee_id) REFERENCES employees(id) ON DELETE CASCADE
            );

            CREATE TABLE IF NOT EXISTS commissions (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                employee_id INTEGER NOT NULL,
                date TEXT NOT NULL,
                sales_amount REAL DEFAULT 0,
                rate REAL DEFAULT 0,
                amount REAL DEFAULT 0,
                note TEXT DEFAULT '',
                month TEXT DEFAULT '',
                FOREIGN KEY (employee_id) REFERENCES employees(id) ON DELETE CASCADE
            );

            CREATE TABLE IF NOT EXISTS deduction_types (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL UNIQUE,
                category TEXT DEFAULT 'other', -- penalty/loan/damage/social/food/other
                description TEXT DEFAULT '',
                active INTEGER DEFAULT 1
            );

            CREATE TABLE IF NOT EXISTS deductions (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                employee_id INTEGER NOT NULL,
                date TEXT NOT NULL,
                deduction_type TEXT DEFAULT '',
                amount REAL DEFAULT 0,
                note TEXT DEFAULT '',
                month TEXT DEFAULT '',
                FOREIGN KEY (employee_id) REFERENCES employees(id) ON DELETE CASCADE
            );

            CREATE TABLE IF NOT EXISTS advances (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                employee_id INTEGER NOT NULL,
                date TEXT NOT NULL,
                amount REAL DEFAULT 0,
                installment_count INTEGER DEFAULT 1,
                installment_amount REAL DEFAULT 0,
                current_installment INTEGER DEFAULT 0,
                remaining REAL DEFAULT 0,
                status TEXT DEFAULT 'active',
                note TEXT DEFAULT '',
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (employee_id) REFERENCES employees(id) ON DELETE CASCADE
            );

            CREATE TABLE IF NOT EXISTS payroll_proof (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                employee_id INTEGER NOT NULL,
                month TEXT NOT NULL,
                gross_salary REAL DEFAULT 0,
                total_allowances REAL DEFAULT 0,
                overtime_amount REAL DEFAULT 0,
                commission_amount REAL DEFAULT 0,
                total_earnings REAL DEFAULT 0,
                social_insurance_employee REAL DEFAULT 0,
                social_insurance_employer REAL DEFAULT 0,
                income_tax REAL DEFAULT 0,
                advance_installments REAL DEFAULT 0,
                absence_deduction REAL DEFAULT 0,
                late_deduction REAL DEFAULT 0,
                other_deductions REAL DEFAULT 0,
                total_deductions REAL DEFAULT 0,
                net_salary REAL DEFAULT 0,
                days_worked REAL DEFAULT 0,
                status TEXT DEFAULT 'draft', -- draft/confirmed/paid
                paid_date TEXT DEFAULT '',
                note TEXT DEFAULT '',
                UNIQUE(employee_id, month),
                FOREIGN KEY (employee_id) REFERENCES employees(id) ON DELETE CASCADE
            );

            CREATE TABLE IF NOT EXISTS salary_history (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                employee_id INTEGER NOT NULL,
                old_salary REAL DEFAULT 0,
                new_salary REAL DEFAULT 0,
                change_date TEXT DEFAULT '',
                reason TEXT DEFAULT '',
                created_by TEXT DEFAULT '',
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (employee_id) REFERENCES employees(id) ON DELETE CASCADE
            );

            -- التعاقدات
            CREATE TABLE IF NOT EXISTS contracts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                employee_id INTEGER NOT NULL,
                contract_type TEXT DEFAULT 'permanent', -- permanent/fixed/temporary/parttime
                contract_number TEXT DEFAULT '',
                start_date TEXT NOT NULL,
                end_date TEXT DEFAULT '',
                salary REAL DEFAULT 0,
                allowance_details TEXT DEFAULT '',
                notes TEXT DEFAULT '',
                status TEXT DEFAULT 'active', -- active/expired/terminated
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (employee_id) REFERENCES employees(id) ON DELETE CASCADE
            );

            -- توقيع استلام الراتب (بصمة إلكترونية)
            CREATE TABLE IF NOT EXISTS payroll_signatures (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                employee_id INTEGER NOT NULL,
                month TEXT NOT NULL,
                slip_number TEXT DEFAULT '',
                gross_salary REAL DEFAULT 0,
                net_salary REAL DEFAULT 0,
                signature_data TEXT DEFAULT '',       -- قاعدة بيانات من الصورة أو نص التوقيع
                sign_date TEXT DEFAULT '',
                signed_by_ip TEXT DEFAULT '',
                notes TEXT DEFAULT '',
                UNIQUE(employee_id, month),
                FOREIGN KEY (employee_id) REFERENCES employees(id) ON DELETE CASCADE
            );

            -- سجل التدقيق (إجراءات حساسة)
            CREATE TABLE IF NOT EXISTS audit_log (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER,
                username TEXT DEFAULT '',
                action TEXT DEFAULT '',
                entity TEXT DEFAULT '',
                entity_id INTEGER,
                details TEXT DEFAULT '',
                ip_address TEXT DEFAULT '',
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            );

            -- حوافز/خصومات جماعية
            CREATE TABLE IF NOT EXISTS bulk_incentives (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                month TEXT NOT NULL,
                kind TEXT NOT NULL,        -- bonus / ded
                description TEXT DEFAULT '',
                per_employee_amount REAL DEFAULT 0,
                specific_employees TEXT DEFAULT '', -- JSON list or empty = all active
                applied INTEGER DEFAULT 0,
                created_by TEXT DEFAULT '',
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            );

            -- ضريبة كسب العمل بالشرائح
            CREATE TABLE IF NOT EXISTS tax_brackets (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                from_amount REAL NOT NULL,
                to_amount REAL,    -- NULL = infinity
                rate REAL NOT NULL,
                fixed_deduction REAL DEFAULT 0
            );

            CREATE TABLE IF NOT EXISTS settings (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                company_name TEXT DEFAULT '',
                company_address TEXT DEFAULT '',
                company_phone TEXT DEFAULT '',
                company_tax_id TEXT DEFAULT '',
                company_insurance_no TEXT DEFAULT '',
                currency TEXT DEFAULT 'EGP',
                -- العمل
                weekly_holidays TEXT DEFAULT '6', -- يوم الجمعة (0=السبت .. 6=الجمعة)
                working_days_monthly REAL DEFAULT 26,
                working_hours_daily REAL DEFAULT 8,
                -- الإضافي
                overtime_weekday REAL DEFAULT 1.5,
                overtime_weekend REAL DEFAULT 2.0,
                overtime_holiday REAL DEFAULT 3.0,
                -- التأمينات
                insurance_floor REAL DEFAULT 2200,
                insurance_ceiling REAL DEFAULT 14700,
                insurance_employee_ratio REAL DEFAULT 11,
                insurance_employer_ratio REAL DEFAULT 18.75,
                -- ضرائب
                tax_exempt_default REAL DEFAULT 0,
                -- غياب/تأخير
                absence_deduction_percent REAL DEFAULT 100,
                late_minutes_tolerance INTEGER DEFAULT 15,
                late_deduction_per_hour REAL DEFAULT 0,
                -- احتساب الأيام بدون سجل حضور كغياب (1 = مفعّل: لا يُحتسب اليوم إلا بوجود سجل حضور)
                count_missing_as_absent INTEGER DEFAULT 1,
                -- أمان
                admin_password_changed INTEGER DEFAULT 0
            );
        ''')
        self.conn.commit()

    def _migrate(self):
        """ترحيل تدريجي للجداول الموجودة (إضافة أعمدة جديدة بدون فقدان بيانات)."""
        c = self._cur()
        # 1) عمود admin_password_changed في settings لإلزام تغيير كلمة مرور المدير أول مرة
        cols = [r[1] for r in c.execute("PRAGMA table_info(settings)").fetchall()]
        if 'admin_password_changed' not in cols:
            c.execute("ALTER TABLE settings ADD COLUMN admin_password_changed INTEGER DEFAULT 0")
        # 2) عمود last_backup في settings لتتبع النسخ الاحتياطي التلقائي الشهري
        if 'last_backup' not in cols:
            c.execute("ALTER TABLE settings ADD COLUMN last_backup TEXT DEFAULT ''")
        # 3) عمود count_missing_as_absent: الأيام بدون سجل حضور تُحتسب غياباً (مفعّل افتراضياً)
        if 'count_missing_as_absent' not in cols:
            c.execute("ALTER TABLE settings ADD COLUMN count_missing_as_absent INTEGER DEFAULT 1")
        # 4) Device extra columns
        dev_cols = [r[1] for r in c.execute("PRAGMA table_info(devices)").fetchall()]
        if 'comm_key' not in dev_cols:
            c.execute("ALTER TABLE devices ADD COLUMN comm_key INTEGER DEFAULT 0")
        if 'notes' not in dev_cols:
            c.execute("ALTER TABLE devices ADD COLUMN notes TEXT DEFAULT ''")
        # 5) Attendance source column
        att_cols = [r[1] for r in c.execute("PRAGMA table_info(attendance)").fetchall()]
        if 'source' not in att_cols:
            c.execute("ALTER TABLE attendance ADD COLUMN source TEXT DEFAULT 'manual'")
        self.conn.commit()

    def seed_defaults(self):
        c = self._cur()
        # المستخدمون الافتراضيون (يُنبأون فقط عند قاعدة بيانات جديدة تماماً)
        c.execute("SELECT COUNT(*) FROM users")
        if c.fetchone()[0] == 0:
            users = [
                ('admin', 'admin123', 'مدير النظام', 'admin'),
                ('supervisor', 'super123', 'محمد المشرف', 'supervisor'),
                ('user', 'user123', 'سارة المستخدمة', 'user'),
                ('viewer', 'viewer123', 'خالد المشاهد', 'viewer'),
            ]
            for uname, pwd, fname, role in users:
                c.execute("INSERT INTO users (username,password,full_name,role) VALUES (?,?,?,?)",
                    (uname, generate_password_hash(pwd), fname, role))
        # settings
        c.execute("SELECT COUNT(*) FROM settings")
        if c.fetchone()[0] == 0:
            c.execute("INSERT INTO settings DEFAULT VALUES")
        # tax brackets - ضريبة كسب العمل في مصر
        c.execute("SELECT COUNT(*) FROM tax_brackets")
        if c.fetchone()[0] == 0:
            brackets = [
                (0, 15000, 0, 0),          # معفاة
                (15000, 30000, 2.5, 0),     # شريحة أولى
                (30000, 45000, 10, 375),    # شريحة ثانية
                (45000, 60000, 15, 2625),   # شريحة ثالثة
                (60000, 200000, 20, 5625),  # شريحة رابعة
                (200000, 400000, 22.5, 10625), # شريحة خامسة
                (400000, 500000, 25, 20625),   # شريحة سادسة
                (500000, 900000, 30, 45625),   # شريحة سابعة
                (900000, None, 32.5, 68125),   # أعلى
            ]
            c.executemany("INSERT INTO tax_brackets (from_amount,to_amount,rate,fixed_deduction) VALUES (?,?,?,?)", brackets)
        # deduction types
        c.execute("SELECT COUNT(*) FROM deduction_types")
        if c.fetchone()[0] == 0:
            types = [
                ('جزاء إداري', 'penalty', 'خصم بسبب مخالفة'),
                ('قرض', 'loan', 'أقساط قرض'),
                ('تلفيات', 'damage', 'خصم أضرار'),
                ('سلفة', 'advance', 'أقساط سلفة'),
                ('طعام', 'food', 'اشتراك وجبات'),
                ('موبايل', 'social', 'فاتورة موبايل'),
                ('خصم آخر', 'other', 'أي خصم آخر'),
            ]
            c.executemany("INSERT INTO deduction_types (name,category,description) VALUES (?,?,?)", types)
        self.conn.commit()

    # ==================== AUTH ====================
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

    # ==================== DEPARTMENTS ====================
    def get_departments(self, active_only=False):
        c = self._cur()
        q = """SELECT d.*, COUNT(e.id) as emp_count
               FROM departments d LEFT JOIN employees e ON d.id=e.department_id AND e.status='active'"""
        if active_only:
            q += " WHERE d.active=1"
        q += " GROUP BY d.id ORDER BY d.name"
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

    # ==================== EMPLOYEES ====================
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
        c.execute("SELECT emp_code FROM employees ORDER BY id DESC LIMIT 1")
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

    # ==================== ATTENDANCE ====================
    def get_attendance(self, month):
        c = self._cur()
        c.execute("""SELECT a.*, e.name as emp_name, e.emp_code
            FROM attendance a JOIN employees e ON a.employee_id=e.id
            WHERE a.month=? ORDER BY e.name, a.date""", (month,))
        return [dict(r) for r in c.fetchall()]

    def get_employee_attendance(self, emp_id, month=None, date_from=None, date_to=None, status=None):
        """Get attendance records strictly for one employee with optional filtering."""
        c = self._cur()
        q = """SELECT a.*, e.name as emp_name, e.emp_code
               FROM attendance a JOIN employees e ON a.employee_id=e.id
               WHERE a.employee_id=?"""
        params = [emp_id]
        if month:
            q += " AND (a.month=? OR a.date LIKE ?)"
            params.extend([month, f"{month}%"])
        if date_from:
            q += " AND a.date >= ?"
            params.append(date_from)
        if date_to:
            q += " AND a.date <= ?"
            params.append(date_to)
        if status and status != 'all':
            q += " AND a.status = ?"
            params.append(status)
        q += " ORDER BY a.date DESC"
        c.execute(q, params)
        return [dict(r) for r in c.fetchall()]

    def bulk_save_attendance(self, month, records):
        c = self._cur()
        for r in records:
            c.execute("""INSERT OR REPLACE INTO attendance (employee_id,date,check_in,check_out,status,note,month)
                VALUES (?,?,?,?,?,?,?)""",
                (r['employee_id'], r['date'], r.get('check_in',''), r.get('check_out',''),
                 r.get('status','present'), r.get('note',''), month))
        self.conn.commit()

    # ==================== LEAVES ====================
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

    # ==================== OVERTIME ====================
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

    # ==================== COMMISSIONS ====================
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

    # ==================== DEDUCTIONS ====================
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

    # ==================== ADVANCES ====================
    def get_advances(self, month=None):
        c = self._cur()
        q = """SELECT a.*, e.name as emp_name, e.emp_code
               FROM advances a JOIN employees e ON a.employee_id=e.id WHERE 1=1"""
        params = []
        if month:
            q += " AND substr(a.date,1,7)=?"
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

    # ==================== INCOME TAX ====================
    def calc_income_tax(self, annual_income, exempt=0):
        """حساب ضريبة كسب العمل حسب الشرائح على الدخل السنوي"""
        c = self._cur()
        c.execute("SELECT * FROM tax_brackets ORDER BY from_amount")
        brackets = [dict(r) for r in c.fetchall()]
        taxable = annual_income - exempt
        if taxable <= 0:
            return 0
        tax = 0
        # نستخدم طريقة الفرق - نحسب الضريبة مباشرة بناءً على الشريحة التي تقع فيها
        for i, b in enumerate(brackets):
            if taxable <= b['from_amount']:
                break
            upper = b['to_amount']
            if upper is None:
                upper = taxable
            if taxable <= (upper if upper else taxable):
                segment = taxable - b['from_amount'] if taxable > b['from_amount'] else 0
                # الضريبة للمبلغ في هذه الشريحة
                if b['fixed_deduction']:
                    tax = (taxable * b['rate']/100) - b['fixed_deduction']
                    break
                else:
                    tax = segment * b['rate']/100
                    break
        return max(0, round(tax, 2))

    # ==================== SETTINGS ====================
    def get_settings(self):
        c = self._cur()
        c.execute("SELECT * FROM settings LIMIT 1")
        r = c.fetchone()
        return dict(r) if r else {}

    def get_device_settings(self):
        """Get device connection settings."""
        settings = self.get_settings()
        return {
            'device_ip': settings.get('device_ip', ''),
            'device_port': int(settings.get('device_port', 4370)),
            'device_status': settings.get('device_status', 'disconnected'),
        }

    def save_device_settings(self, d):
        """Save device connection settings."""
        c = self._cur()
        device_ip = d.get('device_ip', '')
        device_port = d.get('device_port', 4370)
        device_status = d.get('device_status', 'disconnected')
        c.execute(
            "UPDATE settings SET device_ip=?, device_port=?, device_status=? WHERE id=1",
            (device_ip, device_port, device_status)
        )
        self.conn.commit()

    def get_employee_by_code(self, emp_code):
        """Get employee by emp_code."""
        c = self._cur()
        c.execute("SELECT * FROM employees WHERE emp_code=?", (emp_code,))
        r = c.fetchone()
        return dict(r) if r else None

    def get_employee_by_national_id(self, national_id):
        """Get employee by national_id."""
        c = self._cur()
        c.execute("SELECT * FROM employees WHERE national_id=?", (national_id,))
        r = c.fetchone()
        return dict(r) if r else None

    def get_attendance_detail(self, emp_id, date_str):
        """Check if attendance record exists for employee on date."""
        c = self._cur()
        c.execute(
            "SELECT * FROM attendance WHERE employee_id=? AND date=?",
            (emp_id, date_str)
        )
        r = c.fetchone()
        return dict(r) if r else None

    def get_attendance_from_device(self, month):
        """Get attendance data from ZKTeco device for the specified month."""
        import os
        import sys
        from datetime import datetime
        
        sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
        from zkteco_device import ZKDevice
        
        settings = self.get_device_settings()
        device_ip = settings.get('device_ip', '')
        device_port = settings.get('device_port', 4370)
        
        if not device_ip:
            return []
        
        device = ZKDevice(device_ip, device_port)
        
        if not device.connect():
            self.save_device_settings({
                'device_ip': device_ip,
                'device_port': device_port,
                'device_status': 'connection_failed'
            })
            return []
        
        try:
            attendance = device.get_attendance()
            
            # Save attendance to database
            for record in attendance:
                # Match device uid with employee emp_code or national_id
                emp = self.get_employee_by_code(record['uid']) or \
                      self.get_employee_by_national_id(record['uid'])
                
                if emp:
                    # Check if attendance record already exists for this month
                    existing = self.get_attendance_detail(emp['id'], record['date'])
                    if not existing:
                        self.bulk_save_attendance(month, [{
                            'employee_id': emp['id'],
                            'date': record['date'],
                            'check_in': record['time'],
                            'check_out': record['time'],
                            'status': 'present' if record['state'] == 0 else 'absent'
                        }])
            
            # Update status to connected
            self.save_device_settings({
                'device_ip': device_ip,
                'device_port': device_port,
                'device_status': 'connected'
            })
            
            return attendance
        except Exception as e:
            self.save_device_settings({
                'device_ip': device_ip,
                'device_port': device_port,
                'device_status': f'error: {str(e)}'
            })
            return []
        finally:
            device.disconnect()

    # ==================== DEVICE MANAGEMENT ====================
    def get_devices(self, active_only=True):
        c = self._cur()
        if active_only:
            c.execute("SELECT * FROM devices WHERE active=1 ORDER BY name")
        else:
            c.execute("SELECT * FROM devices ORDER BY name")
        return [dict(r) for r in c.fetchall()]

    def get_device(self, device_id):
        c = self._cur()
        c.execute("SELECT * FROM devices WHERE id=?", (device_id,))
        r = c.fetchone()
        return dict(r) if r else None

    def add_device(self, d):
        c = self._cur()
        c.execute("""INSERT INTO devices (name, device_type, ip_address, port, serial_number,
                     location, status, comm_key, notes, active)
            VALUES (?,?,?,?,?,?,?,?,?,?)""",
            (d.get('name',''), d.get('device_type','zkteco'), d.get('ip_address',''),
             int(d.get('port',4370)), d.get('serial_number',''), d.get('location',''),
             d.get('status','disconnected'), int(d.get('comm_key',0)), d.get('notes',''),
             int(d.get('active', 1))))
        self.conn.commit()
        return c.lastrowid

    def update_device(self, device_id, d):
        c = self._cur()
        c.execute("""UPDATE devices SET name=?, device_type=?, ip_address=?, port=?,
                     serial_number=?, location=?, status=?, comm_key=?, notes=?, active=?,
                     updated_at=CURRENT_TIMESTAMP WHERE id=?""",
            (d.get('name',''), d.get('device_type','zkteco'), d.get('ip_address',''),
             int(d.get('port',4370)), d.get('serial_number',''), d.get('location',''),
             d.get('status','disconnected'), int(d.get('comm_key',0)), d.get('notes',''),
             int(d.get('active', 1)), device_id))
        self.conn.commit()

    def delete_device(self, device_id):
        c = self._cur()
        c.execute("DELETE FROM devices WHERE id=?", (device_id,))
        self.conn.commit()

    def update_device_status(self, device_id, status, total_records=0):
        c = self._cur()
        c.execute("""UPDATE devices SET status=?, total_records=?, updated_at=CURRENT_TIMESTAMP,
            last_sync=CASE WHEN ?='connected' THEN CURRENT_TIMESTAMP ELSE last_sync END
            WHERE id=?""",
            (status, total_records, status, device_id))
        self.conn.commit()

    def add_device_log(self, device_id, action, description='', records_count=0, success=1, error_message=''):
        c = self._cur()
        c.execute("""INSERT INTO device_logs (device_id, action, description, records_count, success, error_message)
            VALUES (?,?,?,?,?,?)""",
            (device_id, action, description, records_count, success, error_message))
        self.conn.commit()
        return c.lastrowid

    def get_device_logs(self, device_id=None, action=None, success=None, limit=100):
        c = self._cur()
        q = """SELECT dl.*, d.name as device_name
               FROM device_logs dl JOIN devices d ON dl.device_id=d.id
               WHERE 1=1"""
        params = []
        if device_id:
            q += " AND dl.device_id=?"
            params.append(device_id)
        if action:
            q += " AND dl.action=?"
            params.append(action)
        if success is not None:
            q += " AND dl.success=?"
            params.append(success)
        q += " ORDER BY dl.created_at DESC LIMIT ?"
        params.append(limit)
        c.execute(q, params)
        return [dict(r) for r in c.fetchall()]


    # ==================== BIOMETRIC ATTENDANCE ====================
    def save_biometric_attendance(self, device_id, records):
        c = self._cur()
        count = 0
        for r in records:
            try:
                c.execute("""INSERT OR IGNORE INTO biometric_attendance
                    (device_id, device_uid, check_date, check_time, check_type, status, processed)
                    VALUES (?,?,?,?,?,?,0)""",
                    (device_id, r.get('uid',''), r.get('date',''), r.get('time',''),
                     r.get('check_type','check_in'), int(r.get('state',0))))
                if c.rowcount > 0:
                    count += 1
            except Exception:
                pass
        self.conn.commit()
        return count

    def get_biometric_attendance(self, device_id=None, processed=None, date_from=None, date_to=None, limit=500):
        c = self._cur()
        q = """SELECT ba.*, e.name as emp_name, e.emp_code, d.name as device_name
               FROM biometric_attendance ba
               LEFT JOIN employees e ON ba.employee_id=e.id
               LEFT JOIN devices d ON ba.device_id=d.id
               WHERE 1=1"""
        params = []
        if device_id:
            q += " AND ba.device_id=?"
            params.append(device_id)
        if processed is not None:
            q += " AND ba.processed=?"
            params.append(processed)
        if date_from:
            q += " AND ba.check_date>=?"
            params.append(date_from)
        if date_to:
            q += " AND ba.check_date<=?"
            params.append(date_to)
        q += " ORDER BY ba.check_date DESC, ba.check_time DESC LIMIT ?"
        params.append(limit)
        c.execute(q, params)
        return [dict(r) for r in c.fetchall()]

    def get_unprocessed_attendance_count(self, device_id=None):
        c = self._cur()
        if device_id:
            c.execute("SELECT COUNT(*) FROM biometric_attendance WHERE device_id=? AND processed=0", (device_id,))
        else:
            c.execute("SELECT COUNT(*) FROM biometric_attendance WHERE processed=0")
        return c.fetchone()[0]

    def mark_attendance_processed(self, attendance_ids, employee_id=None):
        c = self._cur()
        if isinstance(attendance_ids, int):
            attendance_ids = [attendance_ids]
        for aid in attendance_ids:
            if employee_id:
                c.execute("UPDATE biometric_attendance SET processed=1, employee_id=? WHERE id=?", (employee_id, aid))
            else:
                c.execute("UPDATE biometric_attendance SET processed=1 WHERE id=?", (aid,))
        self.conn.commit()

    def map_device_employee(self, device_id, device_uid, employee_id):
        c = self._cur()
        c.execute("""INSERT OR REPLACE INTO device_employee_mapping (device_id, device_uid, employee_id)
            VALUES (?,?,?)""",
            (device_id, device_uid, employee_id))
        self.conn.commit()

    def get_device_employees(self, device_id):
        c = self._cur()
        c.execute("""SELECT dem.*, e.name as emp_name, e.emp_code
            FROM device_employee_mapping dem
            JOIN employees e ON dem.employee_id=e.id
            WHERE dem.device_id=?
            ORDER BY e.name""", (device_id,))
        return [dict(r) for r in c.fetchall()]

    def get_device_employees_extended(self, device_id):
        """Like get_device_employees but includes attendance count and dept."""
        c = self._cur()
        c.execute("""
            SELECT dem.device_uid, dem.mapped_at,
                   e.name as emp_name, e.emp_code, e.id as emp_id, e.id as employee_id,
                   d.name as dept_name,
                   COUNT(ba.id) as att_count
            FROM device_employee_mapping dem
            JOIN employees e ON dem.employee_id=e.id
            LEFT JOIN departments d ON e.department_id=d.id
            LEFT JOIN biometric_attendance ba
                   ON ba.device_id=dem.device_id AND ba.device_uid=dem.device_uid
            WHERE dem.device_id=?
            GROUP BY dem.device_uid
            ORDER BY e.name""", (device_id,))
        return [dict(r) for r in c.fetchall()]

    def get_unmapped_device_uids(self, device_id):
        """Return UIDs that have attendance records but no employee mapping."""
        c = self._cur()
        c.execute("""
            SELECT ba.device_uid,
                   COUNT(ba.id) as records_count,
                   MAX(ba.check_date || ' ' || ba.check_time) as last_seen
            FROM biometric_attendance ba
            WHERE ba.device_id=?
              AND ba.device_uid NOT IN (
                  SELECT device_uid FROM device_employee_mapping WHERE device_id=?
              )
            GROUP BY ba.device_uid
            ORDER BY records_count DESC""", (device_id, device_id))
        return [dict(r) for r in c.fetchall()]

    def unmap_device_employee(self, device_id, device_uid):
        c = self._cur()
        c.execute("DELETE FROM device_employee_mapping WHERE device_id=? AND device_uid=?",
                  (device_id, device_uid))
        self.conn.commit()

    def get_biometric_attendance_count(self, device_id=None, date=None):
        """Count biometric attendance records."""
        c = self._cur()
        q = "SELECT COUNT(*) FROM biometric_attendance WHERE 1=1"
        params = []
        if device_id:
            q += " AND device_id=?"
            params.append(device_id)
        if date:
            q += " AND check_date=?"
            params.append(date)
        c.execute(q, params)
        return c.fetchone()[0]

    def bulk_process_biometric_attendance(self, device_id):
        """Mark pending records as processed=1 for mapped employees."""
        c = self._cur()
        c.execute("""
            UPDATE biometric_attendance SET processed=1,
                employee_id=(
                    SELECT dem.employee_id FROM device_employee_mapping dem
                    WHERE dem.device_id=biometric_attendance.device_id
                      AND dem.device_uid=biometric_attendance.device_uid
                )
            WHERE device_id=? AND processed=0
              AND device_uid IN (
                  SELECT device_uid FROM device_employee_mapping WHERE device_id=?
              )""", (device_id, device_id))
        processed = c.rowcount
        self.conn.commit()
        return {'processed': processed}

    def link_pending_biometric_records(self, device_id, device_uid, employee_id):
        """Mark all pending records for a specific UID as processed and linked."""
        c = self._cur()
        c.execute("""UPDATE biometric_attendance
                     SET processed=1, employee_id=?
                     WHERE device_id=? AND device_uid=? AND processed=0""",
                  (employee_id, device_id, device_uid))
        self.conn.commit()
        return c.rowcount

    def get_employee_by_device_uid(self, device_id, device_uid):
        c = self._cur()
        c.execute("""SELECT e.* FROM device_employee_mapping dem
            JOIN employees e ON dem.employee_id=e.id
            WHERE dem.device_id=? AND dem.device_uid=?""", (device_id, device_uid))
        r = c.fetchone()
        return dict(r) if r else None

    def find_candidate_employee_for_uid(self, uid):
        """Intelligently match a device UID to an existing employee."""
        if not uid:
            return None
        # 1. Exact emp_code match
        emp = self.get_employee_by_code(str(uid).strip())
        if emp:
            return emp
        # 2. Try integer-based matches (id, or EMP001 / EMP01 / EMP1)
        try:
            val = int(str(uid).strip())
            # Try formatted codes
            for pattern in [f"EMP{val:03d}", f"EMP{val:02d}", f"EMP{val}"]:
                emp = self.get_employee_by_code(pattern)
                if emp:
                    return emp
            # Try employee id
            emp = self.get_employee(val)
            if emp:
                return emp
        except (ValueError, TypeError):
            pass
        return None

    def apply_biometric_attendance_to_payroll(self, device_id, month=None, overwrite=False):
        if not month:
            month = datetime.now().strftime('%Y-%m')

        c = self._cur()
        # Find distinct employee + check_date pairs for this device and month
        c.execute("""SELECT DISTINCT dem.employee_id, ba.check_date
            FROM biometric_attendance ba
            JOIN device_employee_mapping dem ON ba.device_id=dem.device_id AND ba.device_uid=dem.device_uid
            WHERE ba.device_id=? AND ba.processed=1 AND substr(ba.check_date,1,7)=?
            ORDER BY dem.employee_id, ba.check_date""",
            (device_id, month))

        pairs = c.fetchall()
        applied_count = 0
        skipped_count = 0

        for p in pairs:
            emp_id = p['employee_id']
            check_date = p['check_date']

            c.execute("SELECT * FROM attendance WHERE employee_id=? AND date=?",
                      (emp_id, check_date))
            existing = c.fetchone()

            # Find all punches for this specific employee on this date
            c.execute("""SELECT ba.check_time
                FROM biometric_attendance ba
                JOIN device_employee_mapping dem ON ba.device_id=dem.device_id AND ba.device_uid=dem.device_uid
                WHERE ba.device_id=? AND dem.employee_id=? AND ba.processed=1 AND ba.check_date=?
                ORDER BY ba.check_time ASC""",
                (device_id, emp_id, check_date))
            day_records = c.fetchall()

            check_in = ''
            check_out = ''
            status = 'present'

            if day_records:
                check_in = day_records[0]['check_time']
                if len(day_records) > 1:
                    check_out = day_records[-1]['check_time']
                if check_in > '09:00':
                    status = 'late'

            if existing:
                if overwrite:
                    c.execute("""UPDATE attendance SET check_in=?, check_out=?, status=?, source='device'
                        WHERE id=?""",
                        (check_in, check_out, status, existing['id']))
                    applied_count += 1
                else:
                    skipped_count += 1
            else:
                c.execute("""INSERT INTO attendance (employee_id, date, check_in, check_out, status, note, month, source)
                    VALUES (?,?,?,?,?,?,?,?)""",
                    (emp_id, check_date, check_in, check_out, status, '', month, 'device'))
                applied_count += 1

        self.conn.commit()

        # Update biometric_attendance to status 2 (applied)
        c.execute("""UPDATE biometric_attendance SET processed=2
            WHERE device_id=? AND processed=1 AND substr(check_date,1,7)=?
            AND device_uid IN (SELECT device_uid FROM device_employee_mapping WHERE device_id=?)""",
            (device_id, month, device_id))
        self.conn.commit()

        return {'applied': applied_count, 'skipped': skipped_count}

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

    # ==================== FPS / GPS (FACE RECOGNITION & LOCATION) ====================
    def get_fps_settings(self):
        settings = self.get_settings()
        return {
            'fps_enabled': settings.get('fps_enabled', 0),
            'fps_threshold': settings.get('fps_threshold', 0.6),
            'fps_min_confidence': settings.get('fps_min_confidence', 0.7),
            'gps_enabled': settings.get('gps_enabled', 0),
            'gps_required': settings.get('gps_required', 0),
            'gps_tolerance_meters': settings.get('gps_tolerance_meters', 50),
            'gps_verify': settings.get('gps_verify', 0),
            'gps_delay_minutes': settings.get('gps_delay_minutes', 0),
            'location_required': settings.get('location_required', 0),
            'verify_location': settings.get('verify_location', 0),
            'distance_tolerance': settings.get('distance_tolerance', 50),
            'force_location_check': settings.get('force_location_check', 0),
            'ip_whitelist': settings.get('ip_whitelist', ''),
            'company_lat': settings.get('company_lat', ''),
            'company_lng': settings.get('company_lng', ''),
            'login_method': settings.get('login_method', 'username'),
            'login_status': settings.get('login_status', 'active'),
            'mobile_login_enabled': settings.get('mobile_login_enabled', 0),
            'mobile_login_type': settings.get('mobile_login_type', 'face'),
            'mobile_return_login': settings.get('mobile_return_login', 0),
        }

    def save_fps_settings(self, d):
        """Save FPS (Face Recognition) and GPS settings."""
        current = self.get_settings()
        def get_val(key, default):
            return d[key] if key in d else current.get(key, default)
        def get_bool(key, default=0):
            if key in d:
                return 1 if str(d[key]).lower() in ('1', 'on', 'true', 'yes') else 0
            return 1 if str(current.get(key, default)).lower() in ('1', 'on', 'true', 'yes') else 0

        c = self._cur()
        c.execute("""
            UPDATE settings SET
            fps_enabled=?, fps_threshold=?, fps_min_confidence=?,
            gps_enabled=?, gps_required=?, gps_tolerance_meters=?,
            gps_verify=?, gps_delay_minutes=?, location_required=?,
            verify_location=?, distance_tolerance=?, force_location_check=?,
            ip_whitelist=?, company_lat=?, company_lng=?,
            login_method=?, login_status=?, mobile_login_enabled=?,
            mobile_login_type=?, mobile_return_login=?
            WHERE id=1""",
            (
                get_bool('fps_enabled', 0),
                float(get_val('fps_threshold', 0.6) or 0.6),
                float(get_val('fps_min_confidence', 0.7) or 0.7),
                get_bool('gps_enabled', 0),
                get_bool('gps_required', 0),
                float(get_val('gps_tolerance_meters', 50) or 50),
                get_bool('gps_verify', 0),
                int(get_val('gps_delay_minutes', 0) or 0),
                get_bool('location_required', 0),
                get_bool('verify_location', 0),
                float(get_val('distance_tolerance', 50) or 50),
                get_bool('force_location_check', 0),
                get_val('ip_whitelist', ''),
                get_val('company_lat', ''),
                get_val('company_lng', ''),
                get_val('login_method', 'username'),
                get_val('login_status', 'active'),
                get_bool('mobile_login_enabled', 0),
                get_val('mobile_login_type', 'face'),
                get_bool('mobile_return_login', 0),
            )
        )
        self.conn.commit()

    def calculate_distance(self, lat1, lon1, lat2, lon2):
        """Calculate distance between two GPS coordinates in meters (Haversine formula)."""
        import math
        R = 6371000  # Earth radius in meters
        lat1_rad = math.radians(lat1)
        lat2_rad = math.radians(lat2)
        delta_lat = math.radians(lat2 - lat1)
        delta_lon = math.radians(lon2 - lon1)
        a = math.sin(delta_lat / 2) ** 2 + math.cos(lat1_rad) * math.cos(lat2_rad) * math.sin(delta_lon / 2) ** 2
        c = 2 * math.atan2(math.sqrt(a), math.sqrt(1 - a))
        return R * c

    def update_employee_face(self, emp_id, face_data):
        """Update or register employee face data."""
        c = self._cur()
        c.execute("UPDATE employees SET face_data=? WHERE id=?", (face_data, emp_id))
        self.conn.commit()

    def delete_employee_face(self, emp_id):
        """Remove employee face data."""
        c = self._cur()
        c.execute("UPDATE employees SET face_data=NULL WHERE id=?", (emp_id,))
        self.conn.commit()

    def get_employee_by_face_data(self, face_data):
        """Get employee by face data (for face recognition login)."""
        c = self._cur()
        c.execute("SELECT * FROM employees WHERE face_data=? LIMIT 1", (face_data,))
        r = c.fetchone()
        return dict(r) if r else None

    # ==================== BACKUP / RESTORE ====================
    def create_backup(self):
        """إنشاء نسخة احتياطية من قاعدة البيانات عبر SQLite online-backup API."""
        import shutil
        try:
            self.conn.commit()
            self.conn.execute("PRAGMA wal_checkpoint(FULL)")
        except Exception:
            pass
        backups_dir = os.path.join(os.path.dirname(DB_PATH), 'backups')
        os.makedirs(backups_dir, exist_ok=True)
        stamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        dest = os.path.join(backups_dir, f'backup_{stamp}.db')
        src = DB_PATH
        try:
            shutil.copy2(src, dest)
        except Exception:
            # بديل: نسخ عبر SQLite backup API
            bconn = sqlite3.connect(dest)
            self.conn.backup(bconn)
            bconn.close()
        # تسجيل آخر نسخة احتياطية في الإعدادات
        now = datetime.now().strftime('%Y-%m-%d %H:%M')
        c = self._cur()
        c.execute("UPDATE settings SET last_backup=? WHERE id=1", (now,))
        self.conn.commit()
        return dest, now

    def list_backups(self):
        backups_dir = os.path.join(os.path.dirname(DB_PATH), 'backups')
        if not os.path.isdir(backups_dir):
            return []
        out = []
        for f in sorted(os.listdir(backups_dir), reverse=True):
            if f.startswith('backup_') and f.endswith('.db'):
                p = os.path.join(backups_dir, f)
                out.append({'filename': f, 'path': p,
                            'size': os.path.getsize(p),
                            'created': datetime.fromtimestamp(os.path.getmtime(p)).strftime('%Y-%m-%d %H:%M')})
        return out

    def delete_backup(self, filename):
        backups_dir = os.path.join(os.path.dirname(DB_PATH), 'backups')
        p = os.path.join(backups_dir, filename)
        if os.path.isfile(p) and filename.startswith('backup_') and filename.endswith('.db'):
            os.remove(p)
            return True
        return False

    def restore_backup(self, filename):
        """استعادة نسخة احتياطية: تنسخ الملف فوق قاعدة البيانات الحالية."""
        backups_dir = os.path.join(os.path.dirname(DB_PATH), 'backups')
        p = os.path.join(backups_dir, filename)
        if not (os.path.isfile(p) and filename.startswith('backup_') and filename.endswith('.db')):
            raise ValueError('ملف نسخة احتياطية غير صالح')
        self.conn.commit()
        try:
            self.conn.close()
        except Exception:
            pass
        import shutil
        shutil.copy2(p, DB_PATH)
        # إعادة فتح الاتصال
        self.conn = sqlite3.connect(DB_PATH, check_same_thread=False, timeout=30)
        self.conn.row_factory = sqlite3.Row
        self.conn.execute("PRAGMA foreign_keys = ON")
        self.conn.execute("PRAGMA journal_mode = WAL")
        return True

    def run_auto_backup_if_due(self):
        """نسخة احتياطية تلقائية شهرية (مقارنة بالشهر الحالي)."""
        sett = self.get_settings()
        last = (sett.get('last_backup') or '')
        if not last.startswith(datetime.now().strftime('%Y-%m')):
            try:
                self.create_backup()
                return True
            except Exception:
                return False
        return False

    # ==================== AUTH HELPERS ====================
    def mark_password_changed(self):
        c = self._cur()
        c.execute("UPDATE settings SET admin_password_changed=1 WHERE id=1")
        self.conn.commit()

    def admin_must_change_password(self, user):
        """إلزام مدير النظام الأولي بتغيير كلمة المرور الافتراضية."""
        if not user or user.get('role') != 'admin':
            return False
        sett = self.get_settings()
        return not bool(sett.get('admin_password_changed'))

    def get_tax_brackets(self):
        c = self._cur()
        c.execute("SELECT * FROM tax_brackets ORDER BY from_amount")
        return [dict(r) for r in c.fetchall()]

    # ==================== PAYROLL ====================
    def _weekly_holiday_weekdays(self, settings):
        """أرقام الإجازة الأسبوعية بأرقام بايثون (0=الاثنين ... 6=الأحد).

        الإعداد محفوظ بالشكل: 0=السبت ... 6=الجمعة (الافتراضي '6' = الجمعة).
        يقبل أكثر من يوم مفصولة بفاصلة، مثال: '5,6'.
        """
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
        """عدد أيام العمل الفعلية في الشهر (بعد استثناء الإجازة الأسبوعية).

        - تُستثنى أيام الإجازة الأسبوعية المضبوطة في الإعدادات.
        - في الشهر الحالي تُحتسب الأيام المنقضية فقط حتى تاريخ اليوم (كي لا تُحسب
          أيام لم تأتِ بعد كغياب).
        """
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
        """تواريخ (YYYY-MM-DD) للإجازات المعتمدة للموظف داخل الشهر المحدد."""
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
        """حساب المرتبات الشامل لكافة الموظفين النشطين"""
        settings = self.get_settings()
        c = self._cur()
        employees = self.get_employees(status='active')

        # احصل على أيام عمل الشهر (عدا الإجازات الأسبوعية)
        monthly_days = settings['working_days_monthly']
        # أيام العمل الفعلية بالشهر (تُستعمل لاحتساب أيام عدم التسجيل كغياب)
        payable_days = self.get_working_days(month, settings)
        count_missing = self._setting_on(settings, 'count_missing_as_absent')

        results = []
        for emp in employees:
            emp_id = emp['id']

            # 1) الأساسي حسب نوع الأجر
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
            else:  # commission
                daily = 0
                hourly = 0
                base = 0

            # 2) البدلات
            allowances = (emp['housing_allowance'] + emp['transport_allowance'] + emp['food_allowance'] +
                          emp['other_allowances'] + emp['danger_allowance'] + emp['phone_allowance'])

            # 3) الحضور - أيام العمل والغياب والتأخير
            c.execute("SELECT * FROM attendance WHERE employee_id=? AND month=?", (emp_id, month))
            att_records = [dict(r) for r in c.fetchall()]
            present_days = sum(1 for a in att_records if a['status'] in ('present','late'))
            late_days = sum(1 for a in att_records if a['status'] == 'late')
            sick_days = sum(1 for a in att_records if a['status'] == 'sick')
            leave_days = sum(1 for a in att_records if a['status'] == 'leave')

            # الغياب = الأيام المسجّلة غياباً + الأيام التي لا يوجد لها سجل حضور
            # (لا يُحتسب اليوم في المرتب إلا بوجود سجل: حاضر/متأخر/إجازة/مرضي أو إجازة معتمدة)
            absent_dates = {a['date'] for a in att_records if a['status'] == 'absent'}
            recorded_dates = {a['date'] for a in att_records if a['status'] in ('present','late','leave','sick')}
            absent_days = len(absent_dates)
            missing_days = 0
            if count_missing:
                known_dates = recorded_dates | (self.get_approved_leave_dates(emp_id, month) - absent_dates)
                missing_days = max(0, int(payable_days) - (len(known_dates) + absent_days))
                absent_days += missing_days

            # 4) الإضافي
            c.execute("""SELECT COALESCE(SUM(hours),0) as hrs, COALESCE(SUM(amount),0) as amt
                         FROM overtime WHERE employee_id=? AND month=?""", (emp_id, month))
            ot = dict(c.fetchone())
            overtime_amt = ot['amt']

            # 5) العمولات
            c.execute("""SELECT COALESCE(SUM(amount),0) as amt FROM commissions WHERE employee_id=? AND month=?""", (emp_id, month))
            commissions = float(c.fetchone()['amt'])

            # 6) المستحقات
            base_allowances = base + allowances
            gross = base_allowances + overtime_amt + commissions

            # 7) التأمينات الاجتماعية
            si_employee = 0
            si_employer = 0
            if emp['social_insurance_enabled']:
                ins_floor = settings['insurance_floor']
                ins_ceiling = settings['insurance_ceiling']
                ins_base = min(max(base, ins_floor), ins_ceiling) if ins_ceiling else max(base, ins_floor)
                emp_ratio = emp['social_insurance_employee_ratio'] if emp['social_insurance_employee_ratio'] else settings['insurance_employee_ratio']
                empl_ratio = emp['social_insurance_employer_ratio'] if emp['social_insurance_employer_ratio'] else settings['insurance_employer_ratio']
                si_employee = ins_base * emp_ratio / 100
                si_employer = ins_base * empl_ratio / 100

            # 8) ضريبة كسب العمل (على الدخل السنوي)
            income_tax = 0
            if emp['income_tax_enabled']:
                annual = gross * 12
                exempt = emp['tax_exempt_amount'] if emp['tax_exempt_amount'] else settings['tax_exempt_default']
                income_tax = self.calc_income_tax(annual, exempt)

            # 9) سلف (القسط المستحق هذا الشهر — يستمر في الأشهر التالية حتى اكتمال السلفة)
            advance_installments = 0.0
            c.execute("""SELECT installment_amount, installment_count, current_installment, remaining, date
                         FROM advances WHERE employee_id=? AND status='active'""", (emp_id,))
            for adv in c.fetchall():
                start_month = (adv['date'] or '')[:7]
                if not start_month or start_month > month:
                    continue  # لم يبدأ جدول السلفة بعد
                if int(adv['current_installment'] or 0) >= int(adv['installment_count'] or 0):
                    continue  # اكتملت أقساطها
                adv_remaining = float(adv['remaining'] or 0)
                if adv_remaining <= 0:
                    continue
                # القسط لا يتجاوز المتبقي (القسط الأخير يُصفّر المتبقي)
                advance_installments += min(float(adv['installment_amount'] or 0), adv_remaining)

            # 10) خصومات الغياب
            absence_deduction = absent_days * daily * (settings['absence_deduction_percent']/100)
            # خصم اليوم الكامل للإجازة بدون أجر
            c.execute("""SELECT COALESCE(SUM(days),0) as d FROM leave_requests
                         WHERE employee_id=? AND leave_type='unpaid' AND status='approved' AND substr(start_date,1,7)=?""", (emp_id, month))
            unpaid_days = float(c.fetchone()['d'])
            absence_deduction += unpaid_days * daily

            # خصم التأخير
            late_deduction = late_days * settings['late_deduction_per_hour'] * settings['working_hours_daily']

            # 11) خصومات يدوية (جزاءات، قروض...)
            c.execute("""SELECT COALESCE(SUM(amount),0) as amt FROM deductions WHERE employee_id=? AND month=?""", (emp_id, month))
            other_deductions = float(c.fetchone()['amt'])
            manual_earnings = 0

            # 12) حوافز/خصومات جماعية
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
        # موظفو هذا الشهر الذين تأكّد كشفهم الآن (من مسودة إلى معتمد)
        c.execute("SELECT employee_id FROM payroll_proof WHERE month=? AND status='draft'", (month,))
        draft_ids = [r['employee_id'] for r in c.fetchall()]
        c.execute("SELECT COUNT(*) AS n FROM payroll_proof WHERE month=?", (month,))
        has_saved = int(c.fetchone()['n']) > 0
        c.execute("UPDATE payroll_proof SET status='confirmed' WHERE month=?", (month,))

        # تقدم أقساط السلف: قسط واحد لكل سلفة مستحقة في هذا الشهر — يستمر في الأشهر
        # التالية حتى الاكتمال مع تحديث المتبقي والحالة. لا تقدم إن لم تكن هناك مسودة
        # جديدة (يعيد الاعتماد) أو لم يُحفظ كشف لهذا الشهر إطلاقاً.
        if has_saved and draft_ids:
            ph = ','.join('?' * len(draft_ids))
            c.execute(f"""SELECT id, installment_amount, installment_count, current_installment, remaining
                          FROM advances
                          WHERE status='active' AND substr(date,1,7) <= ?
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
            # القسط الأخير يصفّر المتبقي (يمنع بقايا كسور تقريب)
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

    # ==================== DASHBOARD ====================
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

    # ==================== AUDIT LOG ====================
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
            c.execute("SELECT * FROM audit_log WHERE substr(created_at,1,10)=? ORDER BY created_at DESC, id DESC LIMIT ?", (day, limit))
        else:
            c.execute("SELECT * FROM audit_log ORDER BY created_at DESC, id DESC LIMIT ?", (limit,))
        return [dict(r) for r in c.fetchall()]

    # ==================== CONTRACTS ====================
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
               AND date(co.end_date) BETWEEN date('now','localtime') AND date('now','localtime', ?)
               ORDER BY co.end_date"""
        c.execute(q, (f'+{days} days',))
        return [dict(r) for r in c.fetchall()]

    def delete_contract(self, cid):
        c = self._cur()
        c.execute("DELETE FROM contracts WHERE id=?", (cid,))
        self.conn.commit()

    # ==================== PAYROLL SIGNATURES ====================
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

    # ==================== BULK INCENTIVES ====================
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

    # ==================== DASHBOARD EXTRAS ====================
    def get_pay_type_distribution(self):
        c = self._cur()
        c.execute("""SELECT pay_type as type, COUNT(*) cnt, COALESCE(SUM(base_salary),0) base
                     FROM employees WHERE status='active' GROUP BY pay_type""")
        return [dict(r) for r in c.fetchall()]

    def get_monthly_budget(self, month):
        c = self._cur()
        data = self.calculate_payroll(month)
        return {
            'net': round(sum(r['net'] for r in data), 2),
            'gross': round(sum(r['gross'] for r in data), 2),
            'deductions': round(sum(r['total_deductions'] for r in data), 2),
            'count': len(data),
            'si_employer': round(sum(r['si_employer'] for r in data), 2),
        }

    # دالة مساعدة للتحقق من الحوافز الجماعية (تُستدعى بعد الحفظ)
    def apply_bulk_to_payroll(self, month):
        return True
