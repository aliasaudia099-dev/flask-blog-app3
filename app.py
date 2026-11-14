from flask import Flask, render_template, request, redirect, url_for, flash, jsonify, session, send_file, abort
from database import Database
from functools import wraps
import os, io, re, json, hashlib, secrets, time, threading, webbrowser, base64
from PIL import Image as PILImage
from datetime import datetime, date, timedelta
import calendar
from openpyxl import Workbook
from openpyxl.styles import Font, Alignment, PatternFill, Border, Side
from openpyxl.utils import get_column_letter

import sys
import license as lic

# ------------------------------------------------------------
#  إعداد المفتاح السرّي بشكل ثابت (لا يتغير مع كل تشغيل)
# ------------------------------------------------------------
def _get_secret_key():
    # 1) من متغير البيئة
    env = os.environ.get('PAYROLL_SECRET_KEY')
    if env:
        return env
    # تحديد المجلد الأساسي: بجوار الـ exe في وضع PyInstaller، أو بجانب app.py
    if getattr(sys, 'frozen', False):
        base_dir = os.path.dirname(sys.executable)
    else:
        base_dir = os.path.dirname(os.path.abspath(__file__))
    keyfile = os.path.join(base_dir, '.secret_key')
    # 2) من ملف سري - أول شركة
    if os.path.exists(keyfile):
        with open(keyfile, 'r', encoding='utf-8') as f:
            v = f.read().strip()
            if v:
                return v
    # 3) إنشاء وتخزين
    v = secrets.token_hex(32)
    try:
        with open(keyfile, 'w', encoding='utf-8') as f:
            f.write(v)
    except Exception:
        pass
    return v

app = Flask(__name__)
app.secret_key = _get_secret_key()
app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE='Lax',
    # فُعّل HTTPS (SESSION_COOKIE_SECURE=True) عبر متغير البيئة PAYROLL_HTTPS=1 عند النشر الخارجي
    SESSION_COOKIE_SECURE=(os.environ.get('PAYROLL_HTTPS') == '1'),
    MAX_CONTENT_LENGTH=16 * 1024 * 1024,
)

# ==================== LICENSE CHECK (فحص الترخيص عند الإقلاع) ====================
# يُفحص الترخيص مرة واحدة عند التشغيل، وأي تعديل على license.key أو المفتاح يتطلب إعادة التشغيل.
# أثناء التطوير يمكن تجاوز الفحص: PAYROLL_LICENSE_CHECK=0 python app.py
_LICENSE_ENABLED = os.environ.get('PAYROLL_LICENSE_CHECK', '1') != '0'
if _LICENSE_ENABLED:
    LICENSE_OK, LICENSE_MSG, LICENSE_INFO = lic.license_summary()
else:
    LICENSE_OK, LICENSE_MSG, LICENSE_INFO = True, 'تم تجاوز فحص الترخيص (وضع التطوير)', {}

db = Database()

# ملاحظة: مجلد القوالب والاستاتيك ضمن التطبيق (مجلد التحميل المؤقت في وضع الـ exe)
if getattr(sys, 'frozen', False):
    BASE_DIR = sys._MEIPASS
    DATA_DIR = os.path.dirname(sys.executable)
else:
    BASE_DIR = os.path.dirname(os.path.abspath(__file__))
    DATA_DIR = os.path.dirname(os.path.abspath(__file__))

# ==================== HELPERS / SECURITY ====================

# تخزين مقيد للجلسة لمنع كسر التصعيد
@app.before_request
def before_request():
    # فحص الترخيص: تقفل كل الصفحات عند عدم وجود ترخيص صالح (ما عدا صفحة الترخيص والملفات الثابتة)
    if not LICENSE_OK and request.endpoint not in ('static', 'license_page', 'logout'):
        return redirect(url_for('license_page'))
    db._uid = session.get('user_id')
    db._uname = session.get('username','')
    db._ip = request.remote_addr or ''
    # إلزام المدير بتغيير كلمة المرور الافتراضية قبل استخدام باقي النظام
    if 'user_id' in session and request.endpoint not in ('static','logout','change_password','password_page'):
        u = db.get_user_by_id(session['user_id'])
        if u and db.admin_must_change_password(u):
            return redirect(url_for('password_page'))
    # نسخة احتياطية تلقائية شهرية (مرة كل شهر)
    if session.get('role') == 'admin':
        db.run_auto_backup_if_due()

@app.after_request
def security_headers(resp):
    resp.headers['X-Content-Type-Options'] = 'nosniff'
    resp.headers['X-Frame-Options'] = 'SAMEORIGIN'
    resp.headers['X-XSS-Protection'] = '1; mode=block'
    resp.headers['Referrer-Policy'] = 'same-origin'
    # منع التخزين المؤقت للكشوفات ودخول السجلات الحساسة
    if request.endpoint in ('payslip','reports','reports_pdf','payroll_pdf','dept_report','annual_report','login',
                            'comparison','signatures_log','audit','employees','contracts'):
        resp.headers['Cache-Control'] = 'no-store, no-cache, must-revalidate, max-age=0'
        resp.headers['Pragma'] = 'no-cache'
    return resp

def login_required(f):
    @wraps(f)
    def wrapper(*a, **kw):
        if 'user_id' not in session:
            flash('يجب تسجيل الدخول أولاً', 'error')
            return redirect(url_for('login'))
        return f(*a, **kw)
    return wrapper

# تسلسل الصلاحيات: admin > supervisor > user > viewer
_ROLE_LEVEL = {'admin': 4, 'supervisor': 3, 'user': 2, 'viewer': 1}

def role_required(min_role):
    """حماية مسار بناءً على الحد الأدنى للصلاحية."""
    def decorator(f):
        @wraps(f)
        def wrapper(*a, **kw):
            if 'user_id' not in session:
                flash('يجب تسجيل الدخول أولاً', 'error')
                return redirect(url_for('login'))
            user = db.get_user_by_id(session['user_id'])
            user_level = _ROLE_LEVEL.get(user.get('role',''), 0) if user else 0
            if user_level < _ROLE_LEVEL.get(min_role, 99):
                flash('ليس لديك صلاحية كافية للوصول', 'error')
                return redirect(url_for('dashboard'))
            return f(*a, **kw)
        return wrapper
    return decorator

def admin_required(f):
    @wraps(f)
    def wrapper(*a, **kw):
        if 'user_id' not in session:
            return redirect(url_for('login'))
        user = db.get_user_by_id(session['user_id'])
        if not user or user['role'] != 'admin':
            flash('ليس لديك صلاحية للوصول', 'error')
            return redirect(url_for('dashboard'))
        return f(*a, **kw)
    return wrapper

# ==================== CSRF protection ====================
def csrf_token():
    if 'csrf' not in session:
        session['csrf'] = secrets.token_hex(32)
    return session['csrf']

def csrf_required(f):
    @wraps(f)
    def wrapper(*a, **kw):
        if request.method == 'POST':
            token = request.form.get('_csrf') or (request.get_json(silent=True) or {}).get('_csrf') or ''
            if not token or token != session.get('csrf'):
                abort(400, 'انتهت صلاحية الجلسة (CSRF)')
        return f(*a, **kw)
    return wrapper

@app.context_processor
def inject_globals():
    user = None
    if 'user_id' in session:
        user = db.get_user_by_id(session['user_id'])
    settings = db.get_settings()
    # تنبيهات العقود المنتهية قريباً (للمسؤول)
    expiring = db.get_expiring_contracts(30) if session.get('role') == 'admin' else []
    return dict(current_user=user, sys_settings=settings, today=date.today().isoformat(),
                current_month=datetime.now().strftime('%Y-%m'),
                csrf_token=csrf_token, expiring_contracts=expiring)

def month_range(month):
    y, m = int(month[:4]), int(month[5:7])
    return calendar.monthrange(y, m)[1]

def _t(template, **kw):
    kw['csrf_token'] = csrf_token()
    return render_template(template, **kw)

# ==================== AUTH ====================
# محاولات تسجيل دخول فاشلة بسيطة لمنع التخمين
_login_attempts = {}

@app.route('/login', methods=['GET','POST'])
def login():
    if 'user_id' in session:
        return redirect(url_for('dashboard'))
    if request.method == 'POST':
        username = (request.form.get('username') or '').strip()
        password = request.form.get('password') or ''
        ip = request.remote_addr or ''
        # حدّ من المحاولات
        now = datetime.now()
        for k in list(_login_attempts.keys()):
            if now - _login_attempts[k] > timedelta(minutes=15):
                del _login_attempts[k]
        key = f"{ip}|{username}"
        if _login_attempts.get(key, now - timedelta(minutes=15)) > now - timedelta(minutes=1):
            flash('محاولات كثيرة، انتظر قليلاً ثم حاول مرة أخرى', 'error')
            return render_template('login.html', csrf_token=csrf_token())
        user = db.authenticate(username, password)
        if user and user['active']:
            session.clear()
            session['user_id'] = user['id']
            session['username'] = user['username']
            session['role'] = user['role']
            session['csrf'] = secrets.token_hex(32)
            db._uid = user['id']; db._uname = user['username']; db._ip = ip
            db.log_audit('login', 'user', user['id'], f'تسجيل دخول ناجح')
            # إلزام المدير الأولي بتغيير كلمة المرور الافتراضية
            if db.admin_must_change_password(user):
                flash('يجب تغيير كلمة المرور الافتراضية لأسباب أمنية', 'warning')
                return redirect(url_for('password_page'))
            return redirect(url_for('dashboard'))
        _login_attempts[key] = now
        db.log_audit('login_failed', 'user', None, f'محاولة دخول فاشلة: {username} من {ip}')
        flash('بيانات الدخول غير صحيحة', 'error')
    return render_template('login.html', csrf_token=csrf_token())

@app.route('/logout')
def logout():
    if 'user_id' in session:
        db._uid = session.get('user_id'); db._uname = session.get('username','')
        db.log_audit('logout', 'user', session.get('user_id'), 'تسجيل خروج')
    session.clear()
    return redirect(url_for('login'))

@app.route('/password', methods=['GET'])
@login_required
def password_page():
    mc = db.admin_must_change_password(db.get_user_by_id(session['user_id']))
    return render_template('change_password.html', must_change=mc)

@app.route('/change-password', methods=['POST'])
@login_required
@csrf_required
def change_password():
    user = db.get_user_by_id(session['user_id'])
    old = request.form.get('old_password') or ''
    new = request.form.get('new_password') or ''
    confirm = request.form.get('confirm_password') or ''
    must_change = db.admin_must_change_password(user)
    if not db.verify_password(user['password'], old):
        flash('كلمة المرور الحالية غير صحيحة', 'error')
    elif len(new) < 8:
        flash('كلمة المرور يجب أن تكون 8 أحرف على الأقل', 'error')
    elif new != confirm:
        flash('كلمتا المرور غير متطابقتين', 'error')
    else:
        db.change_password(user['id'], new)
        db.mark_password_changed()
        db.log_audit('change_password', 'user', user['id'], 'تغيير كلمة المرور')
        flash('تم تغيير كلمة المرور بنجاح', 'success')
        if must_change:
            return redirect(url_for('dashboard'))
    if must_change:
        return redirect(url_for('password_page'))
    return redirect(url_for('settings'))

# ==================== DASHBOARD ====================
@app.route('/')
@login_required
def dashboard():
    stats = db.get_dashboard_stats()
    month = datetime.now().strftime('%Y-%m')
    payroll = db.get_saved_payroll(month)
    dist = db.get_pay_type_distribution()
    budget = db.get_monthly_budget(month)
    return render_template('dashboard.html', stats=stats, payroll=payroll,
                           dist=dist, budget=budget, month=month)

# ==================== EMPLOYEES ====================
@app.route('/employees')
@login_required
def employees():
    dept = request.args.get('department')
    status = request.args.get('status','active')
    search = request.args.get('search','')
    sort = request.args.get('sort','name')
    emps = db.get_employees(dept, status, search, sort)
    depts = db.get_departments(True)
    return render_template('employees.html', emps=emps, depts=depts, dept=dept, status=status,
                           sort=sort, search=search)

@app.route('/employees/add', methods=['POST'])
@role_required('supervisor')
@csrf_required
def add_employee():
    d = request.form.to_dict()
    d['emp_code'] = (request.form.get('emp_code') or '').strip() or db.next_emp_code()
    if not (request.form.get('name') or '').strip():
        flash('اسم الموظف مطلوب', 'error')
        return redirect(url_for('employees'))
    for f in ['base_salary','daily_rate','hourly_rate','commission_rate','housing_allowance','transport_allowance',
              'food_allowance','other_allowances','danger_allowance','phone_allowance',
              'social_insurance_employee_ratio','social_insurance_employer_ratio','tax_exempt_amount']:
        d[f] = _num(request.form.get(f))
    d['social_insurance_enabled'] = 1 if request.form.get('social_insurance_enabled') else 0
    d['income_tax_enabled'] = 1 if request.form.get('income_tax_enabled') else 0
    new_id = db.add_employee(d)
    db.log_audit('add', 'employee', new_id, f'إضافة موظف: {d["name"]}')
    flash('تم إضافة الموظف بنجاح', 'success')
    return redirect(url_for('employees'))

@app.route('/employees/<int:emp_id>')
@login_required
def employee_detail(emp_id):
    emp = db.get_employee(emp_id)
    if not emp:
        abort(404)
    history = db.get_salary_history(emp_id)
    depts = db.get_departments(True)
    contracts = db.get_contracts(emp_id)
    return render_template('employee_detail.html', emp=emp, depts=depts, history=history, contracts=contracts)

@app.route('/employees/<int:emp_id>/edit', methods=['POST'])
@role_required('supervisor')
@csrf_required
def edit_employee(emp_id):
    old = db.get_employee(emp_id)
    if not old:
        abort(404)
    d = request.form.to_dict()
    for f in ['base_salary','daily_rate','hourly_rate','commission_rate','housing_allowance','transport_allowance',
              'food_allowance','other_allowances','danger_allowance','phone_allowance',
              'social_insurance_employee_ratio','social_insurance_employer_ratio','tax_exempt_amount']:
        d[f] = _num(request.form.get(f))
    d['social_insurance_enabled'] = 1 if request.form.get('social_insurance_enabled') else 0
    d['income_tax_enabled'] = 1 if request.form.get('income_tax_enabled') else 0
    db.update_employee(emp_id, d)
    if old and _num(old['base_salary']) != d['base_salary']:
        db.record_salary_change(emp_id, old['base_salary'], d['base_salary'],
                                request.form.get('salary_change_reason','تعديل الراتب'), session.get('username',''))
    db.log_audit('edit', 'employee', emp_id, f'تعديل بيانات موظف: {old["name"]}')
    flash('تم تحديث بيانات الموظف', 'success')
    return redirect(url_for('employee_detail', emp_id=emp_id))

@app.route('/employees/<int:emp_id>/delete', methods=['POST'])
@admin_required
@csrf_required
def delete_employee(emp_id):
    emp = db.get_employee(emp_id)
    db.delete_employee(emp_id)
    db.log_audit('delete', 'employee', emp_id, f'حذف موظف: {emp["name"] if emp else ""}')
    flash('تم حذف الموظف', 'success')
    return redirect(url_for('employees'))

@app.route('/employees/<int:emp_id>/face', methods=['POST'])
@login_required
@role_required('supervisor')
@csrf_required
def employee_update_face(emp_id):
    emp = db.get_employee(emp_id)
    if not emp:
        flash('الموظف غير موجود', 'error')
        return redirect(url_for('employees'))
    face_data = None
    if 'face_file' in request.files and request.files['face_file'].filename:
        file = request.files['face_file']
        data = file.read()
        mimetype = file.mimetype or 'image/jpeg'
        face_data = f"data:{mimetype};base64," + base64.b64encode(data).decode('utf-8')
    elif request.form.get('face_data'):
        face_data = request.form.get('face_data')
    elif request.get_json(silent=True) and request.get_json().get('face_data'):
        face_data = request.get_json().get('face_data')

    if face_data:
        db.update_employee_face(emp_id, face_data)
        db.log_audit('face_update', 'employee', emp_id, f'تسجيل/تحديث بصمة الوجه: {emp["name"]}')
        flash('تم حفظ صورة بصمة الوجه بنجاح', 'success')
    else:
        flash('لم يتم تحديد صورة صالحة', 'error')

    if request.is_json:
        return jsonify({'ok': True, 'message': 'تم الحفظ'})
    return redirect(url_for('employee_detail', emp_id=emp_id))

@app.route('/employees/<int:emp_id>/face/delete', methods=['POST'])
@login_required
@role_required('supervisor')
@csrf_required
def employee_delete_face(emp_id):
    emp = db.get_employee(emp_id)
    if not emp:
        flash('الموظف غير موجود', 'error')
        return redirect(url_for('employees'))
    db.delete_employee_face(emp_id)
    db.log_audit('face_delete', 'employee', emp_id, f'حذف بصمة الوجه للموظف {emp["name"]}')
    flash('تم حذف بصمة الوجه بنجاح', 'success')
    return redirect(url_for('employee_detail', emp_id=emp_id))

@app.route('/employees/export')
@login_required
def export_employees():
    emps = db.get_employees(status='all')
    wb = Workbook()
    ws = wb.active
    ws.title = "الموظفين"
    headers = ['الكود','الاسم','الرقم القومي','القسم','الوظيفة','نوع الأجر','الراتب الأساسي','الراتب اليومي','سعر الساعة',
               'السكن','النقل','الطعام','أخرى','خطورة','موبايل','التأمينات','الضرائب','الحالة']
    ws.append(headers)
    for e in emps:
        ws.append([e['emp_code'],e['name'],e['national_id'],e.get('dept_name',''),e['position'],e['pay_type'],
                   e['base_salary'],e['daily_rate'],e['hourly_rate'],e['housing_allowance'],e['transport_allowance'],
                   e['food_allowance'],e['other_allowances'],e['danger_allowance'],e['phone_allowance'],
                   'نعم' if e['social_insurance_enabled'] else 'لا','نعم' if e['income_tax_enabled'] else 'لا',e['status']])
    # تنسيق فخم بأعمدة أرقام
    money = [7,8,9,10,11,12,13,14,15]  # الفهرس (1-base) للأعمدة المالية
    center = [1,4,6,16,17,18]
    _style_sheet(ws, 1, len(headers), money_cols=money, center_cols=center)
    out = _export_xlsx(wb)
    return send_file(out, as_attachment=True, download_name='الموظفين.xlsx',
                     mimetype='application/vnd.openxmlformats-officedocument.spreadsheetml.sheet')

# ==================== DEPARTMENTS ====================
@app.route('/departments')
@login_required
def departments():
    depts = db.get_departments()
    return render_template('departments.html', depts=depts)

@app.route('/departments/add', methods=['POST'])
@login_required
@csrf_required
def add_department():
    name = (request.form.get('name') or '').strip()
    if not name:
        flash('اسم القسم مطلوب', 'error')
        return redirect(url_for('departments'))
    try:
        db.add_department(name, request.form.get('manager',''), request.form.get('cost_center',''))
        db.log_audit('add', 'department', None, f'إضافة قسم: {name}')
        flash('تم إضافة القسم', 'success')
    except Exception:
        flash('القسم موجود بالفعل', 'error')
    return redirect(url_for('departments'))

@app.route('/departments/<int:dep_id>/delete', methods=['POST'])
@admin_required
@csrf_required
def delete_department(dep_id):
    if not db.delete_department(dep_id):
        flash('لا يمكن حذف قسم به موظفين', 'error')
    else:
        db.log_audit('delete', 'department', dep_id, 'حذف قسم')
        flash('تم حذف القسم', 'success')
    return redirect(url_for('departments'))

# ==================== ATTENDANCE ====================
@app.route('/attendance')
@login_required
def attendance():
    month = request.args.get('month', datetime.now().strftime('%Y-%m'))
    emps = db.get_employees(status='active')
    records = db.get_attendance(month)
    return render_template('attendance.html', emps=emps, records=records, month=month)

@app.route('/attendance/save', methods=['POST'])
@role_required('user')
@csrf_required
def save_attendance():
    month = request.json.get('month')
    db.bulk_save_attendance(month, request.json.get('records', []))
    db.log_audit('attendance', 'attendance', None, f'تحديث حضور شهر {month}')
    return jsonify({'ok': True})

# حالة اليوم في تقويم الحضور: (النص المعروض، صنف CSS، الأيقونة)
_ATT_STATUS_META = {
    'present': ('حاضر', 'cal-present', '✅'),
    'late':    ('متأخر', 'cal-late', '⏰'),
    'absent':  ('غائب', 'cal-absent', '❌'),
    'leave':   ('إجازة', 'cal-leave', '🏖️'),
    'sick':    ('مرضي', 'cal-sick', '🤒'),
}

def _month_calendar(month, records_by_date, settings):
    """بناء أسابيع تقويم الشهر (السبت أول يوم) لحضور موظف واحد."""
    try:
        y, m = int(month[:4]), int(month[5:7])
        ndays = calendar.monthrange(y, m)[1]
    except Exception:
        return []
    weekend = db._weekly_holiday_weekdays(settings)
    count_missing = db._setting_on(settings, 'count_missing_as_absent')
    today = date.today()
    cells = []
    for d in range(1, ndays + 1):
        cur = date(y, m, d)
        rec = records_by_date.get(cur.isoformat())
        cell = {'day': d, 'date': cur.isoformat(), 'cin': '', 'cout': '', 'note': ''}
        if cur.weekday() in weekend:
            cell.update(status='weekend', label='إجازة أسبوعية', cls='cal-off', icon='🛌')
        elif cur > today:
            cell.update(status='future', label='لم يأتِ بعد', cls='cal-future', icon='🔜')
        elif rec:
            st = rec.get('status') or 'present'
            label, cls, icon = _ATT_STATUS_META.get(st, (st, 'cal-future', '•'))
            cell.update(status=st, label=label, cls=cls, icon=icon,
                        cin=rec.get('check_in') or '', cout=rec.get('check_out') or '',
                        note=rec.get('note') or '')
        elif count_missing:
            cell.update(status='missing', label='بدون تسجيل = غياب', cls='cal-missing', icon='⛔')
        else:
            cell.update(status='missing', label='بدون تسجيل', cls='cal-nosign', icon='➖')
        cells.append(cell)
    # تجميع الأيام في أسابيع تبدأ من السبت
    weeks, week = [], [None] * ((date(y, m, 1).weekday() + 2) % 7)
    for cell in cells:
        week.append(cell)
        if len(week) == 7:
            weeks.append(week); week = []
    if week:
        week += [None] * (7 - len(week))
        weeks.append(week)
    return weeks

@app.route('/attendance/calendar')
@login_required
def attendance_calendar():
    """شاشة تقويم الحضور: كل موظف وأيام حضوره/غيابه، وعند اختيار موظف يظهر تقويم الشهر."""
    month = request.args.get('month', datetime.now().strftime('%Y-%m'))
    emp_id = request.args.get('emp_id', type=int)
    settings = db.get_settings()
    emps = db.get_employees(status='active')
    summary = {r['employee_id']: r for r in db.calculate_payroll(month)}
    by_emp = {}
    for r in db.get_attendance(month):
        by_emp.setdefault(r['employee_id'], {})[r['date']] = r
    sel = next((e for e in emps if e['id'] == emp_id), None)
    if not sel and emp_id:
        sel = db.get_employee(emp_id)
    weeks = _month_calendar(month, by_emp.get(emp_id, {}), settings) if sel else []
    return render_template('attendance_calendar.html', month=month, emps=emps, summary=summary,
                           sel=sel, sel_summary=summary.get(emp_id), weeks=weeks,
                           count_missing=db._setting_on(settings, 'count_missing_as_absent'),
                           settings=settings)

# ==================== LEAVES ====================
@app.route('/leaves')
@login_required
def leaves():
    emps = db.get_employees(status='active')
    records = db.get_leaves()
    return render_template('leaves.html', emps=emps, records=records)

@app.route('/leaves/add', methods=['POST'])
@role_required('user')
@csrf_required
def add_leave():
    d = request.form.to_dict()
    d['days'] = _num(request.form.get('days'))
    db.add_leave(d)
    db.log_audit('add', 'leave', None, 'إضافة طلب إجازة')
    flash('تم إرسال طلب الإجازة', 'success')
    return redirect(url_for('leaves'))

@app.route('/leaves/<int:leave_id>/<status>', methods=['POST'])
@admin_required
@csrf_required
def leave_status(leave_id, status):
    if status not in ('approved','rejected'):
        abort(400)
    db.update_leave_status(leave_id, status, session.get('username',''))
    db.log_audit('leave_status', 'leave', leave_id, f'{ "اعتماد" if status=="approved" else "رفض" } إجازة')
    flash(f'تم { "اعتماد" if status=="approved" else "رفض" } الإجازة', 'success')
    return redirect(url_for('leaves'))

# ==================== OVERTIME ====================
@app.route('/overtime')
@login_required
def overtime():
    month = request.args.get('month', datetime.now().strftime('%Y-%m'))
    emps = db.get_employees(status='active')
    records = db.get_overtime(month)
    return render_template('overtime.html', emps=emps, records=records, month=month)

@app.route('/overtime/save', methods=['POST'])
@role_required('user')
@csrf_required
def save_overtime():
    month = request.json.get('month')
    db.bulk_save_overtime(month, request.json.get('records', []))
    db.log_audit('overtime', 'overtime', None, f'تحديث إضافي شهر {month}')
    return jsonify({'ok': True})

# ==================== COMMISSIONS ====================
@app.route('/commissions')
@login_required
def commissions():
    month = request.args.get('month', datetime.now().strftime('%Y-%m'))
    emps = db.get_employees(status='active')
    records = db.get_commissions(month)
    return render_template('commissions.html', emps=emps, records=records, month=month)

@app.route('/commissions/save', methods=['POST'])
@role_required('user')
@csrf_required
def save_commissions():
    month = request.json.get('month')
    db.bulk_save_commissions(month, request.json.get('records', []))
    db.log_audit('commissions', 'commissions', None, f'تحديث عمولات شهر {month}')
    return jsonify({'ok': True})

# ==================== DEDUCTIONS ====================
@app.route('/deductions')
@login_required
def deductions():
    month = request.args.get('month', datetime.now().strftime('%Y-%m'))
    emps = db.get_employees(status='active')
    records = db.get_deductions(month)
    types = db.get_deduction_types()
    return render_template('deductions.html', emps=emps, records=records, types=types, month=month)

@app.route('/deductions/save', methods=['POST'])
@role_required('user')
@csrf_required
def save_deductions():
    month = request.json.get('month')
    db.bulk_save_deductions(month, request.json.get('records', []))
    db.log_audit('deductions', 'deductions', None, f'تحديث خصومات شهر {month}')
    return jsonify({'ok': True})

# ==================== BULK INCENTIVES (جماعية) ====================
# حوافز/خصومات تُطبق على الكل دفعة واحدة -> تُسجَّل كحوافز إضافية
@app.route('/bulk-incentives', methods=['GET','POST'])
@role_required('supervisor')
@csrf_required
def bulk_incentives():
    month = request.args.get('month', datetime.now().strftime('%Y-%m'))
    if request.method == 'POST':
        d = request.form.to_dict()
        d['month'] = (request.form.get('month') or datetime.now().strftime('%Y-%m'))
        d['kind'] = request.form.get('kind','bonus')
        d['per_employee_amount'] = _num(request.form.get('per_employee_amount'))
        spe = []
        for key, val in request.form.items():
            if key.startswith('emp_') and val == 'on':
                spe.append(key.replace('emp_',''))
        d['specific_employees'] = json.dumps(spe, ensure_ascii=False)
        db.add_bulk_incentive(d, session.get('username',''))
        db.apply_bulk_to_payroll(d['month'])
        db.log_audit('bulk_incentive', 'incentive', None, f'حافز/خصم جماعي شهر {d["month"]}')
        flash('تم تطبيق الحافز/الخصم الجماعي', 'success')
        return redirect(url_for('bulk_incentives', month=month))
    emps = db.get_employees(status='active')
    items = db.get_bulk_incentives(month)
    return render_template('bulk_incentives.html', emps=emps, items=items, month=month)

@app.route('/bulk-incentives/<int:bid>/delete', methods=['POST'])
@login_required
@csrf_required
def delete_bulk_incentive(bid):
    db.delete_bulk_incentive(bid)
    db.log_audit('delete', 'incentive', bid, 'حذف حافز جماعي')
    flash('تم الحذف', 'success')
    return redirect(url_for('bulk_incentives'))

# ==================== ADVANCES ====================
@app.route('/advances')
@login_required
def advances():
    emps = db.get_employees(status='active')
    records = db.get_advances()
    return render_template('advances.html', emps=emps, records=records)

@app.route('/advances/add', methods=['POST'])
@role_required('supervisor')
@csrf_required
def add_advance():
    d = request.form.to_dict()
    d['amount'] = _num(request.form.get('amount'))
    d['installment_count'] = int(_num(request.form.get('installment_count'), 1))
    db.add_advance(d)
    db.log_audit('add', 'advance', None, 'إضافة سلفة')
    flash('تم إضافة السلفة', 'success')
    return redirect(url_for('advances'))

@app.route('/advances/<int:adv_id>/delete', methods=['POST'])
@admin_required
@csrf_required
def delete_advance(adv_id):
    db.delete_advance(adv_id)
    db.log_audit('delete', 'advance', adv_id, 'حذف سلفة')
    flash('تم حذف السلفة', 'success')
    return redirect(url_for('advances'))

# ==================== PAYROLL ====================
@app.route('/payroll')
@login_required
def payroll():
    month = request.args.get('month', datetime.now().strftime('%Y-%m'))
    calculated = db.calculate_payroll(month)
    saved = db.get_saved_payroll(month)
    settings = db.get_settings()
    signs = db.get_signatures(month)
    signed_map = {s['employee_id']: s for s in signs}
    return render_template('payroll.html', data=calculated, saved=saved, month=month,
                           settings=settings, signed_map=signed_map)

@app.route('/payroll/save', methods=['POST'])
@role_required('supervisor')
@csrf_required
def save_payroll():
    month = request.json.get('month')
    db.save_payroll(month, request.json.get('records', []))
    db.log_audit('payroll_save', 'payroll', None, f'حفظ كشف مرتبات شهر {month}')
    return jsonify({'ok': True})

@app.route('/payroll/confirm', methods=['POST'])
@role_required('supervisor')
@csrf_required
def confirm_payroll():
    month = request.form['month']
    db.confirm_payroll(month, session.get('username',''))
    db.log_audit('payroll_confirm', 'payroll', None, f'اعتماد صرف مرتبات شهر {month}')
    flash('تم اعتماد صرف المرتبات', 'success')
    return redirect(url_for('payroll', month=month))

@app.route('/payroll/export', methods=['POST'])
@role_required('supervisor')
@csrf_required
def export_payroll():
    month = request.form['month']
    data = db.calculate_payroll(month)
    settings = db.get_settings()
    wb = Workbook()
    ws = wb.active
    ws.title = f"مرتبات {month}"
    ws.merge_cells('A1:S1')
    ws['A1'] = f"{settings['company_name']} - كشف مرتبات شهر {month}"
    ws['A1'].font = Font(bold=True, size=14)
    ws['A1'].alignment = Alignment(horizontal='center')
    headers = ['الكود','الاسم','القسم','الوظيفة','أيام الحضور','أيام الغياب','الأساسي','البدلات','إضافي','عمولة','إجمالي المستحق',
               'تأمينات(موظف)','ضرائب','سلف','غياب','تأخير','خصومات أخرى','إجمالي الخصومات','صافي الراتب']
    ws.append([])
    ws.append(headers)
    rows = [[r['emp_code'],r['name'],r['dept_name'],r['position'],r['present_days'],r['absent_days'],
             r['base'],r['allowances'],
             r['overtime_amt'],r['commissions'],r['gross'],r['si_employee'],r['income_tax'],
             r['advance_installments'],r['absence_deduction'],r['late_deduction'],r['other_deductions'],
             r['total_deductions'],r['net']] for r in data]
    for row in rows:
        ws.append(row)
    total_row = len(rows) + 4
    ws.cell(row=total_row, column=2, value='الإجمالي')
    total_cols = [5,6,7,8,9,10,11,12,13,14,15,16,17,18,19]
    # صف الإجمالي: تجميع الأعمدة المالية فقط
    for col in total_cols:
        total = sum(row[col-1] for row in rows)
        ws.cell(row=total_row, column=col, value=round(total,2))
    _style_sheet(ws, header_row=3, ncols=len(headers),
                 total_rows=(total_row,),
                 money_cols=[7,8,9,10,11,12,13,14,15,16,17,18,19],
                 center_cols=[1,3,4,5,6])
    out = _export_xlsx(wb)
    return send_file(out, as_attachment=True, download_name=f'مرتبات-{month}.xlsx',
                     mimetype='application/vnd.openxmlformats-officedocument.spreadsheetml.sheet')

@app.route('/payroll/pdf')
@login_required
def payroll_pdf():
    month = request.args.get('month', datetime.now().strftime('%Y-%m'))
    data = db.calculate_payroll(month)
    settings = db.get_settings()
    return _build_payroll_table_pdf(data, month, settings, 'كشف حساب المرتبات', 'payroll')

@app.route('/payslip/<int:emp_id>/<month>')
@login_required
def payslip(emp_id, month):
    emp = db.get_employee(emp_id)
    if not emp:
        abort(404)
    calc = db.calculate_payroll(month)
    record = next((r for r in calc if r['employee_id']==emp_id), None)
    settings = db.get_settings()
    signed = db.has_signed(emp_id, month)
    return render_template('payslip.html', emp=emp, rec=record, month=month, settings=settings, signed=signed)

@app.route('/payslip/<int:emp_id>/<month>/sign', methods=['POST'])
@login_required
@csrf_required
def sign_payslip(emp_id, month):
    emp = db.get_employee(emp_id)
    if not emp:
        abort(404)
    calc = db.calculate_payroll(month)
    record = next((r for r in calc if r['employee_id']==emp_id), None)
    if not record:
        flash('لا يوجد كشف مرتب لهذا الموظف', 'error')
        return redirect(url_for('payslip', emp_id=emp_id, month=month))
    sig = request.form.get('signature_text') or request.form.get('signature_data') or ''
    # صورة توقيع اختيارية
    sig_img = ''
    if 'signature_img' in request.files and request.files['signature_img'].filename:
        f = request.files['signature_img']
        safe = f.read()
        if len(safe) > 300*1024:
            flash('حجم صورة التوقيع كبير', 'error')
            return redirect(url_for('payslip', emp_id=emp_id, month=month))
        import base64
        sig_img = base64.b64encode(safe).decode('ascii')
    sign_data = sig if sig else (f"img:{sig_img}" if sig_img else '')
    db.sign_payroll(emp_id, month, f"SLIP-{emp_id}-{month}", record['gross'], record['net'],
                    sign_data, request.remote_addr or '', request.form.get('notes',''))
    db.log_audit('sign', 'payslip', emp_id, f'توقيع استلام راتب {month}')
    flash('تم تسجيل توقيع الاستلام بنجاح', 'success')
    return redirect(url_for('payslip', emp_id=emp_id, month=month))

@app.route('/payslip/<int:emp_id>/<month>/pdf')
@login_required
def payslip_pdf(emp_id, month):
    emp = db.get_employee(emp_id)
    if not emp:
        abort(404)
    calc = db.calculate_payroll(month)
    record = next((r for r in calc if r['employee_id']==emp_id), None)
    settings = db.get_settings()
    return _build_payslip_pdf(emp, record, month, settings)

# ==================== CONTRACTS ====================
@app.route('/contracts')
@login_required
def contracts():
    emps = db.get_employees(status='all')
    records = db.get_contracts()
    return render_template('contracts.html', emps=emps, records=records)

@app.route('/contracts/add', methods=['POST'])
@role_required('supervisor')
@csrf_required
def add_contract():
    d = request.form.to_dict()
    d['salary'] = _num(request.form.get('salary'))
    new_id = db.add_contract(d)
    db.log_audit('add', 'contract', new_id, 'إضافة عقد')
    flash('تم إضافة العقد', 'success')
    return redirect(url_for('contracts'))

@app.route('/contracts/<int:cid>/edit', methods=['POST'])
@login_required
@csrf_required
def edit_contract(cid):
    d = request.form.to_dict()
    d['salary'] = _num(request.form.get('salary'))
    db.update_contract(cid, d)
    db.log_audit('edit', 'contract', cid, 'تعديل عقد')
    flash('تم تحديث العقد', 'success')
    return redirect(url_for('contracts'))

@app.route('/contracts/<int:cid>/delete', methods=['POST'])
@admin_required
@csrf_required
def delete_contract(cid):
    db.delete_contract(cid)
    db.log_audit('delete', 'contract', cid, 'حذف عقد')
    flash('تم حذف العقد', 'success')
    return redirect(url_for('contracts'))

# ==================== PAYROLL COMPARISON (مقارنة شهرين) ====================
@app.route('/reports/comparison')
@login_required
def comparison():
    m1 = request.args.get('month1', datetime.now().strftime('%Y-%m'))
    m2 = request.args.get('month2', (datetime.now().replace(day=1) - timedelta(days=1)).strftime('%Y-%m'))
    data1 = {r['employee_id']: r for r in db.calculate_payroll(m1)}
    data2 = {r['employee_id']: r for r in db.calculate_payroll(m2)}
    ids = sorted(set(data1.keys()) | set(data2.keys()))
    rows = []
    for eid in ids:
        a = data1.get(eid); b = data2.get(eid)
        if not a: a = {k: 0 for k in (b or {})}; a['name']=b['name']; a['emp_code']=b['emp_code']; a['employee_id']=eid
        if not b: b = {k: 0 for k in (a or {})}; b['name']=a['name']; b['emp_code']=a['emp_code']; b['employee_id']=eid
        rows.append({'id': eid, 'name': a.get('name',''), 'emp_code': a.get('emp_code',''),
                     'net1': a.get('net',0), 'net2': b.get('net',0),
                     'diff': round((b.get('net',0) or 0) - (a.get('net',0) or 0), 2),
                     'gross1': a.get('gross',0), 'gross2': b.get('gross',0),
                     'ded1': a.get('total_deductions',0), 'ded2': b.get('total_deductions',0)})
    return render_template('comparison.html', rows=rows, m1=m1, m2=m2)

# ==================== REPORTS ====================
@app.route('/reports')
@login_required
def reports():
    month = request.args.get('month', datetime.now().strftime('%Y-%m'))
    data = db.calculate_payroll(month)
    signatures = db.get_signatures(month)
    return render_template('reports.html', data=data, month=month, signatures=signatures)

@app.route('/reports/pdf')
@login_required
def reports_pdf():
    month = request.args.get('month', datetime.now().strftime('%Y-%m'))
    data = db.calculate_payroll(month)
    settings = db.get_settings()
    return _build_payroll_table_pdf(data, month, settings, 'كشف المرتبات', 'reports')

@app.route('/reports/department')
@login_required
def dept_report():
    month = request.args.get('month', datetime.now().strftime('%Y-%m'))
    data = db.calculate_payroll(month)
    from collections import defaultdict
    grouped = defaultdict(lambda: {'count':0,'base':0,'earnings':0,'deductions':0,'net':0})
    for r in data:
        dept = r['dept_name'] or 'بدون قسم'
        g = grouped[dept]
        g['count'] += 1
        g['base'] += r['base']
        g['earnings'] += r['gross']
        g['deductions'] += r['total_deductions']
        g['net'] += r['net']
    return render_template('dept_report.html', grouped=dict(grouped), month=month)

@app.route('/reports/department/export')
@login_required
def dept_report_export():
    month = request.args.get('month', datetime.now().strftime('%Y-%m'))
    from collections import defaultdict
    grouped = defaultdict(lambda: {'count':0,'base':0,'earnings':0,'deductions':0,'net':0})
    for r in db.calculate_payroll(month):
        dept = r['dept_name'] or 'بدون قسم'
        g = grouped[dept]
        g['count'] += 1; g['base'] += r['base']; g['earnings'] += r['gross']
        g['deductions'] += r['total_deductions']; g['net'] += r['net']
    wb = Workbook(); ws = wb.active; ws.title = "تقرير الأقسام"
    headers = ['القسم','عدد الموظفين','الأساسي','إجمالي المستحق','الإجمالي للخصومات','صافي']
    ws.append(headers)
    for dept, g in grouped.items():
        ws.append([dept, g['count'], g['base'], g['earnings'], g['deductions'], g['net']])
    total_row = ws.max_row + 1
    ws.cell(row=total_row, column=1, value='الإجمالي')
    for col, key in [(3,'base'),(4,'earnings'),(5,'deductions'),(6,'net')]:
        ws.cell(row=total_row, column=col, value=round(sum(g[k] for g in grouped.values()), 2))
    ws.cell(row=total_row, column=2, value=sum(g['count'] for g in grouped.values()))
    _style_sheet(ws, 1, len(headers), total_rows=(total_row,),
                 money_cols=[3,4,5,6], center_cols=[2])
    out = _export_xlsx(wb)
    return send_file(out, as_attachment=True, download_name=f'تقرير-الأقسام-{month}.xlsx',
                     mimetype='application/vnd.openxmlformats-officedocument.spreadsheetml.sheet')

@app.route('/reports/annual')
@login_required
def annual_report():
    year = request.args.get('year', str(datetime.now().year))
    result = {}
    grand = {'net':0,'earnings':0,'deductions':0}
    for m in range(1,13):
        month = f"{year}-{m:02d}"
        data = db.calculate_payroll(month)
        result[month] = {'count': len(data), 'net': sum(r['net'] for r in data),
                         'earnings': sum(r['gross'] for r in data),
                         'deductions': sum(r['total_deductions'] for r in data)}
        grand['net'] += result[month]['net']; grand['earnings'] += result[month]['earnings']
        grand['deductions'] += result[month]['deductions']
    return render_template('annual_report.html', data=result, year=year, grand=grand)

# ==================== SIGNATURES LOG (سجل التوقيعات) ====================
@app.route('/reports/signatures')
@login_required
def signatures_log():
    month = request.args.get('month', datetime.now().strftime('%Y-%m'))
    signs = db.get_signatures(month)
    return render_template('signatures.html', signs=signs, month=month)

# ==================== AUDIT LOG (سجل التدقيق) ====================
@app.route('/audit')
@admin_required
def audit():
    day = request.args.get('day', '')
    if day:
        logs = db.get_audit_log(1000, day=day)
    else:
        logs = db.get_audit_log(300)
    return render_template('audit.html', logs=logs, day=day)

@app.route('/audit/export')
@admin_required
def audit_export():
    day = request.args.get('day', '')
    logs = db.get_audit_log(10000, day=day)
    wb = Workbook(); ws = wb.active; ws.title = "سجل التدقيق"
    headers = ['التاريخ','المستخدم','الإجراء','الكيان','التفاصيل','IP']
    ws.append(headers)
    for l in logs:
        ws.append([l['created_at'], l['username'], l['action'], l['entity'], l['details'], l['ip_address']])
    _style_sheet(ws, 1, len(headers), center_cols=[1,2,3,4,6])
    out = _export_xlsx(wb)
    fname = f'سجل-التدقيق-{day}.xlsx' if day else 'سجل-التدقيق.xlsx'
    return send_file(out, as_attachment=True, download_name=fname,
                     mimetype='application/vnd.openxmlformats-officedocument.spreadsheetml.sheet')

# ==================== SETTINGS ====================
@app.route('/settings', methods=['GET','POST'])
@login_required
@csrf_required
def settings():
    if request.method == 'POST':
        if session.get('role') != 'admin':
            flash('الإعدادات تعديلها للمسؤول فقط', 'error')
            return redirect(url_for('settings'))
        form = request.form.to_dict()
        # Determine which settings to save based on form fields
        if 'save_device' in form:
            db.save_device_settings(form)
            db.log_audit('settings', 'device_settings', None, 'تحديث إعدادات الجهاز')
            flash('تم حفظ إعدادات الجهاز', 'success')
        elif 'save_fps' in form or 'gps_enabled' in form or 'company_lat' in form:
            db.save_fps_settings(form)
            db.log_audit('settings', 'fps_gps_settings', None, 'تحديث إعدادات FPS/GPS')
            flash('تم حفظ إعدادات الوجه والموقع', 'success')
        elif 'save_mobile' in form or 'mobile_login_enabled' in form:
            db.save_fps_settings(form)
            db.log_audit('settings', 'mobile_settings', None, 'تحديث إعدادات الهاتف المحمول')
            flash('تم حفظ إعدادات الهاتف المحمول', 'success')
        elif 'save_location' in form:
            db.save_fps_settings(form)
            db.log_audit('settings', 'location_settings', None, 'تحديث إحداثيات الشركة')
            flash('تم حفظ إحداثيات الشركة', 'success')
        else:
            db.save_settings(form)
            db.save_fps_settings(form)
            db.log_audit('settings', 'settings', None, 'تحديث جميع الإعدادات')
            flash('تم حفظ الإعدادات', 'success')
        return redirect(url_for('settings'))
    s = db.get_settings()
    brackets = db.get_tax_brackets()
    backups = db.list_backups()
    # Add device settings
    device_settings = db.get_device_settings()
    # Add FPS/GPS settings
    fps_settings = db.get_fps_settings()
    return render_template('settings.html', s=s, brackets=brackets, backups=backups, device_settings=device_settings, fps_settings=fps_settings)

# ==================== DEVICE MANAGEMENT (ZKTeco Fingerprint) ====================
@app.route('/devices')
@login_required
def devices():
    status_filter   = request.args.get('status', 'all')
    search          = request.args.get('search', '').strip()
    devices_list    = db.get_devices(active_only=False)
    for d in devices_list:
        d['unprocessed_count'] = db.get_unprocessed_attendance_count(d['id'])
        d['mapped_employees']  = len(db.get_device_employees(d['id']))
    # apply filters in Python (simple, avoids extra DB queries)
    if status_filter != 'all':
        devices_list = [d for d in devices_list if d['status'] == status_filter]
    if search:
        sl = search.lower()
        devices_list = [d for d in devices_list
                        if sl in (d.get('name') or '').lower()
                        or sl in (d.get('ip_address') or '').lower()
                        or sl in (d.get('location') or '').lower()]
    global_unprocessed  = db.get_unprocessed_attendance_count()
    global_total_records = sum(d.get('total_records') or 0 for d in db.get_devices(active_only=False))
    return render_template('devices.html',
                           devices=devices_list,
                           status_filter=status_filter,
                           global_unprocessed=global_unprocessed,
                           global_total_records=global_total_records,
                           now=datetime.now())

@app.route('/device/add', methods=['GET', 'POST'])
@login_required
@admin_required
def device_add():
    if request.method == 'POST':
        device_id = db.add_device(request.form.to_dict())
        db.add_device_log(device_id, 'add', 'تم إضافة جهاز: ' + request.form.get('name', ''), success=1)
        db.log_audit('device', 'device_add', device_id, 'إضافة جهاز: ' + request.form.get('name', ''))
        flash('تم إضافة الجهاز بنجاح', 'success')
        return redirect(url_for('devices'))
    return render_template('device_add.html')

@app.route('/device/<int:device_id>/edit', methods=['GET', 'POST'])
@login_required
@admin_required
def device_edit(device_id):
    device = db.get_device(device_id)
    if not device:
        flash('الجهاز غير موجود', 'error')
        return redirect(url_for('devices'))
    if request.method == 'POST':
        db.update_device(device_id, request.form.to_dict())
        db.add_device_log(device_id, 'update', 'تعديل الجهاز: ' + request.form.get('name', ''), success=1)
        db.log_audit('device', 'device_edit', device_id, 'تعديل جهاز: ' + request.form.get('name', ''))
        flash('تم تحديث الجهاز', 'success')
        return redirect(url_for('devices'))
    return render_template('device_edit.html', device=device)

@app.route('/device/<int:device_id>/delete', methods=['POST'])
@login_required
@admin_required
def device_delete(device_id):
    device = db.get_device(device_id)
    if device:
        db.add_device_log(device_id, 'delete', 'حذف الجهاز: ' + device['name'], success=1)
        db.delete_device(device_id)
        db.log_audit('device', 'device_delete', device_id, 'حذف جهاز: ' + device['name'])
        flash('تم حذف الجهاز', 'success')
    return redirect(url_for('devices'))

@app.route('/device/<int:device_id>/connect', methods=['POST'])
@login_required
def device_connect_detail(device_id):
    import os, sys
    from datetime import datetime
    sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
    from zkteco_device import ZKDevice

    device = db.get_device(device_id)
    if not device:
        return jsonify({'ok': False, 'error': 'Device not found'}), 404

    zk = ZKDevice(device['ip_address'], int(device['port']))

    if zk.connect():
        # Auto-sync device clock on every connect
        zk.sync_time(datetime.now())
        db.update_device_status(device_id, 'connected')
        db.add_device_log(device_id, 'connect', 'تم الاتصال: ' + device['name'], success=1)
        db.log_audit('device', 'device_connect', device_id, 'اتصال: ' + device['name'])
        users = zk.get_user_list()
        synced = 0
        for user in users:
            existing = db.get_employee_by_device_uid(device_id, user['uid'])
            if not existing:
                emp = db.get_employee_by_code(user['uid'])
                if emp:
                    db.map_device_employee(device_id, user['uid'], emp['id'])
                    synced += 1
        zk.disconnect()
        db.add_device_log(device_id, 'sync_users', 'مزامنة: ' + str(synced) + ' مستخدم', records_count=synced, success=1)
        return jsonify({'ok': True, 'status': 'connected', 'users_synced': synced})
    else:
        db.update_device_status(device_id, 'connection_failed')
        db.add_device_log(device_id, 'connect', 'فشل الاتصال: ' + device['name'], success=0, error_message='Connection failed')
        db.log_audit('device', 'device_connect_failed', device_id, 'فشل الاتصال: ' + device['name'])
        return jsonify({'ok': False, 'error': 'Connection failed'}), 400

@app.route('/device/<int:device_id>/disconnect', methods=['POST'])
@login_required
def device_disconnect_detail(device_id):
    device = db.get_device(device_id)
    if device:
        db.update_device_status(device_id, 'disconnected')
        db.add_device_log(device_id, 'disconnect', 'قطع الاتصال: ' + device['name'], success=1)
        db.log_audit('device', 'device_disconnect', device_id, 'قطع الاتصال: ' + device['name'])
    return jsonify({'ok': True, 'status': 'disconnected'})

@app.route('/device/<int:device_id>/download-attendance', methods=['POST'])
@login_required
def device_download_attendance(device_id):
    import os, sys
    from datetime import datetime
    sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
    from zkteco_device import ZKDevice

    device = db.get_device(device_id)
    if not device:
        return jsonify({'ok': False, 'error': 'Device not found'}), 404

    month = request.form.get('month', datetime.now().strftime('%Y-%m'))

    zk = ZKDevice(device['ip_address'], int(device['port']))

    if not zk.connect():
        db.update_device_status(device_id, 'connection_failed')
        db.add_device_log(device_id, 'download', 'فشل التحميل - فشل الاتصال', success=0, error_message='Connection failed')
        return jsonify({'ok': False, 'error': 'Connection failed'}), 400

    try:
        attendance = zk.get_attendance()
        saved_count = db.save_biometric_attendance(device_id, attendance)

        db.update_device_status(device_id, 'connected', total_records=len(attendance))
        db.add_device_log(device_id, 'download', 'تحميل الحضور: ' + str(saved_count) + ' سجل', records_count=saved_count, success=1)
        db.log_audit('device', 'device_download', device_id, 'تحميل ' + str(saved_count) + ' سجل')

        zk.disconnect()

        return jsonify({
            'ok': True,
            'records': len(attendance),
            'saved': saved_count,
            'status': 'connected',
            'message': 'تم تحميل ' + str(len(attendance)) + ' سجل، تم حفظ ' + str(saved_count) + ' جديد'
        })
    except Exception as e:
        db.update_device_status(device_id, 'error')
        db.add_device_log(device_id, 'download', 'خطأ: ' + str(e), success=0, error_message=str(e))
        zk.disconnect()
        return jsonify({'ok': False, 'error': str(e)}), 500

@app.route('/device/<int:device_id>/attendance')
@login_required
def device_attendance(device_id):
    device = db.get_device(device_id)
    if not device:
        flash('الجهاز غير موجود', 'error')
        return redirect(url_for('devices'))
    processed = request.args.get('processed', None)
    if processed == 'pending': processed = 0
    elif processed == 'processed': processed = 1
    elif processed == 'applied': processed = 2
    else: processed = None
    date_from = request.args.get('date_from', '')
    date_to = request.args.get('date_to', '')
    records = db.get_biometric_attendance(
        device_id=device_id, processed=processed,
        date_from=date_from if date_from else None,
        date_to=date_to if date_to else None, limit=1000)
    mapped_uids = [m['device_uid'] for m in db.get_device_employees(device_id)]
    unmapped_records = [r for r in records if r['device_uid'] not in mapped_uids and r['processed'] == 0]
    return render_template('device_attendance.html', device=device, records=records,
                           processed=processed, date_from=date_from, date_to=date_to,
                           unmapped_records=unmapped_records,
                           unprocessed_count=db.get_unprocessed_attendance_count(device_id),
                           all_employees=db.get_employees(status='active'),
                           now=datetime.now())

@app.route('/device/<int:device_id>/map-employee', methods=['POST'])
@login_required
@admin_required
def device_map_employee(device_id):
    device_uid  = request.form.get('device_uid')
    employee_id = request.form.get('employee_id')
    apply_pend  = request.form.get('apply_pending') == '1'
    if device_uid and employee_id:
        db.map_device_employee(device_id, device_uid, int(employee_id))
        # Optionally mark all pending records for this UID as processed+linked
        if apply_pend:
            db.link_pending_biometric_records(device_id, device_uid, int(employee_id))
        db.add_device_log(device_id, 'map',
                          f'ربط UID {device_uid} بالموظف {employee_id}', success=1)
        db.log_audit('device', 'device_map', device_id,
                     f'ربط {device_uid} بالموظف {employee_id}')
        flash('تم ربط المستخدم بالموظف', 'success')
    else:
        flash('بيانات غير مكتملة', 'error')
    # Return to whichever page made the request
    ref = request.referrer or ''
    if 'mapping' in ref:
        return redirect(url_for('device_mapping', device_id=device_id))
    return redirect(url_for('device_attendance', device_id=device_id))

@app.route('/device/<int:device_id>/sync-users', methods=['POST'])
@login_required
def device_sync_users(device_id):
    import os, sys
    from datetime import datetime
    sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
    from zkteco_device import ZKDevice

    device = db.get_device(device_id)
    if not device:
        return jsonify({'ok': False, 'error': 'Device not found'}), 404
    zk = ZKDevice(device['ip_address'], int(device['port']))
    if not zk.connect():
        return jsonify({'ok': False, 'error': 'Connection failed'}), 400
    try:
        users = zk.get_user_list()
        synced = 0
        created = 0
        for user in users:
            existing_map = db.get_employee_by_device_uid(device_id, user['uid'])
            if existing_map:
                synced += 1
                continue
            emp = db.find_candidate_employee_for_uid(user['uid'])
            if emp:
                db.map_device_employee(device_id, user['uid'], emp['id'])
                synced += 1
            else:
                new_id = db.add_employee({
                    'emp_code': user['uid'],
                    'name': user['name'],
                    'position': '',
                    'department_id': 1,
                    'phone': '',
                    'email': '',
                    'hire_date': datetime.now().strftime('%Y-%m-%d'),
                    'pay_type': 'monthly',
                    'base_salary': 0,
                    'daily_rate': 0,
                    'hourly_rate': 0,
                })
                db.map_device_employee(device_id, user['uid'], new_id)
                created += 1
        zk.disconnect()
        db.add_device_log(device_id, 'sync_users', 'مزامنة: ' + str(synced) + ' مرتبط، ' + str(created) + ' جديد', records_count=len(users), success=1)
        db.log_audit('device', 'device_sync_users', device_id, 'مزامنة ' + str(len(users)) + ' مستخدم')
        return jsonify({'ok': True, 'synced': synced, 'created': created, 'total': len(users)})
    except Exception as e:
        zk.disconnect()
        return jsonify({'ok': False, 'error': str(e)}), 500

@app.route('/device/<int:device_id>/apply-attendance', methods=['POST'])
@login_required
@admin_required
def device_apply_attendance(device_id):
    device = db.get_device(device_id)
    if not device:
        return jsonify({'ok': False, 'error': 'Device not found'}), 404
    month = request.form.get('month', datetime.now().strftime('%Y-%m'))
    overwrite = request.form.get('overwrite', 'false') == 'true'
    result = db.apply_biometric_attendance_to_payroll(device_id, month, overwrite)
    db.add_device_log(device_id, 'apply', 'تطبيق الحضور شهر ' + month + ': ' + str(result['applied']) + ' مطبق', records_count=result['applied'], success=1)
    db.log_audit('device', 'device_apply_attendance', device_id, 'تطبيق حضور شهر ' + month + ': ' + str(result['applied']) + ' سجل')
    return jsonify({
        'ok': True,
        'applied': result['applied'],
        'skipped': result['skipped'],
        'message': 'تم تطبيق ' + str(result['applied']) + ' سجل، تم تخطي ' + str(result['skipped']) + ' سجل'
    })

@app.route('/device/<int:device_id>/logs')
@login_required
def device_logs(device_id):
    device = db.get_device(device_id)
    if not device:
        flash('الجهاز غير موجود', 'error')
        return redirect(url_for('devices'))
    action    = request.args.get('action', '')
    success_f = request.args.get('success', '')
    logs = db.get_device_logs(
        device_id=device_id,
        action=action or None,
        success=int(success_f) if success_f != '' else None,
        limit=200)
    return render_template('device_logs.html', device=device, logs=logs)

@app.route('/device/<int:device_id>/status', methods=['GET'])
@login_required
def device_status_detail(device_id):
    device = db.get_device(device_id)
    if not device:
        return jsonify({'ok': False, 'error': 'Device not found'}), 404
    return jsonify({
        'ok': True,
        'device_id': device_id,
        'name': device['name'],
        'ip_address': device['ip_address'],
        'port': device['port'],
        'status': device['status'],
        'last_sync': device['last_sync'],
        'total_records': device['total_records'],
        'unprocessed_count': db.get_unprocessed_attendance_count(device_id),
        'mapped_employees': len(db.get_device_employees(device_id))
    })

# ==================== DEVICE — EXTRA ROUTES (New) ====================

@app.route('/device/<int:device_id>/detail')
@login_required
def device_detail(device_id):
    device = db.get_device(device_id)
    if not device:
        flash('الجهاز غير موجود', 'error')
        return redirect(url_for('devices'))
    recent_records  = db.get_biometric_attendance(device_id=device_id, limit=20)
    recent_logs     = db.get_device_logs(device_id=device_id, limit=10)
    today           = datetime.now().strftime('%Y-%m-%d')
    today_count     = db.get_biometric_attendance_count(device_id=device_id, date=today)
    total_records   = db.get_biometric_attendance_count(device_id=device_id)
    unprocessed_count = db.get_unprocessed_attendance_count(device_id)
    mapped_count    = len(db.get_device_employees(device_id))
    return render_template('device_detail.html',
                           device=device,
                           recent_records=recent_records,
                           recent_logs=recent_logs,
                           today_count=today_count,
                           total_records=total_records,
                           unprocessed_count=unprocessed_count,
                           mapped_count=mapped_count,
                           now=datetime.now())

@app.route('/device/<int:device_id>/mapping')
@login_required
def device_mapping(device_id):
    device = db.get_device(device_id)
    if not device:
        flash('الجهاز غير موجود', 'error')
        return redirect(url_for('devices'))
    mappings        = db.get_device_employees_extended(device_id)
    all_employees   = db.get_employees(status='active')
    unmapped_uids   = db.get_unmapped_device_uids(device_id)
    # suggest employee by smart match (emp_code or id or EMP001...)
    for u in unmapped_uids:
        u['suggested_emp'] = db.find_candidate_employee_for_uid(u['device_uid'])
    return render_template('device_mapping.html',
                           device=device,
                           mappings=mappings,
                           all_employees=all_employees,
                           unmapped_uids=unmapped_uids)

@app.route('/device/<int:device_id>/unmap-employee', methods=['POST'])
@login_required
@admin_required
def device_unmap_employee(device_id):
    device_uid = request.form.get('device_uid')
    if device_uid:
        db.unmap_device_employee(device_id, device_uid)
        db.add_device_log(device_id, 'unmap', f'إزالة ربط UID: {device_uid}', success=1)
        db.log_audit('device', 'device_unmap', device_id, f'إزالة ربط {device_uid}')
        flash('تم إزالة الربط', 'success')
    return redirect(url_for('device_mapping', device_id=device_id))

@app.route('/device/test-ping', methods=['POST'])
@login_required
def device_test_ping():
    """Quick connection test without saving anything."""
    import os, sys
    sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
    from zkteco_device import ZKDevice
    ip   = request.form.get('ip', '').strip()
    port = int(request.form.get('port', 4370) or 4370)
    if not ip:
        return jsonify({'ok': False, 'message': 'عنوان IP مطلوب'})
    zk = ZKDevice(ip, port, timeout=4)
    ok, lat, msg = zk.test_connection()
    return jsonify({'ok': ok, 'latency_ms': lat, 'message': msg})

@app.route('/device/<int:device_id>/sync-time', methods=['POST'])
@login_required
def device_sync_time(device_id):
    import os, sys
    sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
    from zkteco_device import ZKDevice
    device = db.get_device(device_id)
    if not device:
        return jsonify({'ok': False, 'error': 'Device not found'}), 404
    zk = ZKDevice(device['ip_address'], int(device['port']), timeout=5)
    if not zk.connect():
        db.update_device_status(device_id, 'connection_failed')
        db.add_device_log(device_id, 'sync_time', 'فشل الاتصال لمزامنة الوقت', success=0,
                          error_message='Connection failed')
        return jsonify({'ok': False, 'error': 'Connection failed'}), 400
    try:
        now = datetime.now()
        ok  = zk.sync_time(now)
        zk.disconnect()
        if ok:
            db.add_device_log(device_id, 'sync_time',
                              f'مزامنة التوقيت: {now.strftime("%Y-%m-%d %H:%M:%S")}', success=1)
            db.log_audit('device', 'device_sync_time', device_id, 'مزامنة وقت الجهاز')
            return jsonify({'ok': True, 'message': f'تم مزامنة توقيت الجهاز: {now.strftime("%Y-%m-%d %H:%M:%S")}'})
        return jsonify({'ok': False, 'error': 'فشلت مزامنة الوقت'}), 400
    except Exception as e:
        zk.disconnect()
        return jsonify({'ok': False, 'error': str(e)}), 500

@app.route('/device/<int:device_id>/clear-attendance', methods=['POST'])
@login_required
@admin_required
def device_clear_attendance(device_id):
    import os, sys
    sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
    from zkteco_device import ZKDevice
    device = db.get_device(device_id)
    if not device:
        return jsonify({'ok': False, 'error': 'Device not found'}), 404
    zk = ZKDevice(device['ip_address'], int(device['port']), timeout=5)
    if not zk.connect():
        return jsonify({'ok': False, 'error': 'Connection failed'}), 400
    try:
        ok = zk.clear_attendance()
        zk.disconnect()
        if ok:
            db.add_device_log(device_id, 'clear', 'مسح سجلات الحضور من الجهاز', success=1)
            db.log_audit('device', 'device_clear_att', device_id, 'مسح سجلات الجهاز')
            return jsonify({'ok': True, 'message': 'تم مسح سجلات الحضور من الجهاز'})
        return jsonify({'ok': False, 'error': 'فشل المسح'}), 400
    except Exception as e:
        zk.disconnect()
        return jsonify({'ok': False, 'error': str(e)}), 500

@app.route('/device/<int:device_id>/restart', methods=['POST'])
@login_required
@admin_required
def device_restart(device_id):
    import os, sys
    sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
    from zkteco_device import ZKDevice
    device = db.get_device(device_id)
    if not device:
        return jsonify({'ok': False, 'error': 'Device not found'}), 404
    zk = ZKDevice(device['ip_address'], int(device['port']), timeout=5)
    if not zk.connect():
        return jsonify({'ok': False, 'error': 'Connection failed'}), 400
    try:
        zk.restart_device()
        zk.disconnect()
        db.add_device_log(device_id, 'restart', 'إعادة تشغيل الجهاز', success=1)
        db.log_audit('device', 'device_restart', device_id, 'إعادة تشغيل الجهاز')
        return jsonify({'ok': True, 'message': 'تم إرسال أمر إعادة التشغيل'})
    except Exception as e:
        zk.disconnect()
        return jsonify({'ok': False, 'error': str(e)}), 500

@app.route('/device/<int:device_id>/bulk-process', methods=['POST'])
@login_required
@admin_required
def device_bulk_process(device_id):
    """Mark all pending (processed=0) biometric records as processed=1 for mapped employees."""
    result = db.bulk_process_biometric_attendance(device_id)
    db.add_device_log(device_id, 'bulk_process',
                      f'معالجة {result["processed"]} سجل', records_count=result['processed'], success=1)
    return jsonify({'ok': True, 'processed': result['processed'],
                    'message': f'تم معالجة {result["processed"]} سجل'})

@app.route('/devices/global-logs')
@login_required
def device_global_logs():
    all_devices = db.get_devices(active_only=False)
    dev_id      = request.args.get('device_id', '')
    action      = request.args.get('action', '')
    success_f   = request.args.get('success', '')
    logs = db.get_device_logs(
        device_id=int(dev_id) if dev_id else None,
        action=action or None,
        success=int(success_f) if success_f != '' else None,
        limit=500)
    return render_template('device_logs.html',
                           device=None,
                           logs=logs,
                           all_devices=all_devices)

@app.route('/devices/global-attendance')
@login_required
def device_global_attendance():
    all_devices = db.get_devices(active_only=False)
    dev_id      = request.args.get('device_id', '')
    date_from   = request.args.get('date_from', '')
    date_to     = request.args.get('date_to', '')
    processed_s = request.args.get('processed', '')
    processed   = int(processed_s) if processed_s != '' else None
    records = db.get_biometric_attendance(
        device_id=int(dev_id) if dev_id else None,
        processed=processed,
        date_from=date_from or None,
        date_to=date_to or None,
        limit=2000)
    return render_template('device_global_attendance.html',
                           records=records,
                           all_devices=all_devices,
                           date_from=date_from,
                           date_to=date_to,
                           now=datetime.now())

# ==================== BACKUP (نسخ احتياطي) ====================
@app.route('/settings/backup', methods=['POST'])
@admin_required
@csrf_required
def backup_create():
    try:
        path, when = db.create_backup()
        db.log_audit('backup', 'system', None, f'نسخة احتياطية يدوية {when}')
        flash(f'تم إنشاء النسخة الاحتياطية', 'success')
    except Exception as e:
        flash(f'فشل إنشاء النسخة الاحتياطية: {e}', 'error')
    return redirect(url_for('settings'))

@app.route('/settings/backups/<path:filename>/restore', methods=['POST'])
@admin_required
@csrf_required
def backup_restore(filename):
    try:
        db.restore_backup(filename)
        db.log_audit('restore', 'system', None, f'استعادة نسخة احتياطية {filename}')
        flash('تمت الاستعادة بنجاح. تم تسجيل الخروج من الجلسة.', 'success')
        session.clear()
        return redirect(url_for('login'))
    except Exception as e:
        flash(f'فشل الاستعادة: {e}', 'error')
        return redirect(url_for('settings'))

@app.route('/settings/backups/<path:filename>/delete', methods=['POST'])
@admin_required
@csrf_required
def backup_delete(filename):
    if db.delete_backup(filename):
        db.log_audit('backup_delete', 'system', None, f'حذف نسخة احتياطية {filename}')
        flash('تم حذف النسخة الاحتياطية', 'success')
    else:
        flash('تعذر حذف النسخة الاحتياطية', 'error')
    return redirect(url_for('settings'))

@app.route('/settings/backups/<path:filename>/download')
@admin_required
def backup_download(filename):
    if not (filename.startswith('backup_') and filename.endswith('.db')):
        abort(404)
    p = os.path.join(os.path.join(DATA_DIR, 'backups'), filename)
    if not os.path.isfile(p):
        abort(404)
    with open(p, 'rb') as f:
        data = f.read()
    return send_file(io.BytesIO(data), as_attachment=True, download_name=filename,
                     mimetype='application/octet-stream')

# ==================== MOBILE ATTENDANCE (FACE RECOGNITION + GPS) ====================
def is_gps_location_required(fps_settings):
    """التحقق مما إذا كان تفعيل نظام GPS أو فرض الموقع إلزامياً"""
    if not fps_settings:
        return False
    loc_req = fps_settings.get('location_required')
    gps_req = fps_settings.get('gps_required')
    gps_ena = fps_settings.get('gps_enabled')
    return any(str(x).lower() in ('1', 'true', 'on', 'yes') for x in (loc_req, gps_req, gps_ena))

@app.route('/mobile/login', methods=['GET', 'POST'])
def mobile_login():
    fps_settings = db.get_fps_settings()
    settings = db.get_settings()
    val = fps_settings.get('mobile_login_enabled')
    if val is None:
        val = settings.get('mobile_login_enabled')
    is_enabled = str(val).lower() in ('1', 'true', 'on', 'yes')
    if not is_enabled:
        flash('تسجيل الدخول عبر الهاتف غير مفعل', 'error')
        return redirect(url_for('login'))

    is_loc_req = is_gps_location_required(fps_settings)

    if request.method == 'POST':
        username = (request.form.get('username') or '').strip()
        password = request.form.get('password') or ''
        lat = request.form.get('lat')
        lng = request.form.get('lng')

        # التحقق الإلزامي من الموقع الجغرافي عند تسجيل الدخول
        if is_loc_req:
            if not lat or not lng:
                flash('فشل في تحديد الموقع. يرجى تمكين GPS والموافقة على مشاركة الموقع لتسجيل الدخول', 'error')
                return render_template('mobile_login.html', fps_settings=fps_settings, is_location_required=is_loc_req)

            company_lat = fps_settings.get('company_lat')
            company_lng = fps_settings.get('company_lng')
            tolerance = float(fps_settings.get('distance_tolerance') or 50.0)
            if company_lat and company_lng:
                try:
                    dist = db.calculate_distance(float(lat), float(lng), float(company_lat), float(company_lng))
                    if dist > tolerance:
                        flash(f'لا يمكن تسجيل الدخول: أنت خارج نطاق مقر العمل ({dist:.0f}م). الحد المسموح به {tolerance:.0f}م', 'error')
                        return render_template('mobile_login.html', fps_settings=fps_settings, is_location_required=is_loc_req)
                except Exception:
                    flash('خطأ في معالجة إحداثيات الموقع الجغرافي', 'error')
                    return render_template('mobile_login.html', fps_settings=fps_settings, is_location_required=is_loc_req)

        emp = db.get_employee_by_code(username) or db.get_employee_by_national_id(username)
        if not emp:
            flash('بيانات الدخول غير صحيحة', 'error')
            return render_template('mobile_login.html', fps_settings=fps_settings, is_location_required=is_loc_req)

        session['user_id'] = emp['id']
        session['username'] = emp['emp_code']
        session['role'] = 'user'
        session['employee_id'] = emp['id']
        session['csrf'] = secrets.token_hex(32)
        db.log_audit('mobile_login', 'login', emp['id'], 'تسجيل دخول عبر الهاتف')
        flash(f'مرحباً {emp["name"]}', 'success')
        return redirect(url_for('mobile_attendance'))

    return render_template('mobile_login.html', fps_settings=fps_settings, is_location_required=is_loc_req)

@app.route('/mobile/attendance', methods=['GET', 'POST'])
def mobile_attendance():
    if 'user_id' not in session or not session.get('employee_id'):
        return redirect(url_for('mobile_login'))

    fps_settings = db.get_fps_settings()
    emp = db.get_employee(session['employee_id'])
    if not emp:
        flash('حساب الموظف غير موجود', 'error')
        return redirect(url_for('mobile_login'))

    is_loc_req = is_gps_location_required(fps_settings)
    today = datetime.now().strftime('%Y-%m-%d')
    existing = db.get_attendance_detail(emp['id'], today)
    if existing and not isinstance(existing, dict):
        existing = dict(existing)

    if request.method == 'POST':
        attendance_type = request.form.get('attendance_type', 'check_in')
        lat = request.form.get('lat')
        lng = request.form.get('lng')
        gps_consent = request.form.get('gps_consent')

        if is_loc_req:
            if not gps_consent:
                flash('يجب الموافقة على مشاركة الموقع لتسجيل الحضور والانصراف', 'error')
                return render_template('mobile_attendance.html', emp=emp, fps_settings=fps_settings, attendance=existing, is_location_required=is_loc_req)
            if not lat or not lng:
                flash('فشل في تحديد الموقع. يرجى تمكين GPS والموافقة على مشاركة الموقع لتسجيل الحضور والانصراف', 'error')
                return render_template('mobile_attendance.html', emp=emp, fps_settings=fps_settings, attendance=existing, is_location_required=is_loc_req)
            company_lat = fps_settings.get('company_lat')
            company_lng = fps_settings.get('company_lng')
            tolerance = float(fps_settings.get('distance_tolerance') or 50.0)
            if company_lat and company_lng:
                try:
                    dist = db.calculate_distance(float(lat), float(lng), float(company_lat), float(company_lng))
                    if dist > tolerance:
                        flash(f'لا يمكن تسجيل العملية: أنت خارج نطاق مقر العمل ({dist:.0f}م). الحد المسموح به {tolerance:.0f}م', 'error')
                        return render_template('mobile_attendance.html', emp=emp, fps_settings=fps_settings, attendance=existing, is_location_required=is_loc_req)
                except Exception:
                    flash('خطأ في قراءة إحداثيات الموقع الجغرافي', 'error')
                    return render_template('mobile_attendance.html', emp=emp, fps_settings=fps_settings, attendance=existing, is_location_required=is_loc_req)

        now_time = datetime.now().strftime('%H:%M:%S')
        month = today[:7]

        if attendance_type == 'check_in':
            if existing and existing.get('check_in'):
                flash('تم تسجيل الحضور مسبقاً اليوم', 'warning')
            else:
                db.bulk_save_attendance(month, [{
                    'employee_id': emp['id'],
                    'date': today,
                    'check_in': now_time,
                    'check_out': (existing.get('check_out') if existing else ''),
                    'status': 'present',
                    'source': 'mobile',
                    'lat': lat,
                    'lng': lng,
                    'note': 'تسجيل حضور عبر الهاتف'
                }])
                db.log_audit('mobile_attendance', 'check_in', emp['id'], f'تسجيل حضور في {now_time}')
                flash('تم تسجيل الحضور بنجاح', 'success')
        else:
            if not existing or not existing.get('check_in'):
                flash('يجب تسجيل الحضور أولاً قبل الانصراف', 'error')
            elif existing.get('check_out'):
                flash('تم تسجيل الانصراف مسبقاً اليوم', 'warning')
            else:
                db.bulk_save_attendance(month, [{
                    'employee_id': emp['id'],
                    'date': today,
                    'check_in': existing.get('check_in', ''),
                    'check_out': now_time,
                    'status': 'present',
                    'source': 'mobile',
                    'lat': lat,
                    'lng': lng,
                    'note': 'تسجيل انصراف عبر الهاتف'
                }])
                db.log_audit('mobile_attendance', 'check_out', emp['id'], f'تسجيل انصراف في {now_time}')
                flash('تم تسجيل الانصراف بنجاح', 'success')

        return redirect(url_for('mobile_attendance'))

    return render_template('mobile_attendance.html', emp=emp, fps_settings=fps_settings, attendance=existing, is_location_required=is_loc_req)

@app.route('/api/mobile/verify-location', methods=['POST'])
def api_verify_location():
    data = request.get_json(silent=True) or request.form.to_dict() or {}
    lat = data.get('lat')
    lng = data.get('lng')
    if not lat or not lng:
        return jsonify({'ok': False, 'error': 'الإحداثيات مطلوبة'}), 400
    fps_settings = db.get_fps_settings()
    company_lat = fps_settings.get('company_lat')
    company_lng = fps_settings.get('company_lng')
    tolerance = float(fps_settings.get('distance_tolerance') or 50.0)
    if not company_lat or not company_lng:
        return jsonify({'ok': False, 'error': 'إحداثيات الشركة غير محددة'}), 400
    try:
        dist = db.calculate_distance(float(lat), float(lng), float(company_lat), float(company_lng))
        inside = dist <= tolerance
        return jsonify({
            'ok': True,
            'inside': inside,
            'distance': round(dist, 1),
            'tolerance': tolerance,
            'message': f'داخل نطاق مقر العمل ({dist:.0f}م)' if inside else f'خارج نطاق مقر العمل ({dist:.0f}م - الحد المسموح {tolerance:.0f}م)'
        })
    except Exception as e:
        return jsonify({'ok': False, 'error': str(e)}), 400

def compare_face_images(b64_1, b64_2, threshold=0.55):
    """
    مقارنة صورتي وجه عبر التحليل البصري التوزيعي ومعامل الارتباط (Pearson Correlation + Pixel MAE).
    يرجع (تطابق: bool, نسبة التطابق: float).
    """
    if not b64_1 or not b64_2:
        return False, 0.0
    if b64_1 == b64_2:
        return True, 1.0
    try:
        import math
        def decode_image_vector(b):
            if ',' in b:
                b = b.split(',', 1)[1]
            data = base64.b64decode(b)
            img = PILImage.open(io.BytesIO(data)).convert('L')
            img = img.resize((32, 32), PILImage.Resampling.LANCZOS)
            return [p / 255.0 for p in list(img.tobytes())]

        v1 = decode_image_vector(b64_1)
        v2 = decode_image_vector(b64_2)

        mean1 = sum(v1) / len(v1)
        mean2 = sum(v2) / len(v2)
        dev1 = [x - mean1 for x in v1]
        dev2 = [y - mean2 for y in v2]
        num = sum(a * b for a, b in zip(dev1, dev2))
        den1 = math.sqrt(sum(a * a for a in dev1))
        den2 = math.sqrt(sum(b * b for b in dev2))
        if den1 < 1e-4 or den2 < 1e-4:
            return False, 0.0

        corr = max(0.0, num / (den1 * den2))
        mae = sum(abs(a - b) for a, b in zip(v1, v2)) / len(v1)
        mae_sim = 1.0 - mae

        # دمج الارتباط النمطي (التعابير والملامح) مع تطابق السطوع
        score = (corr * 0.7) + (mae_sim * 0.3)
        return (score >= threshold), round(score, 3)
    except Exception as e:
        print('خطأ في مقارنة بصمات الوجه:', e)
        return False, 0.0

@app.route('/mobile/face-login', methods=['POST'])
def mobile_face_login():
    fps_settings = db.get_fps_settings()
    settings = db.get_settings()
    val = fps_settings.get('mobile_login_enabled')
    if val is None:
        val = settings.get('mobile_login_enabled')
    if not str(val).lower() in ('1', 'true', 'on', 'yes'):
        return jsonify({'ok': False, 'error': 'تسجيل الدخول عبر الهاتف غير مفعل'}), 403

    data = request.get_json(silent=True) or request.form.to_dict() or {}
    face_data = data.get('face_data')
    if not face_data:
        return jsonify({'ok': False, 'error': 'بيانات الوجه مطلوبة'}), 400

    threshold = float(fps_settings.get('fps_threshold') or 0.55)

    # 1. إذا كان الموظف مسجل دخول بالفعل ويريد حفظ/تحديث بصمة وجهه
    if 'employee_id' in session:
        emp = db.get_employee(session['employee_id'])
        if not emp:
            return jsonify({'ok': False, 'error': 'الموظف غير موجود'}), 404
        db.update_employee_face(emp['id'], face_data)
        db.log_audit('face_enroll', 'employee', emp['id'], f'تسجيل/تحديث بصمة الوجه عبر الهاتف: {emp["name"]}')
        return jsonify({'ok': True, 'message': f'تم حفظ وتسجيل بصمة الوجه بنجاح للموظف {emp["name"]}!'})

    # 2. محاولة تسجيل دخول ببصمة الوجه
    # التحقق الإلزامي من الموقع الجغرافي عند تسجيل الدخول بالوجه
    if is_gps_location_required(fps_settings):
        lat = data.get('lat')
        lng = data.get('lng')
        if not lat or not lng:
            return jsonify({'ok': False, 'error': 'فشل في تحديد الموقع. يرجى تمكين GPS والموافقة على مشاركة الموقع لتسجيل الدخول'}), 400
        company_lat = fps_settings.get('company_lat')
        company_lng = fps_settings.get('company_lng')
        tolerance = float(fps_settings.get('distance_tolerance') or 50.0)
        if company_lat and company_lng:
            try:
                dist = db.calculate_distance(float(lat), float(lng), float(company_lat), float(company_lng))
                if dist > tolerance:
                    return jsonify({'ok': False, 'error': f'لا يمكن تسجيل الدخول: أنت خارج نطاق مقر العمل ({dist:.0f}م). الحد المسموح به {tolerance:.0f}م'}), 403
            except Exception:
                return jsonify({'ok': False, 'error': 'خطأ في معالجة إحداثيات الموقع الجغرافي'}), 400

    username = (data.get('username') or '').strip()
    password = data.get('password') or ''
    emp = None

    if username:
        emp = db.get_employee_by_code(username) or db.get_employee_by_national_id(username)
        if not emp:
            return jsonify({'ok': False, 'error': f'لم يتم العثور على موظف برقم/كود: {username}'}), 404

        stored_face = emp.get('face_data')
        if stored_face:
            # مقارنة الوجه بالصورة المخزنة
            match, sim = compare_face_images(stored_face, face_data, threshold=threshold)
            if not match:
                return jsonify({'ok': False, 'error': f'تعذر التعرف على الوجه. نسبة التطابق ({sim*100:.0f}%) أقل من المسموح'}), 401
        else:
            # الموظف لا يملك صورة مخزنة بعد
            # إذا أدخل كلمة المرور أو الكود نعتمد تسجيل بصمة الوجه لأول مرة
            if password or not emp.get('national_id'):
                db.update_employee_face(emp['id'], face_data)
                db.log_audit('face_enroll', 'employee', emp['id'], f'تسجيل بصمة الوجه لأول مرة: {emp["name"]}')
            else:
                return jsonify({
                    'ok': False,
                    'need_enroll': True,
                    'error': 'لا توجد بصمة وجه مسجلة لهذا الموظف بعد. يرجى إدخال كلمة المرور مع التقاط الصورة لحفظها لأول مرة، أو الدخول أولاً بكود الموظف.'
                }), 400
    else:
        # لم يدخل كوداً: البحث بين جميع الموظفين الذين لديهم صور مسجلة
        candidates = [e for e in db.get_employees(status='active') if e.get('face_data')]
        best_emp = None
        best_sim = 0.0
        for e in candidates:
            match, sim = compare_face_images(e['face_data'], face_data, threshold=threshold)
            if match and sim > best_sim:
                best_sim = sim
                best_emp = e

        if not best_emp:
            return jsonify({'ok': False, 'error': 'لم يتم التعرف على الوجه. يرجى إدخال الكود الوظيفي'}), 401
        emp = best_emp

    # تسجيل الدخول بنجاح
    session['user_id'] = emp['id']
    session['username'] = emp['emp_code']
    session['role'] = 'user'
    session['employee_id'] = emp['id']
    session['csrf'] = secrets.token_hex(32)
    db.log_audit('mobile_face_login', 'face_auth', emp['id'], f'تسجيل دخول ناجح ببصمة الوجه: {emp["name"]}')
    return jsonify({
        'ok': True,
        'message': f'تم التحقق من الوجه بنجاح - مرحباً {emp["name"]}',
        'redirect': url_for('mobile_attendance')
    })

@app.route('/mobile/logout')
def mobile_logout():
    session.clear()
    flash('تم تسجيل الخروج', 'success')
    return redirect(url_for('mobile_login'))

# ==================== MOBILE VIEWS FOR LOGGED-IN EMPLOYEE ====================
@app.route('/mobile/records')
def mobile_records():
    if 'user_id' not in session or not session.get('employee_id'):
        return redirect(url_for('mobile_login'))
    emp_id = session['employee_id']
    emp = db.get_employee(emp_id)
    if not emp:
        flash('حساب الموظف غير موجود', 'error')
        return redirect(url_for('mobile_login'))

    month = request.args.get('month', datetime.now().strftime('%Y-%m'))
    status_filter = request.args.get('status', 'all')
    date_from = request.args.get('date_from', '')
    date_to = request.args.get('date_to', '')

    records = db.get_employee_attendance(emp_id, month=month if not (date_from or date_to) else None,
                                        date_from=date_from or None, date_to=date_to or None,
                                        status=status_filter)

    total_present = sum(1 for r in records if r.get('status') == 'present' or (r.get('check_in') and r.get('status') != 'absent'))
    total_absent = sum(1 for r in records if r.get('status') == 'absent')
    total_late = sum(1 for r in records if r.get('status') == 'late')
    total_leave = sum(1 for r in records if r.get('status') in ('leave', 'sick', 'annual'))

    stats = {
        'total': len(records),
        'present': total_present,
        'absent': total_absent,
        'late': total_late,
        'leave': total_leave
    }

    return render_template('mobile_records.html', emp=emp, records=records, month=month,
                           status_filter=status_filter, date_from=date_from, date_to=date_to,
                           stats=stats)

@app.route('/mobile/calendar')
def mobile_calendar():
    if 'user_id' not in session or not session.get('employee_id'):
        return redirect(url_for('mobile_login'))
    emp_id = session['employee_id']
    emp = db.get_employee(emp_id)
    if not emp:
        flash('حساب الموظف غير موجود', 'error')
        return redirect(url_for('mobile_login'))

    month = request.args.get('month', datetime.now().strftime('%Y-%m'))
    settings = db.get_settings()

    try:
        y, m = int(month[:4]), int(month[5:7])
        prev_month = (date(y, m, 1) - timedelta(days=1)).strftime('%Y-%m')
        next_month = (date(y, m, 28) + timedelta(days=5)).strftime('%Y-%m')
    except Exception:
        prev_month = month
        next_month = month

    records = db.get_employee_attendance(emp_id, month=month)
    records_by_date = {r['date']: r for r in records}
    weeks = _month_calendar(month, records_by_date, settings)

    return render_template('mobile_calendar.html', emp=emp, month=month, prev_month=prev_month,
                           next_month=next_month, weeks=weeks, settings=settings)

@app.route('/mobile/payslip')
def mobile_payslip():
    if 'user_id' not in session or not session.get('employee_id'):
        return redirect(url_for('mobile_login'))
    emp_id = session['employee_id']
    emp = db.get_employee(emp_id)
    if not emp:
        flash('حساب الموظف غير موجود', 'error')
        return redirect(url_for('mobile_login'))

    month = request.args.get('month', datetime.now().strftime('%Y-%m'))
    settings = db.get_settings()

    try:
        y, m = int(month[:4]), int(month[5:7])
        prev_month = (date(y, m, 1) - timedelta(days=1)).strftime('%Y-%m')
        next_month = (date(y, m, 28) + timedelta(days=5)).strftime('%Y-%m')
    except Exception:
        prev_month = month
        next_month = month

    calc = db.calculate_payroll(month)
    record = next((r for r in calc if r['employee_id'] == emp_id), None)
    signed = db.has_signed(emp_id, month)

    return render_template('mobile_payslip.html', emp=emp, rec=record, month=month,
                           prev_month=prev_month, next_month=next_month, settings=settings,
                           signed=signed)

@app.route('/mobile/payslip/pdf')
def mobile_payslip_pdf():
    if 'user_id' not in session or not session.get('employee_id'):
        return redirect(url_for('mobile_login'))
    emp_id = session['employee_id']
    emp = db.get_employee(emp_id)
    if not emp:
        abort(404)
    month = request.args.get('month', datetime.now().strftime('%Y-%m'))
    calc = db.calculate_payroll(month)
    record = next((r for r in calc if r['employee_id'] == emp_id), None)
    settings = db.get_settings()
    return _build_payslip_pdf(emp, record, month, settings)

@app.route('/mobile/payslip/sign', methods=['POST'])
def mobile_payslip_sign():
    if 'user_id' not in session or not session.get('employee_id'):
        return redirect(url_for('mobile_login'))
    emp_id = session['employee_id']
    month = request.form.get('month', datetime.now().strftime('%Y-%m'))
    emp = db.get_employee(emp_id)
    if not emp:
        abort(404)
    calc = db.calculate_payroll(month)
    record = next((r for r in calc if r['employee_id'] == emp_id), None)
    if not record:
        flash('لا توجد بيانات مرتب لهذا الشهر', 'error')
        return redirect(url_for('mobile_payslip', month=month))
    sig = request.form.get('signature_text') or emp['name']
    db.sign_payroll(emp_id, month, f"SLIP-{emp_id}-{month}", record['gross'], record['net'],
                    sig, request.remote_addr or '', request.form.get('notes', 'توقيع إلكتروني عبر الهاتف'))
    db.log_audit('sign', 'payslip', emp_id, f'توقيع استلام راتب عبر الهاتف شهر {month}')
    flash('تم تسجيل توقيعك على استلام المرتب بنجاح', 'success')
    return redirect(url_for('mobile_payslip', month=month))

@app.route('/users')
@admin_required
def users():
    all = db.get_all_users()
    return render_template('users.html', users=all)

@app.route('/users/add', methods=['GET', 'POST'])
@admin_required
@csrf_required
def add_user():
    if request.method == 'GET':
        return redirect(url_for('users'))
    u = request.form.to_dict()
    if len(u.get('password','')) < 8:
        flash('كلمة المرور يجب أن تكون 8 أحرف على الأقل', 'error')
        return redirect(url_for('users'))
    # تحقق من صلاحية صالحة فقط
    valid_roles = ('admin','supervisor','user','viewer')
    role = u.get('role','user')
    if role not in valid_roles:
        role = 'user'
    u['role'] = role
    try:
        db.add_user(u)
        db.log_audit('add', 'user', None, f'إضافة مستخدم: {u.get("username")} ({role})')
        flash('تم إضافة المستخدم', 'success')
    except Exception:
        flash('اسم المستخدم موجود بالفعل', 'error')
    return redirect(url_for('users'))

@app.route('/users/<int:uid>/toggle', methods=['POST'])
@admin_required
@csrf_required
def toggle_user(uid):
    if uid == session.get('user_id'):
        flash('لا يمكنك تعطيل حسابك', 'error')
    else:
        db.toggle_user(uid)
        db.log_audit('toggle', 'user', uid, 'تفعيل/تعطيل مستخدم')
        flash('تم تحديث حالة المستخدم', 'success')
    return redirect(url_for('users'))

@app.route('/users/<int:uid>/delete', methods=['POST'])
@admin_required
@csrf_required
def delete_user(uid):
    if uid == session.get('user_id'):
        flash('لا يمكنك حذف حسابك', 'error')
    else:
        db.delete_user(uid)
        db.log_audit('delete', 'user', uid, 'حذف مستخدم')
        flash('تم حذف المستخدم', 'success')
    return redirect(url_for('users'))

# ==================== GUIDE (دليل الاستخدام) ====================
@app.route('/guide')
@login_required
def guide():
    return render_template('guide.html')

# ==================== LICENSE (حالة الترخيص) ====================
@app.route('/license')
def license_page():
    # متاحة للجميع عند عدم صلاحية الترخيص (شاشة القفل)، وتحتاج تسجيل دخول عند صلاحية الترخيص
    if LICENSE_OK and 'user_id' not in session:
        flash('يجب تسجيل الدخول أولاً', 'error')
        return redirect(url_for('login'))
    return render_template('license.html', ok=LICENSE_OK, msg=LICENSE_MSG,
                           info=LICENSE_INFO, license_path=lic.LICENSE_FILE)

# ==================== PDF generation ====================
def _build_payslip_pdf(emp, record, month, settings):
    if record is None:
        from flask import abort
        abort(404)
    try:
        from reportlab.pdfgen import canvas
        from reportlab.lib.pagesizes import A4
        from reportlab.pdfbase import pdfmetrics
        from reportlab.pdfbase.ttfonts import TTFont
        from reportlab.lib.utils import ImageReader
        from reportlab.lib.colors import HexColor
        import arabic_reshaper
        from bidi.algorithm import get_display
        from PIL import Image as PILImage
    except Exception as e:
        flash(f'مكتبة PDF غير متوفرة: {e}', 'error')
        return redirect(url_for('payslip', emp_id=emp['id'], month=month))

    # تحميل خط عربي
    font_name = 'Arial'
    font_bold = 'ArialBold'
    font_path = r'C:\Windows\Fonts\arial.ttf'
    font_bold_path = r'C:\Windows\Fonts\arialbd.ttf'
    if not os.path.exists(font_path):
        font_path = os.path.join(BASE_DIR, 'static', 'fonts', 'arial.ttf')
    try:
        pdfmetrics.registerFont(TTFont(font_name, font_path))
        if os.path.exists(font_bold_path):
            try:
                pdfmetrics.registerFont(TTFont(font_bold, font_bold_path))
            except Exception:
                font_bold = font_name
        else:
            font_bold = font_name
    except Exception:
        font_name = 'Helvetica'
        font_bold = 'Helvetica-Bold'

    def ar(text):
        try:
            return get_display(arabic_reshaper.reshape(str(text)))
        except Exception:
            return str(text)

    buf = io.BytesIO()
    c = canvas.Canvas(buf, pagesize=A4)
    W, H = A4
    margin = 40
    cy = H - 45

    def heading(txt, size, y, color=None):
        fnt = font_bold if font_bold in pdfmetrics.getRegisteredFontNames() else font_name
        c.setFont(fnt, size)
        c.setFillColor(color or HexColor('#1e3a5f'))
        c.drawCentredString(W/2, y, ar(txt))
        return y - size - 10

    def row_label_value(label, value, x1, x2, y, size=10):
        c.setFont(font_bold if font_bold in pdfmetrics.getRegisteredFontNames() else font_name, size)
        c.setFillColor(HexColor('#4b5563'))
        c.drawString(x1, y, ar(label))
        c.setFillColor(HexColor('#111827'))
        c.drawRightString(x2, y, ar(value))

    # header company
    if settings.get('company_name'):
        cy = heading(settings['company_name'], 15, cy)
    cy = heading('إيصال استلام المرتب', 13, cy, HexColor('#2563eb'))
    cy -= 4
    c.setStrokeColor(HexColor('#2563eb')); c.setLineWidth(1.2)
    c.line(margin, cy, W-margin, cy)
    cy -= 18

    # slip info
    c.setFont(font_bold if font_bold in pdfmetrics.getRegisteredFontNames() else font_name, 9)
    c.setFillColor(HexColor('#6b7280'))
    c.drawString(margin, cy, ar(f"رقم القسيمة: SLIP-{emp['emp_code']}-{month}    الشهر: {month}"))
    cy -= 18

    # employee data
    c.setFont(font_bold, 10); c.setFillColor(HexColor('#1e3a5f'))
    c.drawString(margin, cy, ar('بيانات الموظف'))
    cy -= 16
    grid_items = [('الاسم', emp['name']), ('الكود', emp['emp_code']), ('القسم', emp.get('dept_name','')),
                  ('الوظيفة', emp['position']), ('نوع الأجر', emp['pay_type']),
                  ('أيام الحضور', f"{int(record.get('present_days', 0))} من {int(record.get('payable_days', 0))} يوم"),
                  ('أيام الغياب', f"{int(record.get('absent_days', 0))} يوم")]
    kw = 2; kws = (W - 2*margin) / (kw*2)
    for i in range(0, len(grid_items), 2):
        row = grid_items[i:i+2]
        x = margin
        for label, val in row:
            row_label_value(label+': ', val, x, x+kws, cy, 9)
            x += kws
        cy -= 16

    cy -= 6

    # earnings
    c.setFont(font_bold, 10); c.setFillColor(HexColor('#1e3a5f'))
    c.drawString(margin, cy, ar('المستحقات'))
    cy -= 14
    c.setFont(font_name, 9); c.setFillColor(HexColor('#111827'))
    def money_line(label, val, y):
        c.drawString(margin+24, y, ar(label))
        c.drawRightString(W-margin, y, ar(f"{val:,.2f} {settings.get('currency','')}"))
    money_line('الأساسي', record['base'], cy); cy -= 14
    money_line('إجمالي البدلات', record['allowances'], cy); cy -= 14
    money_line('الإضافي', record['overtime_amt'], cy); cy -= 14
    money_line('العمولات', record['commissions'], cy); cy -= 14
    c.setFont(font_bold,10); c.setFillColor(HexColor('#16a34a'))
    money_line('إجمالي المستحق', record['gross'], cy); cy -= 18

    # deductions
    c.setFont(font_bold, 10); c.setFillColor(HexColor('#1e3a5f'))
    c.drawString(margin, cy, ar('الخصومات'))
    cy -= 14
    c.setFont(font_name, 9); c.setFillColor(HexColor('#111827'))
    money_line('تأمينات (موظف)', record['si_employee'], cy); cy -= 14
    money_line('ضريبة كسب العمل', record['income_tax'], cy); cy -= 14
    money_line('أقساط سلف', record['advance_installments'], cy); cy -= 14
    money_line(f"خصم غياب ({int(record.get('absent_days', 0))} يوم)", record['absence_deduction'], cy); cy -= 14
    money_line('خصم تأخير', record['late_deduction'], cy); cy -= 14
    money_line('خصومات أخرى', record['other_deductions'], cy); cy -= 14
    c.setFont(font_bold,10); c.setFillColor(HexColor('#dc2626'))
    money_line('إجمالي الخصومات', record['total_deductions'], cy); cy -= 20

    # net salary box
    c.setFillColor(HexColor('#2563eb'))
    c.roundRect(margin, cy-52, W-2*margin, 44, 10, fill=1)
    c.setFillColor(HexColor('#ffffff'))
    c.setFont(font_bold, 11)
    c.drawString(margin+20, cy-22, ar('صافي الراتب المستحق: '))
    c.drawRightString(W-margin-20, cy-22, ar(f"{record['net']:,.2f} {settings.get('currency','')}"))
    cy -= 66

    # signature/stamp area
    c.setStrokeColor(HexColor('#cbd5e1'))
    c.setFont(font_name, 9); c.setFillColor(HexColor('#6b7280'))
    # signature taken?
    try:
        signed = db.has_signed(emp['id'], month)
    except Exception:
        signed = False
    if signed:
        c.drawString(margin, cy, ar('✓ تم التوقيع على الاستلام إلكترونياً'))
    c.drawString(margin, cy-30, ar('توقيع الموظف: ____________'))
    c.drawRightString(W-margin, cy-30, ar('ختم الشركة وتوقيع مسؤول الصرف: ____________'))
    cy -= 55
    c.setFont(font_name, 8); c.setFillColor(HexColor('#9ca3af'))
    c.drawCentredString(W/2, 30, ar('نظام المرتبات الشامل — جميع الحقوق محفوظة © 2026 محاسب / أحمد عبد الله'))

    c.showPage()
    c.save()
    buf.seek(0)
    return send_file(buf, as_attachment=True, download_name=f'قسيمة-مكان-{emp["emp_code"]}-{month}.pdf',
                     mimetype='application/pdf')

def _register_pdf_font():
    """تسجيل خط عربي للـ PDF (مرة واحدة) — يُعيد (الخط الأساسي، الخط العريض)."""
    from reportlab.pdfbase import pdfmetrics
    from reportlab.pdfbase.ttfonts import TTFont
    names = pdfmetrics.getRegisteredFontNames()
    reg, bold = 'ArialPayroll', 'ArialPayrollBold'
    if reg in names:
        return reg, (bold if bold in names else reg)
    path = r'C:\Windows\Fonts\arial.ttf'
    bold_path = r'C:\Windows\Fonts\arialbd.ttf'
    if not os.path.exists(path):
        path = os.path.join(BASE_DIR, 'static', 'fonts', 'arial.ttf')
        bold_path = os.path.join(BASE_DIR, 'static', 'fonts', 'arialbd.ttf')
    try:
        pdfmetrics.registerFont(TTFont(reg, path))
    except Exception:
        return 'Helvetica', 'Helvetica-Bold'
    try:
        if os.path.exists(bold_path):
            pdfmetrics.registerFont(TTFont(bold, bold_path))
        else:
            bold = reg
    except Exception:
        bold = reg
    return reg, bold

def _build_payroll_table_pdf(data, month, settings, title, back_endpoint='payroll'):
    """بناء PDF أفقي (A4) لجدول المرتبات — يُستعمل في حساب المرتبات وكشف المرتبات."""
    if not data:
        flash('لا توجد بيانات مرتبات لهذا الشهر', 'error')
        return redirect(url_for(back_endpoint, month=month))
    try:
        from reportlab.pdfgen import canvas
        from reportlab.lib.pagesizes import A4, landscape
        from reportlab.pdfbase import pdfmetrics
        from reportlab.lib.colors import HexColor, white
        import arabic_reshaper
        from bidi.algorithm import get_display
    except Exception as e:
        flash(f'مكتبة PDF غير متوفرة: {e}', 'error')
        return redirect(url_for(back_endpoint, month=month))

    font_name, font_bold = _register_pdf_font()
    fnt = font_bold if font_bold in pdfmetrics.getRegisteredFontNames() else font_name

    def ar(text):
        s = str(text)
        if not any('\u0600' <= ch <= '\u06FF' for ch in s):
            return s  # نصوص لاتينية/أرقام تبقى كما هي
        try:
            return get_display(arabic_reshaper.reshape(s))
        except Exception:
            return s

    # الأعمدة بترتيب من اليمين إلى اليسار: (العنوان، المفتاح، العرض النسبي، النوع)
    cols = [
        ('م', 'idx', 15, 'text'),
        ('الكود', 'emp_code', 32, 'text'),
        ('الاسم', 'name', 64, 'text'),
        ('القسم', 'dept_name', 42, 'text'),
        ('حضور', 'present_days', 25, 'num'),
        ('غياب', 'absent_days', 25, 'num'),
        ('الأساسي', 'base', 38, 'money'),
        ('البدلات', 'allowances', 38, 'money'),
        ('إضافي', 'overtime_amt', 36, 'money'),
        ('عمولة', 'commissions', 36, 'money'),
        ('المستحق', 'gross', 44, 'money'),
        ('تأمينات', 'si_employee', 38, 'money'),
        ('ضرائب', 'income_tax', 36, 'money'),
        ('سلف', 'advance_installments', 34, 'money'),
        ('خصم غياب', 'absence_deduction', 36, 'money'),
        ('تأخير', 'late_deduction', 34, 'money'),
        ('أخرى', 'other_deductions', 34, 'money'),
        ('الخصومات', 'total_deductions', 44, 'money'),
        ('الصافي', 'net', 48, 'money'),
    ]

    W, H = landscape(A4)
    margin = 20
    usable = W - 2 * margin
    widths = [c[2] * usable / sum(c[2] for c in cols) for c in cols]

    row_h, head_h, footer_h = 13.0, 15.0, 26.0
    head_block = (26 if settings.get('company_name') else 8) + 24 + 14 + 6  # الشركة + العنوان + المعلومات + فاصل
    rows_per_page = max(1, int((H - 2 * margin - head_block - head_h - footer_h) // row_h))

    # صف الإجماليات
    tot = {'_totals': True, 'idx': '', 'emp_code': '', 'name': '', 'dept_name': ''}
    for _l, key, _w, typ in cols:
        if typ in ('num', 'money'):
            tot[key] = sum(float(x.get(key) or 0) for x in data)
    rows = []
    for i, r in enumerate(data, 1):
        rr = dict(r)
        rr['idx'] = i
        rows.append(rr)
    rows.append(tot)
    pages = [rows[i:i + rows_per_page] for i in range(0, len(rows), rows_per_page)]

    blue = HexColor('#1e3a5f'); gray = HexColor('#6b7280'); grid = HexColor('#cbd5e1')
    head_bg = HexColor('#1e3a5f'); alt_bg = HexColor('#f8fafc'); tot_bg = HexColor('#e2e8f0')
    red = HexColor('#dc2626'); dark = HexColor('#111827')

    def fmt(val, typ):
        if typ == 'money':
            return f"{float(val or 0):,.0f}"
        if typ == 'num':
            return str(int(float(val or 0)))
        return str(val or '')

    buf = io.BytesIO()
    c = canvas.Canvas(buf, pagesize=landscape(A4))
    n_pages = len(pages)
    for p_idx, page in enumerate(pages):
        # ---- ترويسة الصفحة ----
        y = H - margin
        if settings.get('company_name'):
            c.setFont(fnt, 13); c.setFillColor(blue)
            c.drawCentredString(W / 2, y - 13, ar(settings['company_name']))
            y -= 26
        c.setFont(fnt, 12); c.setFillColor(blue)
        c.drawCentredString(W / 2, y - 12, ar(f'{title} — شهر {month}'))
        y -= 24
        c.setFont(font_name, 8); c.setFillColor(gray)
        sub = (f"عدد الموظفين: {len(data)} | العملة: {settings.get('currency') or 'ج.م'} | "
               f"تاريخ الإصدار: {datetime.now().strftime('%Y-%m-%d')}")
        c.drawCentredString(W / 2, y - 9, ar(sub))
        y -= 14
        c.setStrokeColor(blue); c.setLineWidth(1)
        c.line(margin, y, W - margin, y)
        y -= 6

        table_top = y
        # ---- رأس الجدول ----
        c.setFillColor(head_bg)
        c.rect(margin, y - head_h, usable, head_h, fill=1, stroke=0)
        x = W - margin
        for (label, key, _w, typ), w in zip(cols, widths):
            c.setFont(fnt, 6.8); c.setFillColor(white)
            c.drawCentredString(x - w / 2, y - head_h + 4.8, ar(label))
            x -= w
        y -= head_h

        # ---- صفوف البيانات ----
        for r_idx, r in enumerate(page):
            is_tot = bool(r.get('_totals'))
            bg = tot_bg if is_tot else (alt_bg if r_idx % 2 else white)
            c.setFillColor(bg)
            c.rect(margin, y - row_h, usable, row_h, fill=1, stroke=0)
            if is_tot:
                span_w = sum(widths[:4])
                c.setFont(fnt, 7); c.setFillColor(blue)
                c.drawCentredString(W - margin - span_w / 2, y - row_h + 4.2, ar('الإجمالي'))
            x = W - margin
            for (label, key, _w, typ), w in zip(cols, widths):
                if is_tot and key in ('idx', 'emp_code', 'name', 'dept_name'):
                    x -= w
                    continue
                val = fmt(r.get(key), typ)
                if val == '':
                    x -= w
                    continue
                is_neg = typ == 'money' and float(r.get(key) or 0) < 0
                if is_tot:
                    c.setFont(fnt, 6.8)
                    c.setFillColor(red if is_neg else blue)
                else:
                    c.setFont(fnt if key == 'name' else font_name, 6.5)
                    c.setFillColor(red if is_neg else dark)
                c.drawRightString(x - 3, y - row_h + 4.2, ar(val))
                x -= w
            c.setStrokeColor(grid); c.setLineWidth(0.4)
            c.line(margin, y - row_h, W - margin, y - row_h)
            y -= row_h
        table_bottom = y

        # ---- حدود الأعمدة والإطار ----
        c.setStrokeColor(grid); c.setLineWidth(0.4)
        xs = [W - margin]
        for w in widths:
            xs.append(xs[-1] - w)
        for xb in xs:
            c.line(xb, table_top, xb, table_bottom)
        c.setLineWidth(0.8)
        c.rect(margin, table_bottom, usable, table_top - table_bottom, fill=0, stroke=1)

        # ---- تذييل الصفحة ----
        c.setFont(font_name, 7.5); c.setFillColor(gray)
        c.drawCentredString(W / 2, margin - 10, ar(f'صفحة {p_idx + 1} من {n_pages}'))
        if p_idx == n_pages - 1:
            si_emp = sum(float(x.get('si_employer') or 0) for x in data)
            c.drawString(margin, margin - 10, ar(f'حصة الشركة في التأمينات: {si_emp:,.0f}'))
            c.drawRightString(W - margin, margin - 10, ar('نظام المرتبات الشامل'))
        c.showPage()
    c.save()
    buf.seek(0)
    return send_file(buf, as_attachment=True, download_name=f'{title}-{month}.pdf',
                     mimetype='application/pdf')

# ==================== Helpers ====================
def _num(v, default=0):
    try:
        return float(str(v or '0').replace(',', '').strip() or '0')
    except Exception:
        return default

# ==================== RUN ====================
import webbrowser, threading

# ==================== ورقة Excel فخمة (تصدير موحّد) ====================
_HEADER_FILL = PatternFill('solid', fgColor='1F3864')     # أزرق داكن
_HEADER_FONT = Font(bold=True, color='FFFFFF', size=11)
_ALT_FILL = PatternFill('solid', fgColor='DCE6F1')         # تظليل بديل فاتح
_TOT_FILL = PatternFill('solid', fgColor='FFE699')         # خبرة الإجمالي أصفر
_THIN = Side(style='thin', color='9CA3AF')
_BOX = Border(left=_THIN, right=_THIN, top=_THIN, bottom=_THIN)
_CENTER = Alignment(horizontal='center', vertical='center')
_RIGHT = Alignment(horizontal='right', vertical='center')

def _style_sheet(ws, header_row, ncols, total_rows=(), money_cols=(), center_cols=()):
    """تطبيق شكل فخم على كل ورقة تقرير: ترويسة مسطحة + حدود + تظليل متناوب + عرض أعمدة + تجميد + فلتر."""
    from openpyxl.utils import get_column_letter as _gcl
    # ترويسة
    for c in range(1, ncols + 1):
        cell = ws.cell(row=header_row, column=c)
        cell.font = _HEADER_FONT
        cell.fill = _HEADER_FILL
        cell.alignment = _CENTER
        cell.border = _BOX
    # بيانات (حدود + تظليل متناوب + محاذاة)
    for row in range(header_row + 1, ws.max_row + 1):
        for c in range(1, ncols + 1):
            cell = ws.cell(row=row, column=c)
            cell.border = _BOX
            if row in total_rows:
                cell.fill = _TOT_FILL
                cell.font = Font(bold=True, size=11)
            elif (row - header_row) % 2 == 0:
                cell.fill = _ALT_FILL
            if c in money_cols:
                cell.number_format = '#,##0.00'
                cell.alignment = _RIGHT
            elif c in center_cols:
                cell.alignment = _CENTER
    # عرض أعمدة مناسب
    for c in range(1, ncols + 1):
        letter = _gcl(c)
        col_vals = [ws.cell(row=r, column=c).value for r in range(header_row, ws.max_row + 1)]
        width = max((len(str(v)) if v is not None else 0) for v in col_vals) + 4 if col_vals else 12
        ws.column_dimensions[letter].width = min(max(width, 10), 32)
    ws.freeze_panes = ws.cell(row=header_row + 1, column=1)
    if ws.max_row > header_row:
        ws.auto_filter.ref = f"A{header_row}:{_gcl(ncols)}{ws.max_row}"
    ws.row_dimensions[header_row].height = 22

def _export_xlsx(wb):
    """تحويل المصنف إلى استجابة تنزيل."""
    out = io.BytesIO()
    wb.save(out)
    out.seek(0)
    return out

def _open_browser(port):
    time.sleep(1.5)
    try:
        webbrowser.open(f'http://localhost:{port}/login')
    except Exception:
        pass

def run_server():
    # التشغيل الآمن: debug معطّل في الإنتاج
    debug = os.environ.get('PAYROLL_DEBUG', '0') == '1'
    port = int(os.environ.get('PORT', 5003))
    if os.environ.get('PAYROLL_NO_BROWSER', '0') != '1':
        threading.Thread(target=_open_browser, args=(port,), daemon=True).start()
    app.run(debug=debug, host='0.0.0.0', port=port, threaded=True)

if __name__ == '__main__':
    run_server()

