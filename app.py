import csv
import io
import os
import sqlite3
from datetime import datetime, date
from functools import wraps
from flask import Flask, render_template, request, redirect, url_for, session, flash, Response
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", "dev-secret-change-me")
DB_PATH = os.path.join(os.path.dirname(__file__), "transport.db")


def db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    conn = db()
    cur = conn.cursor()
    cur.executescript('''
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE NOT NULL,
        password_hash TEXT NOT NULL,
        role TEXT NOT NULL,
        driver_id INTEGER,
        active INTEGER DEFAULT 1
    );
    CREATE TABLE IF NOT EXISTS drivers (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        first_name TEXT NOT NULL,
        last_name TEXT NOT NULL,
        phone TEXT,
        license_until TEXT,
        pschein_until TEXT,
        active INTEGER DEFAULT 1
    );
    CREATE TABLE IF NOT EXISTS vehicles (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        plate TEXT NOT NULL,
        name TEXT,
        seats INTEGER DEFAULT 9,
        kind TEXT DEFAULT 'Schuelertransport',
        tuev_until TEXT,
        insurance_until TEXT,
        status TEXT DEFAULT 'active'
    );
    CREATE TABLE IF NOT EXISTS schools (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT NOT NULL,
        address TEXT,
        contact TEXT,
        email TEXT,
        phone TEXT,
        active INTEGER DEFAULT 1
    );
    CREATE TABLE IF NOT EXISTS routes (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT NOT NULL,
        school_id INTEGER,
        driver_id INTEGER,
        vehicle_id INTEGER,
        start_time TEXT,
        end_time TEXT,
        active INTEGER DEFAULT 1
    );
    CREATE TABLE IF NOT EXISTS students (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        first_name TEXT NOT NULL,
        last_name TEXT NOT NULL,
        school_id INTEGER,
        route_id INTEGER,
        driver_id INTEGER,
        hours INTEGER DEFAULT 6,
        address TEXT,
        guardian_phone TEXT,
        note TEXT,
        start_dt TEXT,
        end_dt TEXT,
        active INTEGER DEFAULT 1
    );
    CREATE TABLE IF NOT EXISTS ride_logs (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        log_date TEXT NOT NULL,
        direction TEXT NOT NULL,
        student_id INTEGER NOT NULL,
        route_id INTEGER,
        driver_id INTEGER,
        status TEXT NOT NULL,
        note TEXT,
        created_at TEXT NOT NULL,
        updated_at TEXT NOT NULL,
        UNIQUE(log_date, direction, student_id)
    );
    CREATE TABLE IF NOT EXISTS audit_logs (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        ts TEXT NOT NULL,
        user TEXT,
        action TEXT,
        details TEXT
    );
    ''')
    conn.commit()
    # seed data
    if cur.execute("SELECT COUNT(*) FROM users").fetchone()[0] == 0:
        cur.execute("INSERT INTO drivers(first_name,last_name,phone,pschein_until) VALUES (?,?,?,?)", ("Fahrer", "Eins", "", "2026-12-31"))
        driver_id = cur.lastrowid
        cur.execute("INSERT INTO users(username,password_hash,role,driver_id) VALUES (?,?,?,NULL)", ("admin", generate_password_hash("admin123"), "admin"))
        cur.execute("INSERT INTO users(username,password_hash,role,driver_id) VALUES (?,?,?,?)", ("fahrer1", generate_password_hash("fahrer123"), "driver", driver_id))
        cur.execute("INSERT INTO vehicles(plate,name,seats,tuev_until,insurance_until) VALUES (?,?,?,?,?)", ("MO-TR 101", "Bus 101", 9, "2026-05-31", "2026-12-31"))
        vehicle_id = cur.lastrowid
        cur.execute("INSERT INTO schools(name,address,contact) VALUES (?,?,?)", ("Beispielschule", "Kamp-Lintfort", "Sekretariat"))
        school_id = cur.lastrowid
        cur.execute("INSERT INTO routes(name,school_id,driver_id,vehicle_id,start_time,end_time) VALUES (?,?,?,?,?,?)", ("Route 1", school_id, driver_id, vehicle_id, "07:00", "15:00"))
        route_id = cur.lastrowid
        students = [("Max", "Mueller", 6), ("Sara", "Schmidt", 8), ("Ali", "Yilmaz", 4)]
        for fn, ln, h in students:
            cur.execute("INSERT INTO students(first_name,last_name,school_id,route_id,driver_id,hours,start_dt) VALUES (?,?,?,?,?,?,?)", (fn, ln, school_id, route_id, driver_id, h, "2026-01-01T00:00"))
        conn.commit()
    conn.close()


def audit(action, details=""):
    conn = db()
    conn.execute("INSERT INTO audit_logs(ts,user,action,details) VALUES (?,?,?,?)", (datetime.now().isoformat(timespec='seconds'), session.get('username'), action, details))
    conn.commit(); conn.close()


def login_required(role=None):
    def deco(fn):
        @wraps(fn)
        def wrapper(*args, **kwargs):
            if not session.get('user_id'):
                return redirect(url_for('login'))
            if role and session.get('role') != role:
                flash('Keine Berechtigung')
                return redirect(url_for('home'))
            return fn(*args, **kwargs)
        return wrapper
    return deco


def today_str():
    return request.args.get('date') or date.today().isoformat()


def route_status(conn, route, log_date):
    students = conn.execute("SELECT COUNT(*) c FROM students WHERE active=1 AND route_id=?", (route['id'],)).fetchone()['c']
    if students == 0:
        return {'label':'Keine Schüler','class':'warn','done':0,'total':0,'percent':0}
    total_expected = students * 2
    logged = conn.execute("SELECT COUNT(*) c FROM ride_logs WHERE log_date=? AND route_id=?", (log_date, route['id'])).fetchone()['c']
    pct = int((logged / total_expected) * 100) if total_expected else 0
    if logged == 0:
        return {'label':'Nicht gestartet','class':'danger','done':logged,'total':total_expected,'percent':0}
    if logged < total_expected:
        return {'label':'Läuft','class':'warn','done':logged,'total':total_expected,'percent':pct}
    return {'label':'Fertig','class':'ok','done':logged,'total':total_expected,'percent':100}


@app.route('/')
def home():
    if session.get('role') == 'admin': return redirect(url_for('admin_dashboard'))
    if session.get('role') == 'driver': return redirect(url_for('driver_dashboard'))
    return redirect(url_for('login'))


@app.route('/login', methods=['GET','POST'])
def login():
    if request.method == 'POST':
        username = request.form['username'].strip()
        password = request.form['password']
        conn = db(); user = conn.execute("SELECT * FROM users WHERE username=? AND active=1", (username,)).fetchone(); conn.close()
        if user and check_password_hash(user['password_hash'], password):
            session.clear(); session['user_id']=user['id']; session['username']=user['username']; session['role']=user['role']; session['driver_id']=user['driver_id']
            return redirect(url_for('home'))
        flash('Login falsch')
    return render_template('login.html')

@app.route('/logout')
def logout():
    session.clear(); return redirect(url_for('login'))

@app.route('/admin')
@login_required('admin')
def admin_dashboard():
    d = today_str(); conn = db()
    routes = conn.execute('''SELECT r.*, d.first_name||' '||d.last_name driver_name, v.plate vehicle_plate, s.name school_name
                             FROM routes r LEFT JOIN drivers d ON r.driver_id=d.id LEFT JOIN vehicles v ON r.vehicle_id=v.id LEFT JOIN schools s ON r.school_id=s.id
                             WHERE r.active=1 ORDER BY r.name''').fetchall()
    route_cards=[]
    active_routes=0; missing=[]; running=0; finished=0
    for r in routes:
        st = route_status(conn, r, d)
        if st['done']>0: active_routes += 1
        if st['class']=='danger': missing.append(r)
        if st['class']=='warn': running += 1
        if st['class']=='ok': finished += 1
        route_cards.append((r, st))
    drivers_total = conn.execute("SELECT COUNT(*) c FROM drivers WHERE active=1").fetchone()['c']
    vehicles_total = conn.execute("SELECT COUNT(*) c FROM vehicles WHERE status='active'").fetchone()['c']
    students_total = conn.execute("SELECT COUNT(*) c FROM students WHERE active=1").fetchone()['c']
    absent = conn.execute("SELECT COUNT(*) c FROM ride_logs WHERE log_date=? AND status='Fehlt'", (d,)).fetchone()['c']
    cancelled = conn.execute("SELECT COUNT(*) c FROM ride_logs WHERE log_date=? AND status='Abgesagt'", (d,)).fetchone()['c']
    warnings = conn.execute("SELECT * FROM vehicles WHERE tuev_until <= date('now','+60 day') OR insurance_until <= date('now','+60 day') ORDER BY tuev_until").fetchall()
    conn.close()
    return render_template('admin_dashboard.html', d=d, route_cards=route_cards, drivers_total=drivers_total, vehicles_total=vehicles_total, students_total=students_total, absent=absent, cancelled=cancelled, missing=missing, running=running, finished=finished, active_routes=active_routes, warnings=warnings)

@app.route('/admin/route/<int:route_id>')
@login_required('admin')
def route_detail(route_id):
    d=today_str(); conn=db()
    route=conn.execute('''SELECT r.*, d.first_name||' '||d.last_name driver_name, v.plate vehicle_plate, s.name school_name FROM routes r
                          LEFT JOIN drivers d ON r.driver_id=d.id LEFT JOIN vehicles v ON r.vehicle_id=v.id LEFT JOIN schools s ON r.school_id=s.id WHERE r.id=?''',(route_id,)).fetchone()
    students=conn.execute('''SELECT st.*, 
        (SELECT status FROM ride_logs WHERE student_id=st.id AND log_date=? AND direction='Hinfahrt') hin,
        (SELECT status FROM ride_logs WHERE student_id=st.id AND log_date=? AND direction='Rueckfahrt') rueck,
        (SELECT note FROM ride_logs WHERE student_id=st.id AND log_date=? ORDER BY updated_at DESC LIMIT 1) log_note
        FROM students st WHERE st.active=1 AND st.route_id=? ORDER BY st.last_name, st.first_name''',(d,d,d,route_id)).fetchall()
    conn.close()
    return render_template('route_detail.html', route=route, students=students, d=d)

@app.route('/admin/fahrer/<int:driver_id>')
@login_required('admin')
def driver_detail(driver_id):
    d=today_str(); conn=db()
    driver=conn.execute("SELECT * FROM drivers WHERE id=?",(driver_id,)).fetchone()
    routes=conn.execute("SELECT * FROM routes WHERE active=1 AND driver_id=?",(driver_id,)).fetchall()
    route_cards=[(r, route_status(conn,r,d)) for r in routes]
    logs=conn.execute('''SELECT rl.*, st.first_name||' '||st.last_name student_name, r.name route_name FROM ride_logs rl
                         LEFT JOIN students st ON rl.student_id=st.id LEFT JOIN routes r ON rl.route_id=r.id
                         WHERE rl.driver_id=? AND rl.log_date=? ORDER BY rl.updated_at DESC''',(driver_id,d)).fetchall()
    conn.close()
    return render_template('driver_detail.html', driver=driver, route_cards=route_cards, logs=logs, d=d)

@app.route('/admin/missing')
@login_required('admin')
def missing_detail():
    d=today_str(); conn=db()
    rows=[]
    for r in conn.execute('''SELECT r.*, d.first_name||' '||d.last_name driver_name FROM routes r LEFT JOIN drivers d ON r.driver_id=d.id WHERE r.active=1''').fetchall():
        st=route_status(conn,r,d)
        if st['class']=='danger': rows.append((r,st))
    conn.close()
    return render_template('missing.html', rows=rows, d=d)

@app.route('/admin/manage/<what>', methods=['GET','POST'])
@login_required('admin')
def manage(what):
    conn=db()
    if request.method=='POST':
        f=request.form
        if what=='drivers':
            cur=conn.execute("INSERT INTO drivers(first_name,last_name,phone,pschein_until,active) VALUES (?,?,?,?,1)",(f['first_name'],f['last_name'],f.get('phone',''),f.get('pschein_until','')))
            if f.get('username') and f.get('password'):
                conn.execute("INSERT INTO users(username,password_hash,role,driver_id) VALUES (?,?,?,?)",(f['username'],generate_password_hash(f['password']),'driver',cur.lastrowid))
        elif what=='vehicles':
            conn.execute("INSERT INTO vehicles(plate,name,seats,kind,tuev_until,insurance_until,status) VALUES (?,?,?,?,?,?,?)",(f['plate'],f.get('name',''),f.get('seats',9),f.get('kind','Schuelertransport'),f.get('tuev_until',''),f.get('insurance_until',''),'active'))
        elif what=='schools':
            conn.execute("INSERT INTO schools(name,address,contact,email,phone) VALUES (?,?,?,?,?)",(f['name'],f.get('address',''),f.get('contact',''),f.get('email',''),f.get('phone','')))
        elif what=='routes':
            conn.execute("INSERT INTO routes(name,school_id,driver_id,vehicle_id,start_time,end_time) VALUES (?,?,?,?,?,?)",(f['name'],f.get('school_id'),f.get('driver_id'),f.get('vehicle_id'),f.get('start_time',''),f.get('end_time','')))
        elif what=='students':
            conn.execute("INSERT INTO students(first_name,last_name,school_id,route_id,driver_id,hours,address,guardian_phone,note,start_dt,end_dt) VALUES (?,?,?,?,?,?,?,?,?,?,?)",(f['first_name'],f['last_name'],f.get('school_id'),f.get('route_id'),f.get('driver_id'),f.get('hours',6),f.get('address',''),f.get('guardian_phone',''),f.get('note',''),f.get('start_dt',''),f.get('end_dt','')))
        conn.commit(); audit('create '+what); flash('Gespeichert'); return redirect(url_for('manage', what=what))
    data={}
    data['drivers']=conn.execute("SELECT * FROM drivers ORDER BY last_name").fetchall()
    data['vehicles']=conn.execute("SELECT * FROM vehicles ORDER BY plate").fetchall()
    data['schools']=conn.execute("SELECT * FROM schools ORDER BY name").fetchall()
    data['routes']=conn.execute('''SELECT r.*, s.name school, d.first_name||' '||d.last_name driver, v.plate vehicle FROM routes r LEFT JOIN schools s ON r.school_id=s.id LEFT JOIN drivers d ON r.driver_id=d.id LEFT JOIN vehicles v ON r.vehicle_id=v.id ORDER BY r.name''').fetchall()
    data['students']=conn.execute('''SELECT st.*, s.name school, r.name route, d.first_name||' '||d.last_name driver FROM students st LEFT JOIN schools s ON st.school_id=s.id LEFT JOIN routes r ON st.route_id=r.id LEFT JOIN drivers d ON st.driver_id=d.id ORDER BY st.last_name''').fetchall()
    conn.close()
    return render_template('manage.html', what=what, data=data)


@app.route('/admin/edit/<what>/<int:item_id>', methods=['GET','POST'])
@login_required('admin')
def edit_item(what, item_id):
    table={'drivers':'drivers','vehicles':'vehicles','schools':'schools','routes':'routes','students':'students'}.get(what)
    if not table:
        flash('Unbekannter Bereich')
        return redirect(url_for('admin_dashboard'))
    conn=db()
    if request.method=='POST':
        f=request.form
        active_value = 1 if f.get('active') else 0
        if what=='drivers':
            conn.execute("UPDATE drivers SET first_name=?, last_name=?, phone=?, license_until=?, pschein_until=?, active=? WHERE id=?",
                         (f['first_name'],f['last_name'],f.get('phone',''),f.get('license_until',''),f.get('pschein_until',''),active_value,item_id))
            if f.get('username'):
                user=conn.execute("SELECT id FROM users WHERE driver_id=? AND role='driver'",(item_id,)).fetchone()
                if user and f.get('password'):
                    conn.execute("UPDATE users SET username=?, password_hash=?, active=? WHERE id=?",(f['username'],generate_password_hash(f['password']),active_value,user['id']))
                elif user:
                    conn.execute("UPDATE users SET username=?, active=? WHERE id=?",(f['username'],active_value,user['id']))
                elif f.get('password'):
                    conn.execute("INSERT INTO users(username,password_hash,role,driver_id,active) VALUES (?,?,?,?,?)",(f['username'],generate_password_hash(f['password']),'driver',item_id,active_value))
        elif what=='vehicles':
            conn.execute("UPDATE vehicles SET plate=?, name=?, seats=?, kind=?, tuev_until=?, insurance_until=?, status=? WHERE id=?",
                         (f['plate'],f.get('name',''),f.get('seats',9),f.get('kind','Schuelertransport'),f.get('tuev_until',''),f.get('insurance_until',''),f.get('status','active'),item_id))
        elif what=='schools':
            conn.execute("UPDATE schools SET name=?, address=?, contact=?, email=?, phone=?, active=? WHERE id=?",
                         (f['name'],f.get('address',''),f.get('contact',''),f.get('email',''),f.get('phone',''),active_value,item_id))
        elif what=='routes':
            conn.execute("UPDATE routes SET name=?, school_id=?, driver_id=?, vehicle_id=?, start_time=?, end_time=?, active=? WHERE id=?",
                         (f['name'],f.get('school_id'),f.get('driver_id'),f.get('vehicle_id'),f.get('start_time',''),f.get('end_time',''),active_value,item_id))
        elif what=='students':
            conn.execute("UPDATE students SET first_name=?, last_name=?, school_id=?, route_id=?, driver_id=?, hours=?, address=?, guardian_phone=?, note=?, start_dt=?, end_dt=?, active=? WHERE id=?",
                         (f['first_name'],f['last_name'],f.get('school_id'),f.get('route_id'),f.get('driver_id'),f.get('hours',6),f.get('address',''),f.get('guardian_phone',''),f.get('note',''),f.get('start_dt',''),f.get('end_dt',''),active_value,item_id))
        conn.commit(); conn.close(); audit('edit '+what, str(item_id)); flash('Geändert')
        return redirect(url_for('manage', what=what))
    item=conn.execute(f"SELECT * FROM {table} WHERE id=?",(item_id,)).fetchone()
    data={}
    data['drivers']=conn.execute("SELECT * FROM drivers ORDER BY last_name").fetchall()
    data['vehicles']=conn.execute("SELECT * FROM vehicles ORDER BY plate").fetchall()
    data['schools']=conn.execute("SELECT * FROM schools ORDER BY name").fetchall()
    data['routes']=conn.execute("SELECT * FROM routes ORDER BY name").fetchall()
    user=None
    if what=='drivers':
        user=conn.execute("SELECT username FROM users WHERE driver_id=? AND role='driver'",(item_id,)).fetchone()
    conn.close()
    return render_template('edit.html', what=what, item=item, data=data, user=user)
@app.route('/admin/deactivate/<what>/<int:item_id>')
@login_required('admin')
def deactivate(what,item_id):
    table={'drivers':'drivers','vehicles':'vehicles','schools':'schools','routes':'routes','students':'students'}.get(what)
    if table:
        conn=db()
        if table=='vehicles': conn.execute("UPDATE vehicles SET status='inactive' WHERE id=?",(item_id,))
        else: conn.execute(f"UPDATE {table} SET active=0 WHERE id=?",(item_id,))
        conn.commit(); conn.close(); audit('deactivate '+what, str(item_id))
    return redirect(url_for('manage', what=what))

@app.route('/driver')
@login_required('driver')
def driver_dashboard():
    d=today_str(); driver_id=session.get('driver_id'); conn=db()
    routes=conn.execute("SELECT * FROM routes WHERE active=1 AND driver_id=? ORDER BY name",(driver_id,)).fetchall()
    groups=[]
    for r in routes:
        students=conn.execute('''SELECT st.*, 
        (SELECT status FROM ride_logs WHERE student_id=st.id AND log_date=? AND direction='Hinfahrt') hin,
        (SELECT status FROM ride_logs WHERE student_id=st.id AND log_date=? AND direction='Rueckfahrt') rueck
        FROM students st WHERE st.active=1 AND st.route_id=? ORDER BY st.last_name''',(d,d,r['id'])).fetchall()
        groups.append((r,students))
    conn.close(); return render_template('driver_dashboard.html', groups=groups, d=d)

@app.route('/driver/check', methods=['POST'])
@login_required('driver')
def driver_check():
    f=request.form; now=datetime.now().isoformat(timespec='seconds')
    conn=db()
    student=conn.execute("SELECT * FROM students WHERE id=?",(f['student_id'],)).fetchone()
    conn.execute('''INSERT INTO ride_logs(log_date,direction,student_id,route_id,driver_id,status,note,created_at,updated_at)
                    VALUES (?,?,?,?,?,?,?,?,?)
                    ON CONFLICT(log_date,direction,student_id) DO UPDATE SET status=excluded.status,note=excluded.note,updated_at=excluded.updated_at''',
                 (f['log_date'],f['direction'],f['student_id'],student['route_id'],session.get('driver_id'),f['status'],f.get('note',''),now,now))
    conn.commit(); conn.close(); audit('driver_check', f"{f['student_id']} {f['direction']} {f['status']}")
    return redirect(url_for('driver_dashboard', date=f['log_date']))

@app.route('/admin/export')
@login_required('admin')
def export_csv():
    month=request.args.get('month') or date.today().strftime('%Y-%m')
    conn=db(); rows=conn.execute('''SELECT rl.log_date, rl.direction, rl.status, st.first_name, st.last_name, st.hours, sc.name school, r.name route, d.first_name||' '||d.last_name driver
                                    FROM ride_logs rl LEFT JOIN students st ON rl.student_id=st.id LEFT JOIN schools sc ON st.school_id=sc.id LEFT JOIN routes r ON rl.route_id=r.id LEFT JOIN drivers d ON rl.driver_id=d.id
                                    WHERE rl.log_date LIKE ? ORDER BY sc.name, st.last_name, rl.log_date''',(month+'%',)).fetchall(); conn.close()
    out=io.StringIO(); w=csv.writer(out); w.writerow(['Datum','Richtung','Status','Vorname','Nachname','Stunden','Schule','Route','Fahrer'])
    for row in rows: w.writerow(list(row))
    return Response(out.getvalue(), mimetype='text/csv', headers={'Content-Disposition':f'attachment; filename=abrechnung_{month}.csv'})

init_db()
if __name__ == '__main__':
    app.run(host='0.0.0.0', port=int(os.environ.get('PORT', 5000)), debug=True)
