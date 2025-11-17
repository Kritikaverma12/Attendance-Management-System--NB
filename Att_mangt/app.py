# app.py
import os
from datetime import datetime, timedelta, date
from functools import wraps

from flask import (
    Flask, render_template, request, redirect, session, url_for, jsonify, abort
)
from flask_sqlalchemy import SQLAlchemy
import bcrypt
import jwt
# from app import db, app


# ---------- All config ----------
BASE_DIR = os.path.abspath(os.path.dirname(__file__))
DB_PATH = os.path.join(BASE_DIR, 'attendance.db')

# app = Flask(__name__, template_folder='templates', static_folder='static')
# app.config['SECRET_KEY'] = os.getenv('SECRET_KEY', 'change_me_for_prod')
#
# app.config['SQLALCHEMY_DATABASE_URI'] = "mysql+pymysql://root:kritika%40123@localhost/attendance_management"
# app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False


app = Flask(__name__, template_folder='templates', static_folder='static')
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY', 'change_me_for_prod')
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///' + DB_PATH
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
JWT_SECRET = app.config['SECRET_KEY']

db = SQLAlchemy(app)


# ---------- Models ----------
class User(db.Model):
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True)
    type = db.Column(db.String(20), default='admin')  # admin / lecturer / student
    full_name = db.Column(db.String(150), nullable=False)
    email = db.Column(db.String(200), unique=True, nullable=False)
    password = db.Column(db.String(255), nullable=False)
    submitted_by = db.Column(db.String(80), nullable=True)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    @staticmethod
    def hash_password(plain: str) -> str:
        return bcrypt.hashpw(plain.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')

    @staticmethod
    def check_password(plain: str, hashed: str) -> bool:
        if not plain or not hashed:
            return False
        return bcrypt.checkpw(plain.encode('utf-8'), hashed.encode('utf-8'))


class Department(db.Model):
    __tablename__ = 'departments'
    id = db.Column(db.Integer, primary_key=True)
    department_name = db.Column(db.String(150), nullable=False)
    submitted_by = db.Column(db.String(80), nullable=True)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)


class Course(db.Model):
    __tablename__ = 'courses'
    id = db.Column(db.Integer, primary_key=True)
    course_name = db.Column(db.String(200), nullable=False)
    department_id = db.Column(db.Integer, db.ForeignKey('departments.id'), nullable=True)
    semester = db.Column(db.String(50), nullable=True)
    class_name = db.Column(db.String(80), nullable=True)
    lecture_hours = db.Column(db.Integer, nullable=True)
    submitted_by = db.Column(db.String(80), nullable=True)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    department = db.relationship('Department', backref=db.backref('courses', lazy=True))


class Student(db.Model):
    __tablename__ = 'students'
    id = db.Column(db.Integer, primary_key=True)
    full_name = db.Column(db.String(150), nullable=False)
    department_id = db.Column(db.Integer, db.ForeignKey('departments.id'), nullable=True)
    course_id = db.Column(db.Integer, db.ForeignKey('courses.id'), nullable=True)
    class_name = db.Column(db.String(80), nullable=True)
    submitted_by = db.Column(db.String(80), nullable=True)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    department = db.relationship('Department', backref=db.backref('students', lazy=True))
    course = db.relationship('Course', backref=db.backref('students', lazy=True))


class AttendanceLog(db.Model):
    __tablename__ = 'attendance_log'
    id = db.Column(db.Integer, primary_key=True)
    student_id = db.Column(db.Integer, db.ForeignKey('students.id'), nullable=False)
    course_id = db.Column(db.Integer, db.ForeignKey('courses.id'), nullable=False)
    present = db.Column(db.Boolean, default=False)
    submitted_by = db.Column(db.String(80), nullable=True)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    student = db.relationship('Student', backref=db.backref('attendance', lazy=True))
    course = db.relationship('Course', backref=db.backref('attendance', lazy=True))


# ---------- Helpers ----------
def create_token(user_id: int, hours: int = 4) -> str:
    payload = {
        'user_id': user_id,
        'exp': datetime.utcnow() + timedelta(hours=hours)
    }
    return jwt.encode(payload, JWT_SECRET, algorithm='HS256')


def decode_token(token: str):
    try:
        return jwt.decode(token, JWT_SECRET, algorithms=['HS256'])
    except Exception:
        return None


def api_token_required(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        auth = request.headers.get('Authorization', '')
        if not auth:
            return jsonify({'message': 'Token missing'}), 401
        token = auth.split(' ')[1] if ' ' in auth else auth
        payload = decode_token(token)
        if not payload:
            return jsonify({'message': 'Invalid or expired token'}), 401
        request.user_id = payload['user_id']
        return f(*args, **kwargs)
    return wrapper


# ---------- Routes (Html ui) ----------
@app.route('/', methods=['GET', 'POST'])
def login():
    """
    Browser login page. Uses session for admin UI.
    """
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')
        user = User.query.filter_by(email=email).first()
        if user and User.check_password(password, user.password):
            session['user_id'] = user.id
            session['user_name'] = user.full_name
            return redirect('/dashboard')
        # also allow hardcoded default admin (if user table not present)
        if email == 'admin@example.com' and password == 'admin123':
            session['user_id'] = 0
            session['user_name'] = 'Admin'
            return redirect('/dashboard')
        return render_template('login.html', error='Invalid credentials')
    return render_template('login.html')


@app.route('/dashboard')
def dashboard():
    if 'user_id' not in session:
        return redirect('/')
    # summary counts for dashboard
    num_students = Student.query.count()
    num_courses = Course.query.count()
    num_depts = Department.query.count()
    num_att = AttendanceLog.query.count()
    return render_template('dashboard.html',
                           num_students=num_students,
                           num_courses=num_courses,
                           num_depts=num_depts,
                           num_att=num_att)


@app.route('/logout')
def logout():
    session.clear()
    return redirect('/')


# departments UI
@app.route('/departments', methods=['GET', 'POST'])
def departments_page():
    if 'user_id' not in session:
        return redirect('/')
    if request.method == 'POST':
        name = request.form.get('department_name')
        if name:
            d = Department(department_name=name, submitted_by=session.get('user_name'))
            db.session.add(d); db.session.commit()
            return redirect('/departments')
    deps = Department.query.all()
    return render_template('departments.html', departments=deps)


# courses UI
@app.route('/courses', methods=['GET', 'POST'])
def courses_page():
    if 'user_id' not in session:
        return redirect('/')
    depts = Department.query.all()
    if request.method == 'POST':
        course_name = request.form.get('course_name')
        department_id = request.form.get('department_id') or None
        semester = request.form.get('semester')
        class_name = request.form.get('class_name')
        lecture_hours = request.form.get('lecture_hours')
        if course_name:
            c = Course(course_name=course_name,
                       department_id=int(department_id) if department_id else None,
                       semester=semester,
                       class_name=class_name,
                       lecture_hours=int(lecture_hours) if lecture_hours else None,
                       submitted_by=session.get('user_name'))
            db.session.add(c); db.session.commit()
            return redirect('/courses')
    courses = Course.query.all()
    return render_template('courses.html', courses=courses, departments=depts)


# students UI
@app.route('/students', methods=['GET', 'POST'])
def students_page():
    if 'user_id' not in session:
        return redirect('/')
    depts = Department.query.all()
    courses = Course.query.all()
    if request.method == 'POST':
        name = request.form.get('full_name')
        department_id = request.form.get('department_id') or None
        course_id = request.form.get('course_id') or None
        class_name = request.form.get('class_name')
        if name:
            s = Student(full_name=name,
                        department_id=int(department_id) if department_id else None,
                        course_id=int(course_id) if course_id else None,
                        class_name=class_name,
                        submitted_by=session.get('user_name'))
            db.session.add(s); db.session.commit()
            return redirect('/students')
    studs = Student.query.all()
    return render_template('students.html', students=studs, departments=depts, courses=courses)


# attendance UI
@app.route('/attendance', methods=['GET', 'POST'])
def attendance_page():
    if 'user_id' not in session:
        return redirect('/')
    students = Student.query.all()
    courses = Course.query.all()
    if request.method == 'POST':
        student_id = request.form.get('student_id')
        course_id = request.form.get('course_id')
        present = request.form.get('present') == 'Present'
        if student_id and course_id:
            # avoid duplicates for same student,course in same run (optional)
            a = AttendanceLog(student_id=int(student_id), course_id=int(course_id),
                              present=present, submitted_by=session.get('user_name'))
            db.session.add(a); db.session.commit()
            return redirect('/attendance')
    logs = AttendanceLog.query.order_by(AttendanceLog.updated_at.desc()).all()
    return render_template('attendance.html', students=students, courses=courses, logs=logs)


# ---------- api (json) routes (protected by token) ----------
@app.route('/api/login', methods=['POST'])
def api_login():
    data = request.get_json() or {}
    email = data.get('email'); password = data.get('password')
    if not email or not password:
        return jsonify({'message': 'email & password required'}), 400
    user = User.query.filter_by(email=email).first()
    if not user or not User.check_password(password, user.password):
        # allow default admin as fallback
        if email == 'admin@example.com' and password == 'admin123':
            token = create_token(0)
            return jsonify({'token': token})
        return jsonify({'message': 'invalid credentials'}), 401
    token = create_token(user.id)
    return jsonify({'token': token})


# departments - API
@app.route('/api/departments', methods=['GET'])
@api_token_required
def api_list_departments():
    deps = Department.query.all()
    return jsonify([{'id': d.id, 'department_name': d.department_name} for d in deps])


@app.route('/api/departments', methods=['POST'])
@api_token_required
def api_create_department():
    data = request.get_json() or {}
    name = data.get('department_name')
    if not name:
        return jsonify({'message': 'department_name required'}), 400
    d = Department(department_name=name, submitted_by=request.user_id)
    db.session.add(d); db.session.commit()
    return jsonify({'id': d.id, 'department_name': d.department_name}), 201


# courses - API
@app.route('/api/courses', methods=['GET'])
@api_token_required
def api_list_courses():
    cs = Course.query.all()
    return jsonify([{'id': c.id, 'course_name': c.course_name, 'department_id': c.department_id} for c in cs])


@app.route('/api/courses', methods=['POST'])
@api_token_required
def api_create_course():
    data = request.get_json() or {}
    name = data.get('course_name')
    if not name:
        return jsonify({'message': 'course_name required'}), 400
    c = Course(course_name=name,
               department_id=data.get('department_id'),
               semester=data.get('semester'),
               class_name=data.get('class_name'),
               lecture_hours=data.get('lecture_hours'),
               submitted_by=request.user_id)
    db.session.add(c); db.session.commit()
    return jsonify({'id': c.id, 'course_name': c.course_name}), 201


# students - API
@app.route('/api/students', methods=['GET'])
@api_token_required
def api_list_students():
    ss = Student.query.all()
    return jsonify([{'id': s.id, 'full_name': s.full_name, 'department_id': s.department_id, 'course_id': s.course_id} for s in ss])


@app.route('/api/students', methods=['POST'])
@api_token_required
def api_create_student():
    data = request.get_json() or {}
    name = data.get('full_name')
    if not name:
        return jsonify({'message': 'full_name required'}), 400
    s = Student(full_name=name,
                department_id=data.get('department_id'),
                course_id=data.get('course_id'),
                class_name=data.get('class_name'),
                submitted_by=request.user_id)
    db.session.add(s); db.session.commit()
    return jsonify({'id': s.id, 'full_name': s.full_name}), 201


# attendance - API
@app.route('/api/attendance', methods=['GET'])
@api_token_required
def api_list_attendance():
    logs = AttendanceLog.query.all()
    return jsonify([{'id': l.id, 'student_id': l.student_id, 'course_id': l.course_id, 'present': l.present, 'timestamp': l.updated_at.isoformat()} for l in logs])


@app.route('/api/attendance', methods=['POST'])
@api_token_required
def api_mark_attendance():
    data = request.get_json() or {}
    sid = data.get('student_id'); cid = data.get('course_id')
    present = data.get('present', False)
    if not sid or not cid:
        return jsonify({'message': 'student_id and course_id required'}), 400
    a = AttendanceLog(student_id=sid, course_id=cid, present=bool(present), submitted_by=request.user_id)
    db.session.add(a); db.session.commit()
    return jsonify({'id': a.id, 'present': a.present}), 201


# ---------- start ----------
if __name__ == '__main__':
    # created database with default login for admin
    with app.app_context():
        db.create_all()
        # create default admin user if not exists
        if not User.query.filter_by(email='admin@example.com').first():
            admin = User(full_name='Admin User', email='admin@example.com', password=User.hash_password('admin123'), type='admin', submitted_by='system')
            db.session.add(admin)
            db.session.commit()
            print('Created default admin: admin@example.com / admin123')
    app.run(debug=True, port=5007)
