from flask import Flask, flash, render_template, request, redirect, session, jsonify, make_response, url_for
from db_utils import init_db, add_student, verify_login, get_teacher_subjects
from face_utils import encode_face, compare_faces, encode_image, match_face
import os
import base64
from io import BytesIO
from io import StringIO
from PIL import Image
import sqlite3
from datetime import datetime, timedelta
import csv
import re
import math
from db_utils import add_department, delete_department, get_all_departments, promote_students
from math import radians, sin, cos, sqrt, atan2
import face_recognition
import qrcode
import io
from flask import send_file

app = Flask(__name__)
app.secret_key = 'your_secret_key'
def haversine(lat1, lon1, lat2, lon2):
    R = 6371000  # meters
    lat1, lon1, lat2, lon2 = map(radians, [lat1, lon1, lat2, lon2])
    dlat = lat2 - lat1
    dlon = lon2 - lon1
    a = sin(dlat/2)**2 + cos(lat1)*cos(lat2)*sin(dlon/2)**2
    c = 2 * atan2(sqrt(a), sqrt(1-a))
    return R * c

# ✅ Home Route
@app.route('/')
def home():
    return render_template('home.html')


# ✅ Student Login (Face Recognition → Choose Session)
# --- Student login: filter active sessions by dept/year ---
from flask import render_template, request, session
from datetime import datetime, timedelta
from PIL import Image
import face_recognition
import sqlite3
import os
import base64
from io import BytesIO

@app.route('/student/login', methods=['GET', 'POST'])
def student_login():
    if request.method == 'POST':
        face_data = request.form.get('face_image')
        lat = request.form.get('latitude')
        lon = request.form.get('longitude')

        if not face_data:
            return "❌ Face image not provided."
        if not lat or not lon:
            return "❌ Location not provided. Please allow location access."

        # Parse and validate GPS coordinates
        try:
            student_lat = float(lat)
            student_lon = float(lon)
        except ValueError:
            return "❌ Invalid location coordinates."

        # Check proximity to any campus
        try:
            conn = sqlite3.connect("database.db")
            c = conn.cursor()
            c.execute("SELECT name, latitude, longitude FROM campuses")
            campuses = c.fetchall()
            conn.close()
        except Exception as e:
            return f"❌ Database error: {str(e)}"

        is_near_any_campus = False
        for campus_name, campus_lat, campus_lon in campuses:
            distance = haversine(student_lat, student_lon, campus_lat, campus_lon)
            if distance <= 300:
                is_near_any_campus = True
                break

        if not is_near_any_campus:
            return "❌ You are not within any recognized campus boundary."

        try:
            # Decode face image from base64
            image_data = face_data.split(",")[1]
            img_bytes = BytesIO(base64.b64decode(image_data))
            img = Image.open(img_bytes).convert('RGB')

            # Save temporarily
            os.makedirs("static/temp", exist_ok=True)
            temp_path = "static/temp/temp_login_face.jpg"
            img.save(temp_path)

            # Encode face
            unknown_image = face_recognition.load_image_file(temp_path)
            encodings = face_recognition.face_encodings(unknown_image)

            if not encodings:
                os.remove(temp_path)
                return "❌ No face detected. Try again."

            unknown_encoding = encodings[0]

            # Match face with database
            conn = sqlite3.connect("database.db")
            c = conn.cursor()
            c.execute("SELECT id, name, image_path, department, year FROM students")
            students = c.fetchall()
            conn.close()

            matched_student = None
            for sid, name, image_path, dept, year in students:
                known_encoding = encode_face(image_path)
                if known_encoding is not None and compare_faces(known_encoding, unknown_encoding):
                    matched_student = (sid, name, dept, year)
                    break

            os.remove(temp_path)

            if not matched_student:
                return "❌ Face not recognized."

            student_id, student_name, student_dept, student_year = matched_student
            session['student_id'] = student_id

            # Find today's active sessions for the student
            now = datetime.now()
            today = now.date().isoformat()

            conn = sqlite3.connect("database.db")
            c = conn.cursor()
            c.execute('''
                SELECT s.id, sub.subject_name, s.start_time, s.time_limit
                FROM sessions s
                JOIN subjects sub ON s.subject_id = sub.id
                WHERE s.date = ? AND s.department = ? AND s.year = ?
            ''', (today, student_dept, student_year))
            all_sessions = c.fetchall()
            conn.close()

            active_sessions = []
            for sid, subject_name, start_time, time_limit in all_sessions:
                start = datetime.strptime(f"{today} {start_time}", "%Y-%m-%d %H:%M")
                end = start + timedelta(minutes=int(time_limit))
                if start <= now <= end:
                    active_sessions.append((sid, subject_name))

            return render_template("choose_session.html", student_name=student_name, sessions=active_sessions)

        except Exception as e:
            if os.path.exists("static/temp/temp_login_face.jpg"):
                os.remove("static/temp/temp_login_face.jpg")
            return f"❌ Error during login: {str(e)}"

    # GET: Load login form
    return render_template("student_login.html")


# ✅ Mark Attendance (Student Selected Session)
@app.route('/student/mark-attendance', methods=['POST'])
def mark_attendance():
    student_id = request.form['student_id']
    session_id = request.form['session_id']

    now = datetime.now()
    current_date = now.date().isoformat()
    current_time = now.strftime('%H:%M')

    # Connect to DB
    conn = sqlite3.connect("database.db", check_same_thread=False)
    c = conn.cursor()

    # Fetch student details
    c.execute("SELECT department, year FROM students WHERE id = ?", (student_id,))
    student = c.fetchone()
    if not student:
        conn.close()
        return "<h3>❌ Invalid student ID.</h3><a href='/'>🏠 Return Home</a>"

    student_dept, student_year = student

    # Fetch session details
    c.execute('''SELECT date, start_time, time_limit, department, year
                 FROM sessions WHERE id = ?''', (session_id,))
    session_data = c.fetchone()
    if not session_data:
        conn.close()
        return "<h3>❌ Session not found.</h3><a href='/'>🏠 Return Home</a>"

    session_date, start_time, time_limit, session_dept, session_year = session_data

    # Validate department and year
    if student_dept != session_dept or student_year != session_year:
        conn.close()
        return "<h3>❌ You are not eligible for this session.</h3><a href='/'>🏠 Return Home</a>"

    # Validate session time
    start = datetime.strptime(f"{session_date} {start_time}", "%Y-%m-%d %H:%M")
    end = start + timedelta(minutes=time_limit)
    if not (start <= now <= end):
        conn.close()
        return "<h3>❌ Session is not active right now.</h3><a href='/'>🏠 Return Home</a>"

    # Check if already marked
    c.execute('''SELECT * FROM attendance 
                 WHERE student_id = ? AND session_id = ?''', (student_id, session_id))
    if c.fetchone():
        conn.close()
        return "<h3>✅ Attendance already marked for this session.</h3><a href='/'>🏠 Return Home</a>"

    # Mark attendance
    c.execute('''INSERT INTO attendance (student_id, session_id, date, time)
                 VALUES (?, ?, ?, ?)''', (student_id, session_id, current_date, current_time))
    conn.commit()
    conn.close()

    return "<h3>✅ Attendance marked successfully.</h3><a href='/'>🏠 Return Home</a>"


# ✅ Student Registration
@app.route('/student/register', methods=['GET', 'POST'])
def student_register():
    if request.method == 'POST':
        try:
            # Extract form fields
            name = request.form['name']
            dept = request.form['department']
            student_id = request.form['student_id']
            roll_no = request.form['roll_no']
            email = request.form['email']
            year = request.form['year']
            face_data = request.form.get('face_image')

            if not face_data:
                return "❌ Face image not captured. Please try again."

            # Decode base64 image
            image_data = face_data.split(",")[1]
            img_bytes = BytesIO(base64.b64decode(image_data))
            img = Image.open(img_bytes).convert('RGB')

            # Save image temporarily for encoding
            temp_path = "static/temp_register_face.jpg"
            img.save(temp_path)

            # Encode the face
            image_np = face_recognition.load_image_file(temp_path)
            face_encodings = face_recognition.face_encodings(image_np)

            if not face_encodings:
                os.remove(temp_path)
                return "❌ No face detected in the captured image."

            new_encoding = face_encodings[0]

            # Connect to DB
            conn = sqlite3.connect("database.db", timeout=10, check_same_thread=False)
            c = conn.cursor()

            # Check for duplicate faces
            c.execute("SELECT image_path FROM students")
            all_paths = c.fetchall()

            for (path,) in all_paths:
                if not os.path.exists(path):
                    continue
                try:
                    known_image = face_recognition.load_image_file(path)
                    known_encodings = face_recognition.face_encodings(known_image)
                    if known_encodings and face_recognition.compare_faces([known_encodings[0]], new_encoding)[0]:
                        conn.close()
                        os.remove(temp_path)
                        return "⚠️ This face is already registered with another student."
                except Exception:
                    continue  # skip unreadable images

            # Save face permanently
            os.makedirs("static/student_faces", exist_ok=True)
            filename = f"{student_id}.jpg"
            save_path = os.path.join("static/student_faces", filename)
            img.save(save_path)

            # Store in DB
            c.execute("""INSERT INTO students (name, department, student_id, roll_no, email, year, image_path)
                         VALUES (?, ?, ?, ?, ?, ?, ?)""",
                      (name, dept, student_id, roll_no, email, year, save_path))
            conn.commit()
            conn.close()
            os.remove(temp_path)

            return "✅ Student registered successfully!"

        except Exception as e:
            return f"🚫 Error during registration: {str(e)}"

    # For GET: load form
    departments = get_all_departments()  # Should return list like [(1, 'CSE'), (2, 'ECE'), ...]
    return render_template('student_register.html', departments=departments)


# ✅ Forgot Password
@app.route('/student/forgot-password', methods=['GET', 'POST'])
def forgot_password():
    if request.method == 'POST':
        email = request.form['email']
        new_password = request.form['new_password']
        confirm_password = request.form['confirm_password']

        if new_password != confirm_password:
            return "Passwords do not match. Please try again."

        conn = sqlite3.connect("database.db", check_same_thread=False)
        c = conn.cursor()
        c.execute("SELECT * FROM students WHERE email = ?", (email,))
        student = c.fetchone()

        if not student:
            return "Email not registered."

        c.execute("UPDATE students SET password = ? WHERE email = ?", (new_password, email))
        conn.commit()
        conn.close()

        return "Password reset successful. You can now <a href='/student/login'>login</a>."
    
    return render_template('student_forgot_password.html')

@app.route('/student/mark-attendance-qr', methods=['POST'])
def mark_attendance_qr():
    student_id = request.form['student_id']
    qr_token = request.form['qr_token']
    # Optionally: face_image = request.files['face_image']

    # Validate qr_token (check if it's valid for the current session and time)
    # If valid, mark attendance for student_id

    # ... your logic here ...

    return jsonify({'status': 'success'})

# ✅ Teacher Login
@app.route('/teacher/login-inline', methods=['POST'])
def teacher_login_inline():
    username = request.form.get('teacher_username')
    password = request.form.get('teacher_password')

    conn = sqlite3.connect("database.db", check_same_thread=False)
    c = conn.cursor()
    c.execute("SELECT id, username FROM teachers WHERE username = ? AND password = ?", (username, password))
    teacher = c.fetchone()
    conn.close()

    if teacher:
        session['teacher_id'] = teacher[0]
        session['teacher_name'] = teacher[1]
        return redirect('/teacher/dashboard')
    else:
        return render_template('home.html', teacher_error="❌ Invalid teacher credentials.")


# ✅ Teacher Dashboard (Create Sessions)
# --- Teacher dashboard: add delete and department filter ---
@app.route('/teacher/dashboard', methods=['GET', 'POST'])
def teacher_dashboard():
    if 'teacher_id' not in session:
        return redirect('/')

    tid = session['teacher_id']
    teacher_name = session['teacher_name']

    with sqlite3.connect("database.db", timeout=10, check_same_thread=False) as conn:
        c = conn.cursor()

        # Fetch departments assigned to this teacher
        c.execute("SELECT department FROM teacher_department WHERE teacher_id = ?", (tid,))
        departments = [row[0] for row in c.fetchall()]

        # Fetch subjects assigned to this teacher
        c.execute('''
            SELECT s.id, s.subject_name, s.subject_code
            FROM subjects s
            JOIN teacher_subject ts ON s.id = ts.subject_id
            WHERE ts.teacher_id = ?
        ''', (tid,))
        subjects = c.fetchall()

        if request.method == 'POST':
            try:
                subject_id = request.form['subject_id']
                date = request.form['date']
                start_time = request.form['start_time']
                time_limit = int(request.form['time_limit'])
                year = request.form['year']
                department = request.form['department']

                if department not in departments:
                    return "❌ You are not authorized to create sessions for this department.", 403

                c.execute('''
                    INSERT INTO sessions
                    (teacher_id, subject_id, date, start_time, time_limit, year, department)
                    VALUES (?, ?, ?, ?, ?, ?, ?)
                ''', (tid, subject_id, date, start_time, time_limit, year, department))
                conn.commit()

            except Exception as e:
                return f"An error occurred while creating the session: {str(e)}", 500

        # Fetch sessions with subject name and year (required for grouping in frontend)
        c.execute('''
            SELECT sessions.id, subjects.subject_name, sessions.date,
                   sessions.start_time, sessions.time_limit, sessions.year
            FROM sessions
            JOIN subjects ON sessions.subject_id = subjects.id
            WHERE sessions.teacher_id = ?
            ORDER BY sessions.date DESC, sessions.start_time DESC
        ''', (tid,))
        sessions = c.fetchall()

    return render_template('teacher_dashboard.html',
                           teacher_name=teacher_name,
                           subjects=subjects,
                           departments=departments,
                           sessions=sessions)


# ✅ Export Attendance CSV
@app.route('/teacher/session/<int:session_id>/export')
def export_session_csv(session_id):
    if 'teacher_id' not in session:
        return redirect('/teacher/login')

    conn = sqlite3.connect("database.db", check_same_thread=False)
    c = conn.cursor()

    # Get session details: date, subject name, and year
    c.execute('''
        SELECT sessions.date, sessions.year, sessions.department, subjects.subject_name
        FROM sessions
        JOIN subjects ON sessions.subject_id = subjects.id
        WHERE sessions.id = ?
    ''', (session_id,))
    session_data = c.fetchone()

    if not session_data:
        return "Session not found."

    date, year, department, subject_name = session_data

    # Sanitize subject name for use in filename
    safe_subject = re.sub(r'[^A-Za-z0-9]+', '_', subject_name)

    # Fetch attendance data
    c.execute('''SELECT students.name, students.roll_no, students.department, attendance.time 
                 FROM attendance 
                 JOIN students ON attendance.student_id = students.id 
                 WHERE attendance.session_id = ?''', (session_id,))
    rows = c.fetchall()
    conn.close()

    # Prepare CSV content
    output = StringIO()
    writer = csv.writer(output)
    writer.writerow(['Student Name', 'Roll No', 'Department', 'Time Marked'])
    writer.writerows(rows)

    # Create response
    filename = f"{safe_subject}_{department}_{year}_{date}.csv"
    response = make_response(output.getvalue())
    response.headers["Content-Disposition"] = f"attachment; filename={filename}"
    response.headers["Content-type"] = "text/csv"
    return response

@app.route('/teacher/session/<int:session_id>/qr')
def session_qr(session_id):
    # Generate a unique token for this session (could be session_id + timestamp or a random string)
    import time
    token = f"{session_id}-{int(time.time() // 300)}"  # changes every 5 minutes

    # Save token in DB or cache if you want to validate later

    img = qrcode.make(token)
    buf = io.BytesIO()
    img.save(buf)
    buf.seek(0)
    return send_file(buf, mimetype='image/png')

# ✅ Admin Routes
@app.route('/admin/login-inline', methods=['POST'])
def admin_login_inline():
    username = request.form.get('admin_username')
    password = request.form.get('admin_password')

    conn = sqlite3.connect("database.db", check_same_thread=False)
    c = conn.cursor()
    c.execute("SELECT id FROM admins WHERE username = ? AND password = ?", (username, password))
    admin = c.fetchone()
    conn.close()

    if admin:
        session['admin_id'] = admin[0]
        session['admin_username'] = username
        return redirect('/admin/dashboard')
    else:
        return render_template('home.html', admin_error="❌ Invalid admin credentials.")


@app.route('/admin/dashboard')
def admin_dashboard():
    if 'admin_id' not in session:
        return redirect('/')

    conn = sqlite3.connect("database.db", check_same_thread=False)
    c = conn.cursor()
    c.execute("SELECT COUNT(*) FROM students")
    student_count = c.fetchone()[0]
    c.execute("SELECT COUNT(*) FROM sessions WHERE date = ?", (datetime.now().date().isoformat(),))
    today_sessions = c.fetchone()[0]
    conn.close()

    return render_template('admin_dashboard.html',
                           student_count=student_count,
                           today_sessions=today_sessions)

@app.route('/admin/edit-student/<int:student_id>', methods=['GET', 'POST'])
def edit_student(student_id):
    if 'admin_id' not in session:
        return redirect('/')

    conn = sqlite3.connect("database.db", check_same_thread=False)
    c = conn.cursor()

    if request.method == 'POST':
        name = request.form['name']
        department = request.form['department']
        student_id_val = request.form['student_id']
        roll_no = request.form['roll_no']
        email = request.form['email']
        year = request.form['year']

        c.execute('''UPDATE students
                     SET name=?, department=?, student_id=?, roll_no=?, email=?, year=?
                     WHERE id=?''',
                  (name, department, student_id_val, roll_no, email, year, student_id))
        conn.commit()
        conn.close()
        return redirect('/admin/manage-students')

    c.execute("SELECT * FROM students WHERE id = ?", (student_id,))
    student = c.fetchone()

    c.execute("SELECT name FROM departments")
    departments = [row[0] for row in c.fetchall()]
    conn.close()

    return render_template('edit_student.html', student=student, departments=departments)

@app.route('/admin/manage-students')
def manage_students():
    dept_filter = request.args.get('department')
    year_filter = request.args.get('year')

    conn = sqlite3.connect('database.db')
    c = conn.cursor()

    # Get departments for dropdown
    c.execute("SELECT * FROM departments")
    departments = c.fetchall()

    # Build the filter query
    query = "SELECT id, name, department, student_id, roll_no, email, year FROM students WHERE 1=1"
    params = []

    if dept_filter:
        query += " AND department = ?"
        params.append(dept_filter)
    if year_filter:
        query += " AND year = ?"
        params.append(year_filter)

    c.execute(query, params)
    students = c.fetchall()
    conn.close()

    return render_template("manage_students.html",
                           students=students,
                           departments=departments,
                           selected_dept=dept_filter,
                           selected_year=year_filter)

# --- Admin manages teachers with departments ---
@app.route('/admin/manage-teachers', methods=['GET', 'POST'])
def manage_teachers():
    if 'admin_id' not in session:
        return redirect('/admin/login')

    conn = sqlite3.connect("database.db", check_same_thread=False)
    c = conn.cursor()

    c.execute("SELECT * FROM departments")
    departments = c.fetchall()
    c.execute("SELECT id, subject_name, subject_code FROM subjects")
    subjects = c.fetchall()

    # Handle Add Teacher form submission
    if request.method == 'POST' and request.form.get('action') == 'add':
        username = request.form['username']
        password = request.form['password']
        selected_departments = request.form.getlist('departments')
        selected_subjects = request.form.getlist('subjects')

        # Insert new teacher
        c.execute("INSERT INTO teachers (username, password) VALUES (?, ?)", (username, password))
        teacher_id = c.lastrowid

        # Assign departments
        for dept in selected_departments:
            c.execute("INSERT INTO teacher_department (teacher_id, department) VALUES (?, ?)", (teacher_id, dept))

        # Assign subjects
        for subject_id in selected_subjects:
            c.execute("INSERT INTO teacher_subject (teacher_id, subject_id) VALUES (?, ?)", (teacher_id, subject_id))

        conn.commit()

    c.execute('''
        SELECT t.id, t.username, GROUP_CONCAT(DISTINCT td.department), GROUP_CONCAT(DISTINCT s.subject_id)
        FROM teachers t
        LEFT JOIN teacher_department td ON t.id = td.teacher_id
        LEFT JOIN teacher_subject s ON t.id = s.teacher_id
        GROUP BY t.id
    ''')
    teachers = c.fetchall()

    teacher_departments = {
        teacher_id: [dept.strip() for dept in (dept_str or '').split(',') if dept_str]
        for teacher_id, _, dept_str, _ in teachers
    }
    teacher_subjects = {
        teacher_id: [sid for sid in (sid_str or '').split(',') if sid_str]
        for teacher_id, _, _, sid_str in teachers
    }

    conn.close()
    return render_template('manage_teachers.html',
                           departments=departments,
                           subjects=subjects,
                           teachers=teachers,
                           teacher_departments=teacher_departments,
                           teacher_subjects=teacher_subjects)
@app.route('/admin/update-teacher-subjects/<int:teacher_id>', methods=['POST'])
def update_teacher_subjects(teacher_id):
    if 'admin_id' not in session:
        return redirect('/admin/login')

    selected_subjects = request.form.getlist('subjects')

    conn = sqlite3.connect("database.db", check_same_thread=False)
    c = conn.cursor()

    # Remove all current subject assignments for this teacher
    c.execute("DELETE FROM teacher_subject WHERE teacher_id = ?", (teacher_id,))

    # Add new subject assignments
    for subject_id in selected_subjects:
        c.execute("INSERT INTO teacher_subject (teacher_id, subject_id) VALUES (?, ?)", (teacher_id, subject_id))

    conn.commit()
    conn.close()
    return redirect('/admin/manage-teachers')
@app.route('/admin/update-teacher-departments/<int:teacher_id>', methods=['POST'])
def update_teacher_departments(teacher_id):
    if 'admin_id' not in session:
        return redirect('/')

    selected_departments = request.form.getlist('departments')

    conn = sqlite3.connect("database.db", check_same_thread=False)
    c = conn.cursor()

    # Remove existing departments
    c.execute("DELETE FROM teacher_department WHERE teacher_id = ?", (teacher_id,))

    # Insert new selections
    for dept in selected_departments:
        c.execute("INSERT INTO teacher_department (teacher_id, department) VALUES (?, ?)", (teacher_id, dept))

    conn.commit()
    conn.close()
    return redirect('/admin/manage-teachers')

@app.route('/admin/add-subject', methods=['GET', 'POST'])
def add_subject():
    if 'admin_id' not in session:
        return redirect('/')

    conn = sqlite3.connect("database.db", check_same_thread=False)
    c = conn.cursor()

    edit_subject = None

    if request.method == 'POST':
        subject_id = request.form.get('subject_id')
        name = request.form.get('subject_name')
        code = request.form.get('subject_code')

        if subject_id:  # Update
            c.execute("UPDATE subjects SET subject_name = ?, subject_code = ? WHERE id = ?", (name, code, subject_id))
        else:  # Add
            try:
                c.execute("INSERT INTO subjects (subject_name, subject_code) VALUES (?, ?)", (name, code))
            except sqlite3.IntegrityError:
                conn.close()
                return "❌ Subject code already exists!"

        conn.commit()

    c.execute("SELECT id, subject_name, subject_code FROM subjects")
    subjects = c.fetchall()
    conn.close()
    return render_template("add_subject.html", subjects=subjects, edit_subject=edit_subject)


@app.route('/admin/edit-subject/<int:subject_id>')
def edit_subject(subject_id):
    if 'admin_id' not in session:
        return redirect('/')

    conn = sqlite3.connect("database.db", check_same_thread=False)
    c = conn.cursor()
    c.execute("SELECT id, subject_name, subject_code FROM subjects WHERE id = ?", (subject_id,))
    subject = c.fetchone()
    c.execute("SELECT id, subject_name, subject_code FROM subjects")
    subjects = c.fetchall()
    conn.close()

    if subject:
        subject_dict = {'id': subject[0], 'subject_name': subject[1], 'subject_code': subject[2]}
        return render_template("add_subject.html", subjects=subjects, edit_subject=subject_dict)
    else:
        return redirect('/admin/add-subject')


@app.route('/admin/delete-subject/<int:subject_id>')
def delete_subject(subject_id):
    if 'admin_id' not in session:
        return redirect('/')

    conn = sqlite3.connect("database.db", check_same_thread=False)
    c = conn.cursor()
    c.execute("DELETE FROM subjects WHERE id = ?", (subject_id,))
    conn.commit()
    conn.close()
    return redirect('/admin/add-subject')

@app.route('/admin/update-teacher/<int:teacher_id>', methods=['POST'])
def update_teacher_department(teacher_id):
    if 'admin' not in session:
        return redirect('/admin/login')

    new_departments = request.form.getlist('departments')

    conn = sqlite3.connect("database.db")
    c = conn.cursor()

    # Clear old departments
    c.execute("DELETE FROM teacher_department WHERE teacher_id = ?", (teacher_id,))

    # Insert new ones
    for dept in new_departments:
        c.execute("INSERT INTO teacher_department (teacher_id, department) VALUES (?, ?)", (teacher_id, dept))

    conn.commit()
    conn.close()
    return redirect('/admin/manage-teachers')
@app.route('/admin/manage-departments', methods=['GET', 'POST'])
def manage_departments():
    if 'admin_id' not in session:
        return redirect('/')

    conn = sqlite3.connect("database.db", check_same_thread=False)
    c = conn.cursor()

    if request.method == 'POST':
        action = request.form.get('action')
        if action == 'add':
            dept_name = request.form.get('dept_name')
            if dept_name:
                try:
                    c.execute("INSERT INTO departments (name) VALUES (?)", (dept_name,))
                    conn.commit()
                except sqlite3.IntegrityError:
                    return "❌ Department already exists."
        elif action == 'delete':
            dept_id = request.form.get('dept_id')
            c.execute("DELETE FROM departments WHERE id = ?", (dept_id,))
            conn.commit()
        elif action == 'update':
            dept_id = request.form.get('dept_id')
            new_name = request.form.get('new_name')
            c.execute("UPDATE departments SET name = ? WHERE id = ?", (new_name, dept_id))
            conn.commit()

    c.execute("SELECT id, name FROM departments")
    departments = c.fetchall()
    conn.close()

    return render_template("manage_departments.html", departments=departments)

@app.route('/admin/reset-teacher-password/<int:teacher_id>', methods=['POST'])
def reset_teacher_password(teacher_id):
    if 'admin_id' not in session:
        return redirect('/')

    new_password = request.form['new_password']

    conn = sqlite3.connect("database.db", check_same_thread=False)
    c = conn.cursor()
    c.execute("UPDATE teachers SET password = ? WHERE id = ?", (new_password, teacher_id))
    conn.commit()
    conn.close()

    return redirect('/admin/manage-teachers')
@app.route('/admin/edit-teacher/<int:teacher_id>')
def edit_teacher(teacher_id):
    if 'admin_id' not in session:
        return redirect('/')
    
    conn = sqlite3.connect("database.db", check_same_thread=False)
    c = conn.cursor()
    c.execute("SELECT username FROM teachers WHERE id = ?", (teacher_id,))
    row = c.fetchone()
    if not row:
        return redirect('/admin/manage-teachers')

    username = row[0]
    c.execute("SELECT department FROM teacher_department WHERE teacher_id = ?", (teacher_id,))
    departments = [d[0] for d in c.fetchall()]
    c.execute("SELECT * FROM departments")
    all_departments = c.fetchall()
    c.execute('''SELECT t.id, t.username, GROUP_CONCAT(td.department)
                 FROM teachers t
                 LEFT JOIN teacher_department td ON t.id = td.teacher_id
                 GROUP BY t.id''')
    teachers = c.fetchall()
    conn.close()

    edit_teacher = {'id': teacher_id, 'username': username, 'departments': departments}
    return render_template("manage_teachers.html", edit_teacher=edit_teacher, teachers=teachers, departments=all_departments)

@app.route('/admin/delete-department/<int:dept_id>')
def delete_department_route(dept_id):
    if 'admin' not in session:
        return redirect('/admin/login')
    delete_department(dept_id)
    return redirect('/admin/manage-departments')

@app.route('/admin/promote-students', methods=['POST'])
def promote_students():
    conn = sqlite3.connect("database.db")
    c = conn.cursor()

    try:
        promotion_order = [("Third", "Fourth"), ("Second", "Third"), ("First", "Second")]
        for current_year, next_year in promotion_order:
            c.execute("UPDATE students SET year = ? WHERE year = ?", (next_year, current_year))
        conn.commit()
        message = "✅ Students promoted to the next academic year successfully."
    except Exception as e:
        conn.rollback()
        message = f"❌ Error during promotion: {e}"
    finally:
        conn.close()

    return f"<h3>{message}</h3><a href='/admin/dashboard'>🔙 Back to Dashboard</a>"

# ✅ Logout Routes
@app.route('/admin/logout')
def admin_logout():
    session.pop('admin_id', None)
    session.pop('admin_username', None)
    return redirect('/')


@app.route('/teacher/logout')
def teacher_logout():
    session.pop('teacher_id', None)
    session.pop('teacher_name', None)
    return redirect('/')



@app.route('/student/logout')
def student_logout():
    session.pop('student_id', None)
    return redirect('/student/login')


# ✅ Delete Teacher
@app.route('/admin/delete-teacher/<int:teacher_id>', methods=['POST'])
def delete_teacher(teacher_id):
    if 'admin_id' not in session:
        return redirect('/')

    conn = sqlite3.connect("database.db", check_same_thread=False)
    c = conn.cursor()
    c.execute("DELETE FROM teacher_subject WHERE teacher_id = ?", (teacher_id,))
    c.execute("DELETE FROM teacher_department WHERE teacher_id = ?", (teacher_id,))
    c.execute("DELETE FROM teachers WHERE id = ?", (teacher_id,))
    conn.commit()
    conn.close()

    return redirect('/admin/manage-teachers')

@app.route('/admin/edit-department/<int:id>', methods=['GET', 'POST'])
def edit_department(id):
    conn = sqlite3.connect("database.db", check_same_thread=False)
    c = conn.cursor()

    if request.method == 'POST':
        new_name = request.form['name']
        c.execute("UPDATE departments SET name = ? WHERE id = ?", (new_name, id))
        conn.commit()
        conn.close()
        return redirect('/admin/manage-departments')

    c.execute("SELECT id, name FROM departments WHERE id = ?", (id,))
    dept = c.fetchone()
    conn.close()
    return render_template("edit_department.html", department=dept)

@app.route('/admin/manage-campuses', methods=['GET', 'POST'])
def manage_campuses():
    conn = sqlite3.connect("database.db")
    c = conn.cursor()

    if request.method == 'POST':
        name = request.form.get('campus_name')
        latitude = request.form.get('latitude')
        longitude = request.form.get('longitude')
        if name and latitude and longitude:
            try:
                lat = float(latitude)
                lon = float(longitude)
                c.execute("INSERT INTO campuses (name, latitude, longitude) VALUES (?, ?, ?)", (name, lat, lon))
                conn.commit()
            except ValueError:
                conn.close()
                return "❌ Invalid latitude or longitude."
    
    c.execute("SELECT * FROM campuses")
    campuses = c.fetchall()
    conn.close()
    return render_template("manage_campuses.html", campuses=campuses)


@app.route('/admin/delete-campus/<int:campus_id>', methods=['POST'])
def delete_campus(campus_id):
    conn = sqlite3.connect("database.db")
    c = conn.cursor()
    c.execute("DELETE FROM campuses WHERE id = ?", (campus_id,))
    conn.commit()
    conn.close()
    return redirect(url_for('manage_campuses'))

@app.route('/admin/delete-student/<int:student_id>', methods=['POST'])
def delete_student(student_id):
    try:
        conn = sqlite3.connect('database.db')
        c = conn.cursor()

        # Get image path
        c.execute("SELECT image_path FROM students WHERE id = ?", (student_id,))
        result = c.fetchone()

        if result:
            image_path = result[0]
            if image_path and os.path.exists(image_path):
                os.remove(image_path)

            c.execute("DELETE FROM students WHERE id = ?", (student_id,))
            conn.commit()

        conn.close()
        return redirect(url_for('manage_students'))

    except Exception as e:
        return f"<h3>❌ Error deleting student: {e}</h3><a href='/admin/dashboard'>🏠 Return to Dashboard</a>"

@app.route('/admin/edit-campus/<int:campus_id>', methods=['GET', 'POST'])
def edit_campus(campus_id):
    conn = sqlite3.connect("database.db")
    c = conn.cursor()

    if request.method == 'POST':
        name = request.form.get('campus_name')
        latitude = request.form.get('latitude')
        longitude = request.form.get('longitude')
        try:
            lat = float(latitude)
            lon = float(longitude)
            c.execute("UPDATE campuses SET name = ?, latitude = ?, longitude = ? WHERE id = ?", (name, lat, lon, campus_id))
            conn.commit()
            conn.close()
            return redirect(url_for('manage_campuses'))
        except ValueError:
            conn.close()
            return "❌ Invalid latitude or longitude."

    c.execute("SELECT * FROM campuses WHERE id = ?", (campus_id,))
    campus = c.fetchone()
    conn.close()
    if not campus:
        return "❌ Campus not found."
    return render_template("edit_campus.html", campus=campus)

@app.route('/teacher/session/<int:sid>/delete')
def delete_session(sid):
    if 'teacher_id' not in session:
        return redirect('/teacher/login')
    with sqlite3.connect("database.db", timeout=5, check_same_thread=False) as conn:
        conn.execute("DELETE FROM sessions WHERE id = ? AND teacher_id = ?", (sid, session['teacher_id']))
    return redirect('/teacher/dashboard')

if __name__ == '__main__':
    if not os.path.exists("database.db"):
        init_db()
    app.run(host='0.0.0.0', port=5000, ssl_context=('cert.pem', 'key.pem'))
