import json
from flask import Flask, flash, render_template, request, redirect, session, jsonify, make_response, url_for, send_file
import click
import os # This is a standard library import, not from db_utils
import base64
from io import BytesIO
from io import StringIO
from PIL import Image
import psycopg2
import psycopg2.extras
from datetime import datetime, timedelta
import time
import csv
import re
import pytz
from db_utils import (init_db, get_connection, get_all_departments, add_department,
                      delete_department, promote_students, get_student_by_student_id, update_student_sign_count)
from math import radians, sin, cos, sqrt, atan2
import qrcode
import io
from webauthn import generate_registration_options, options_to_json, verify_registration_response, generate_authentication_options, verify_authentication_response
from webauthn.helpers import parse_registration_credential_json, parse_authentication_credential_json, base64url_to_bytes, bytes_to_base64url
from werkzeug.security import generate_password_hash, check_password_hash
from dotenv import load_dotenv

load_dotenv() # Load environment variables from .env file

app = Flask(__name__)
# Load the secret key from an environment variable for security
# The second argument is a default key for development if the .env file is not present.
app.secret_key = os.getenv("FLASK_SECRET_KEY", "a-default-secret-for-dev")

# ---------------- Utility Functions ---------------- #
def haversine(lat1, lon1, lat2, lon2):
    """Calculate distance in meters between two lat/lon coords."""
    R = 6371000
    lat1, lon1, lat2, lon2 = map(radians, [lat1, lon1, lat2, lon2])
    dlat, dlon = lat2 - lat1, lon2 - lon1
    a = sin(dlat/2)**2 + cos(lat1) * cos(lat2) * sin(dlon/2)**2
    return R * 2 * atan2(sqrt(a), sqrt(1-a))

def db_query(query, params=(), fetchone=False, commit=False):
    """Utility wrapper for SQLite queries."""
    # This function is no longer ideal as cursor management is more explicit with psycopg2.
    # It's better to refactor calls to use the 'with get_connection()' pattern directly.
    with get_connection() as conn:
        with conn.cursor(cursor_factory=psycopg2.extras.DictCursor) as c:
            c.execute(query, params)
            if commit:
                conn.commit()
                return None # No return value on commit
            if fetchone:
                return c.fetchone()
            return c.fetchall()



# ---------------- Routes ---------------- #
@app.route('/')
def home():
    return render_template('home.html')


# ---------------- Student Login ---------------- #
@app.route('/student/login', methods=['GET', 'POST'])
def student_login():
    return render_template("student_login.html")


@app.route("/student/login/verify", methods=["POST"])
def student_login_verify():
    student_id_val = request.form.get("student_id")
    auth_response_json = request.form.get("webauthn_assertion")

    if not student_id_val:
        return "Student ID is required.", 400

    student = get_student_by_student_id(student_id_val)
    if not student:
        return "Student not found.", 404

    # --- WebAuthn Verification ---
    if auth_response_json:
        try: # Use the library's parse_credential_json
            auth_cred = parse_authentication_credential_json(auth_response_json)
            verification = verify_authentication_response( # type: ignore
                credential=auth_cred,
                expected_challenge=session["webauthn_challenge"],
                expected_rp_id=request.host.split(':')[0],
                expected_origin=request.origin,
                credential_public_key=student["public_key"],
                credential_current_sign_count=student["sign_count"],
                require_user_verification=True,
            )
            # Update sign count
            update_student_sign_count(student["id"], verification.new_sign_count)
        except Exception as e: # More specific error handling is better in production
            return f"Login verification failed: {e}", 400

    # --- PIN Verification (Fallback) ---
    else:
        return "WebAuthn assertion is required.", 400

    # If WebAuthn verification is successful, set session
    session["student_id"] = student["id"]
    session["student_name"] = student["name"]

    # Check for active sessions before redirecting
    # Use a specific timezone (e.g., IST) to avoid server/client time mismatches.
    ist = pytz.timezone('Asia/Kolkata')
    now = datetime.now(ist)
    today = now.date().isoformat()
    student_dept = student["department"]
    student_year = student["year"]

    with get_connection() as conn:
        with conn.cursor(cursor_factory=psycopg2.extras.DictCursor) as c:
            c.execute("""
            SELECT s.id, s.start_time, s.time_limit, sub.subject_name
            FROM sessions s
            JOIN subjects sub ON s.subject_id = sub.id
            WHERE s.date = %s AND s.department = %s AND s.year = %s
            """, (today, student_dept, student_year))
            all_sessions_today = c.fetchall()

    active_sessions = []
    for sess in all_sessions_today:
        # Handle both 'HH:MM' and 'HH:MM:SS' time formats from the database.
        time_format = "%Y-%m-%d %H:%M"
        if ':' in sess['start_time'] and sess['start_time'].count(':') == 2:
            time_format = "%Y-%m-%d %H:%M:%S"
        # Make the start_time timezone-aware before comparison
        naive_start_time = datetime.strptime(f"{today} {sess['start_time']}", time_format)
        start_time = ist.localize(naive_start_time)

        end_time = start_time + timedelta(minutes=sess['time_limit'])

        if start_time <= now <= end_time:
            active_sessions.append(sess)

    if len(active_sessions) == 1:
        # If only one session is active, redirect straight to the scanner.
        return redirect(url_for("student_scan_qr", session_id=active_sessions[0]['id']))
    elif len(active_sessions) > 1:
        # If multiple sessions are active, let the student choose.
        return render_template("choose_session.html", active_sessions=active_sessions, student_name=session["student_name"])
    else:
        # If no sessions are active, show the info page.
        return render_template("no_active_session.html", student_name=session["student_name"])


@app.route("/student/scan-qr/<int:session_id>")
def student_scan_qr(session_id):
    if "student_id" not in session:
        return redirect(url_for("student_login"))
    return render_template("student_scan_qr.html", student_name=session["student_name"])


@app.route('/student/mark-attendance', methods=['POST'])
def mark_attendance():
    if "student_id" not in session:
        return "Not logged in", 401

    qr_data_str = request.form.get('qr_data')
    if not qr_data_str:
        return "No QR data received", 400

    try:
        qr_data = json.loads(qr_data_str)
        session_id = qr_data.get("session_id")
        expiry = qr_data.get("expiry")

        if not session_id or not expiry or int(time.time()) > expiry:
            return "Invalid or expired QR code.", 400

        # Use a specific timezone (e.g., IST) to ensure consistent time recording.
        ist = pytz.timezone('Asia/Kolkata')
        now = datetime.now(ist)
        with get_connection() as conn:
            with conn.cursor() as c:
                # Check if already marked
                c.execute("SELECT id FROM attendance WHERE student_id = %s AND session_id = %s", (session['student_id'], session_id))
                if c.fetchone():
                    return "You have already marked attendance for this session.", 200
                c.execute("INSERT INTO attendance (student_id, session_id, date, time) VALUES (%s, %s, %s, %s)",
                            (session['student_id'], session_id, now.date().isoformat(), now.time().strftime('%H:%M:%S')))
        return "✅ Attendance marked successfully!", 200
    except (json.JSONDecodeError, Exception) as e:
        return f"Error processing QR data: {e}", 400


# ---------------- Student Registration ---------------- #
@app.route('/student/register', methods=['GET', 'POST'])
def student_register():
    if request.method == 'POST':
        try:
            name = request.form['name']
            dept = request.form['department']
            student_id = request.form['student_id']
            roll_no = request.form['roll_no']
            email = request.form['email']
            year_str = request.form['year']
            attestation_json = request.form.get('webauthn_attestation')

            # Convert year string (e.g., "Second") to an integer
            year_map = {"First": 1, "Second": 2, "Third": 3, "Fourth": 4}
            year = year_map.get(year_str)
            if year is None:
                flash("Invalid academic year selected. Please try again.", "error")
                return redirect(url_for('student_register'))

            if not attestation_json:
                flash("A WebAuthn device registration is required before completing.", "error")
                return redirect(url_for('student_register'))

            # Use the library's parse_credential_json
            reg_cred = parse_registration_credential_json(attestation_json)
            verification = verify_registration_response( # type: ignore
                credential=reg_cred,
                expected_challenge=session["webauthn_challenge"],
                expected_rp_id=request.host.split(':')[0],
                expected_origin=request.origin,
                require_user_verification=True,
            )

            with get_connection() as conn:
                with conn.cursor() as c:
                    # For a new registration, we should only be inserting.
                    # The UNIQUE constraints on the table will handle errors.
                    c.execute("""
                        INSERT INTO students (name, department, student_id, roll_no, email, year, credential_id, public_key, sign_count)
                        VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)
                    """, (name, dept, student_id, roll_no, email, year, verification.credential_id, verification.credential_public_key, 0))
                    conn.commit()
                    flash("Registration successful! You can now log in.", "success")

            return redirect(url_for('student_login'))

        except psycopg2.IntegrityError as e:
            error_msg = str(e).lower()
            if 'students.student_id' in error_msg:
                flash("A student with this Student ID already exists.", "error")
            elif 'students.email' in error_msg:
                flash("A student with this Email already exists.", "error")
            elif 'roll_no, department' in error_msg:
                flash("A student with this Roll Number already exists in this department.", "error")
            else:
                flash("A student with this ID, Roll Number, or Email already exists.", "error")
            return redirect(url_for('student_register'))

        except UnicodeDecodeError:
            flash("There was an error processing the registration data. Please ensure you are not uploading a file and try again.", "error")
            return redirect(url_for('student_register'))
        except Exception as e:
            flash(f"An unexpected error occurred: {e}", "error")
            return redirect(url_for('student_register'))

    # For GET: Render registration page
    departments = get_all_departments()
    return render_template("student_register.html", departments=departments)

@app.route("/student/register/options", methods=["POST"])
def student_register_options():
    student_id = request.form.get("student_id")
    name = request.form.get("name")

    if not student_id or not name:
        return "Student ID and Name are required.", 400

    # This is the definitive fix for the ValueError/UnicodeDecodeError cycle.
    # We must pass bytes, but the bytes must also be UTF-8 safe to avoid
    # errors during verification.
    # Simplify user_id to just UTF-8 encoded bytes. The webauthn library handles further encoding.
    user_id_bytes = student_id.encode("utf-8")

    # Fetch all existing credential IDs to prevent re-registration of the same device
    # across different student accounts.
    with get_connection() as conn:
        with conn.cursor(cursor_factory=psycopg2.extras.DictCursor) as c:
            c.execute("SELECT credential_id FROM students WHERE credential_id IS NOT NULL")
            existing_creds = c.fetchall()

    # The credential_id is stored as bytes. The bytes_to_base64url function expects bytes.
    # This list comprehension correctly handles the bytes from the database.
    exclude_credentials = [
        {"id": bytes_to_base64url(cred["credential_id"]), "type": "public-key"} for cred in existing_creds
    ]

    options = generate_registration_options(
        rp_id=request.host.split(':')[0],
        rp_name="AttendNow",
        user_id=user_id_bytes,
        user_display_name=name,
        user_name=name,
        exclude_credentials=exclude_credentials,
    )
    session["webauthn_challenge"] = options.challenge

    # Manually construct the JSON response to ensure correct encoding.
    # The `options_to_json` helper can have issues with `exclude_credentials`.
    response_data = {
        "challenge": bytes_to_base64url(options.challenge),
        "rp": options.rp,
        "user": {
            "id": bytes_to_base64url(options.user.id),
            "name": options.user.name,
            "displayName": options.user.display_name,
        },
        "pubKeyCredParams": options.pub_key_cred_params,
        "excludeCredentials": exclude_credentials, # This is already correctly formatted
        "authenticatorSelection": options.authenticator_selection,
    }
    return jsonify(response_data)


@app.route("/student/login/options", methods=["POST"])
def student_login_options():
    student_id = request.form.get("student_id")
    if not student_id:
        return "Student ID is required.", 400

    student = get_student_by_student_id(student_id)
    if not student or not student['credential_id']:
        return jsonify({"error": "This student ID is not registered with this device."}), 404

    # FINAL FIX: Manually construct the options to ensure correct serialization.
    # The `options_to_json` helper does not correctly handle the `id` inside `allow_credentials`.
    # 1. Generate a challenge.
    challenge = generate_authentication_options(rp_id=request.host.split(':')[0]).challenge
    session["webauthn_challenge"] = challenge

    # 2. Encode the credential ID from the DB (bytes) into a base64url string for JSON.
    credential_id_b64url = bytes_to_base64url(student['credential_id'])

    # 3. Manually build the options dictionary.
    options = {
        "challenge": bytes_to_base64url(challenge),
        "allowCredentials": [{"type": "public-key", "id": credential_id_b64url}],
        "userVerification": "required",
    }

    return jsonify(options)

@app.route('/teacher/generate-qr/<int:session_id>')
def generate_qr(session_id):
    # Check if teacher owns this session
    teacher_id = session.get("teacher_id")
    if not teacher_id:
        return redirect("/teacher/login")

    with get_connection() as conn:
        with conn.cursor(cursor_factory=psycopg2.extras.DictCursor) as c:
            c.execute("SELECT id, subject_id, date, start_time, time_limit FROM sessions WHERE id = %s AND teacher_id = %s",
                      (session_id, teacher_id))
            sess = c.fetchone()

    if not sess:
        return "<h3>❌ Invalid session or not authorized.</h3><a href='/teacher/dashboard'>Back</a>"

    # Generate QR payload
    expiry = int(time.time()) + 300  # valid 5 minutes
    qr_payload = {"session_id": session_id, "expiry": expiry}

    # Generate QR image
    qr_img = qrcode.make(json.dumps(qr_payload))
    buf = io.BytesIO()
    qr_img.save(buf, format="PNG")
    qr_b64 = base64.b64encode(buf.getvalue()).decode("utf-8")

    return render_template("show_qr.html", session_id=session_id, qr_code=qr_b64, expiry=expiry)

# ✅ Teacher Login
@app.route('/teacher/login-inline', methods=['POST'])
def teacher_login_inline():
    username = request.form.get('teacher_username')
    password = request.form.get('teacher_password')

    with get_connection() as conn:
        with conn.cursor(cursor_factory=psycopg2.extras.DictCursor) as c:
            c.execute("SELECT id, username, password FROM teachers WHERE username = %s", (username,))
            teacher = c.fetchone()
 
    if teacher and check_password_hash(teacher['password'], password):
        session['teacher_id'] = teacher['id']
        session['teacher_name'] = teacher['username']
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

    with get_connection() as conn:
        with conn.cursor(cursor_factory=psycopg2.extras.DictCursor) as c:
            # Fetch departments assigned to this teacher
            c.execute("SELECT department FROM teacher_department WHERE teacher_id = %s", (tid,))
            departments = [row['department'] for row in c.fetchall()]

            # Fetch subjects assigned to this teacher
            c.execute('''
                SELECT s.id, s.subject_name, s.subject_code
                FROM subjects s
                JOIN teacher_subject ts ON s.id = ts.subject_id
                WHERE ts.teacher_id = %s
            ''', (tid,))
            subjects = c.fetchall()

        if request.method == 'POST':
            # This block needs to be inside the 'with' statement for the cursor 'c'
            try:
                subject_id = request.form['subject_id']
                date = request.form['date']
                start_time = request.form['start_time']
                time_limit = int(request.form['time_limit'])
                year_str = request.form['year']
                year_map = {"First": 1, "Second": 2, "Third": 3, "Fourth": 4}
                year = year_map.get(year_str)
                department = request.form['department']

                if department not in departments:
                    return "❌ You are not authorized to create sessions for this department.", 403

                with conn.cursor() as c_insert:
                    c_insert.execute('''
                        INSERT INTO sessions
                        (teacher_id, subject_id, date, start_time, time_limit, year, department)
                        VALUES (%s, %s, %s, %s, %s, %s, %s)
                    ''', (tid, subject_id, date, start_time, time_limit, year, department))
                    conn.commit()

            except Exception as e:
                return f"An error occurred while creating the session: {str(e)}", 500

        with conn.cursor(cursor_factory=psycopg2.extras.DictCursor) as c_select:
            c_select.execute('''
            SELECT sessions.id, subjects.subject_name, sessions.date, sessions.start_time,
                   sessions.time_limit, sessions.year, sessions.department
            FROM sessions
            JOIN subjects ON sessions.subject_id = subjects.id
            WHERE sessions.teacher_id = %s
            ORDER BY sessions.date DESC, sessions.start_time DESC
            ''', (tid,))
            sessions = c_select.fetchall()

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

    with get_connection() as conn:
        with conn.cursor(cursor_factory=psycopg2.extras.DictCursor) as c:
            # Get session details: date, subject name, and year
            c.execute('''
                SELECT sessions.date, sessions.year, sessions.department, subjects.subject_name
                FROM sessions
                JOIN subjects ON sessions.subject_id = subjects.id
                WHERE sessions.id = %s
            ''', (session_id,))
            session_data = c.fetchone()

        if not session_data:
            return "Session not found."

        date, year, department, subject_name = session_data

        # Sanitize subject name for use in filename
        safe_subject = re.sub(r'[^A-Za-z0-9]+', '_', subject_name)

        # Fetch attendance data within the same cursor context
        with conn.cursor(cursor_factory=psycopg2.extras.DictCursor) as c:
            c.execute('''SELECT students.name, students.roll_no, students.department, attendance.time
                         FROM attendance
                         JOIN students ON attendance.student_id = students.id
                         WHERE attendance.session_id = %s''', (session_id,))
            rows = c.fetchall()

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

# ✅ Admin Routes
@app.route('/admin/login-inline', methods=['POST'])
def admin_login_inline():
    username = request.form.get('admin_username')
    password = request.form.get('admin_password')

    with get_connection() as conn:
        with conn.cursor(cursor_factory=psycopg2.extras.DictCursor) as c:
            c.execute("SELECT id, password FROM admins WHERE username = %s", (username,))
            admin = c.fetchone()
 
    if admin and check_password_hash(admin['password'], password):
        session['admin_id'] = admin['id']
        session['admin_username'] = username
        return redirect('/admin/dashboard')
    else:
        return render_template('home.html', admin_error="❌ Invalid admin credentials.")


@app.route('/admin/dashboard')
def admin_dashboard():
    if 'admin_id' not in session:
        return redirect('/')

    with get_connection() as conn:
        with conn.cursor() as c:
            c.execute("SELECT COUNT(*) FROM students")
            student_count = c.fetchone()[0]
            c.execute("SELECT COUNT(*) FROM sessions WHERE date = %s", (datetime.now().date().isoformat(),))
            today_sessions = c.fetchone()[0]

    return render_template('admin_dashboard.html',
                           student_count=student_count,
                           today_sessions=today_sessions)

@app.route('/admin/edit-student/<int:student_id>', methods=['GET', 'POST'])
def edit_student(student_id):
    if 'admin_id' not in session:
        return redirect('/')

    with get_connection() as conn:
        with conn.cursor(cursor_factory=psycopg2.extras.DictCursor) as c:

            if request.method == 'POST':
                name = request.form['name']
                department = request.form['department']
                student_id_val = request.form['student_id']
                roll_no = request.form['roll_no']
                email = request.form['email']
                year = request.form['year']

                c.execute('''UPDATE students
                            SET name=%s, department=%s, student_id=%s, roll_no=%s, email=%s, year=%s
                            WHERE id=%s''',
                        (name, department, student_id_val, roll_no, email, year, student_id))
                conn.commit()
                return redirect('/admin/manage-students')

            c.execute("SELECT * FROM students WHERE id = %s", (student_id,))
            student = c.fetchone()

            c.execute("SELECT name FROM departments")
            departments = [row['name'] for row in c.fetchall()]

    return render_template('edit_student.html', student=student, departments=departments)

@app.route('/admin/manage-students')
def manage_students():
    dept_filter = request.args.get('department')
    year_filter = request.args.get('year')

    with get_connection() as conn:
        with conn.cursor(cursor_factory=psycopg2.extras.DictCursor) as c:

            # Get departments for dropdown
            c.execute("SELECT * FROM departments")
            departments = c.fetchall()

            # Build the filter query
            query = "SELECT id, name, department, student_id, roll_no, email, year FROM students WHERE 1=1"
            params = []

            if dept_filter:
                query += " AND department = %s"
                params.append(dept_filter)
            if year_filter:
                query += " AND year = %s"
                params.append(year_filter)

            c.execute(query, tuple(params))
            students = c.fetchall()

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

    with get_connection() as conn:
        with conn.cursor(cursor_factory=psycopg2.extras.DictCursor) as c:

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
                hashed_password = generate_password_hash(password)

                # Insert new teacher and get the new ID
                c.execute("INSERT INTO teachers (username, password) VALUES (%s, %s) RETURNING id", (username, hashed_password))
                teacher_id = c.fetchone()['id']

                # Assign departments
                for dept in selected_departments:
                    c.execute("INSERT INTO teacher_department (teacher_id, department) VALUES (%s, %s)", (teacher_id, dept))

                # Assign subjects
                for subject_id in selected_subjects:
                    c.execute("INSERT INTO teacher_subject (teacher_id, subject_id) VALUES (%s, %s)", (teacher_id, subject_id))

                conn.commit()

            # PostgreSQL uses STRING_AGG instead of GROUP_CONCAT
            c.execute('''
                SELECT 
                    t.id, 
                    t.username, 
                    STRING_AGG(DISTINCT td.department, ',') as departments,
                    STRING_AGG(DISTINCT s.subject_id::text, ',') as subject_ids
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

    with get_connection() as conn:
        with conn.cursor() as c:

            # Remove all current subject assignments for this teacher
            c.execute("DELETE FROM teacher_subject WHERE teacher_id = %s", (teacher_id,))

            # Add new subject assignments
            for subject_id in selected_subjects:
                c.execute("INSERT INTO teacher_subject (teacher_id, subject_id) VALUES (%s, %s)", (teacher_id, subject_id))

            conn.commit()

    return redirect('/admin/manage-teachers')
@app.route('/admin/update-teacher-departments/<int:teacher_id>', methods=['POST'])
def update_teacher_departments(teacher_id):
    if 'admin_id' not in session:
        return redirect('/')

    selected_departments = request.form.getlist('departments')

    with get_connection() as conn:
        with conn.cursor() as c:

            # Remove existing departments
            c.execute("DELETE FROM teacher_department WHERE teacher_id = %s", (teacher_id,))

            # Insert new selections
            for dept in selected_departments:
                c.execute("INSERT INTO teacher_department (teacher_id, department) VALUES (%s, %s)", (teacher_id, dept))

            conn.commit()

    return redirect('/admin/manage-teachers')

@app.route('/admin/add-subject', methods=['GET', 'POST'])
def add_subject():
    if 'admin_id' not in session:
        return redirect('/')
    with get_connection() as conn:
        with conn.cursor(cursor_factory=psycopg2.extras.DictCursor) as c:

            edit_subject = None

            if request.method == 'POST':
                subject_id = request.form.get('subject_id')
                name = request.form.get('subject_name')
                code = request.form.get('subject_code')

                if subject_id:  # Update
                    c.execute("UPDATE subjects SET subject_name = %s, subject_code = %s WHERE id = %s", (name, code, subject_id))
                else:  # Add
                    try:
                        c.execute("INSERT INTO subjects (subject_name, subject_code) VALUES (%s, %s)", (name, code))
                    except psycopg2.IntegrityError:
                        return "❌ Subject code already exists!"

                conn.commit()

            c.execute("SELECT id, subject_name, subject_code FROM subjects")
            subjects = c.fetchall()
    return render_template("add_subject.html", subjects=subjects, edit_subject=edit_subject)


@app.route('/admin/edit-subject/<int:subject_id>')
def edit_subject(subject_id):
    if 'admin_id' not in session:
        return redirect('/')

    with get_connection() as conn:
        with conn.cursor(cursor_factory=psycopg2.extras.DictCursor) as c:
            c.execute("SELECT id, subject_name, subject_code FROM subjects WHERE id = %s", (subject_id,))
            subject = c.fetchone()
            c.execute("SELECT id, subject_name, subject_code FROM subjects")
            subjects = c.fetchall()

    if subject:
        subject_dict = {'id': subject['id'], 'subject_name': subject['subject_name'], 'subject_code': subject['subject_code']}
        return render_template("add_subject.html", subjects=subjects, edit_subject=subject_dict)
    else:
        return redirect('/admin/add-subject')


@app.route('/admin/delete-subject/<int:subject_id>')
def delete_subject(subject_id):
    if 'admin_id' not in session:
        return redirect('/')

    with get_connection() as conn:
        with conn.cursor() as c:
            c.execute("DELETE FROM subjects WHERE id = %s", (subject_id,))
            conn.commit()
    return redirect('/admin/add-subject')

@app.route('/admin/update-teacher/<int:teacher_id>', methods=['POST'])
def update_teacher_department(teacher_id):
    if 'admin_id' not in session: # Fixed session check
        return redirect('/admin/login')

    new_departments = request.form.getlist('departments')

    with get_connection() as conn:
        with conn.cursor() as c:
            
            # Clear old departments
            c.execute("DELETE FROM teacher_department WHERE teacher_id = %s", (teacher_id,))

            # Insert new ones
            for dept in new_departments:
                c.execute("INSERT INTO teacher_department (teacher_id, department) VALUES (%s, %s)", (teacher_id, dept))

            conn.commit()
    return redirect('/admin/manage-teachers')
@app.route('/admin/manage-departments', methods=['GET', 'POST'])
def manage_departments():
    if 'admin_id' not in session:
        return redirect('/')

    with get_connection() as conn:
        with conn.cursor(cursor_factory=psycopg2.extras.DictCursor) as c:

            if request.method == 'POST':
                action = request.form.get('action')
                if action == 'add':
                    dept_name = request.form.get('dept_name')
                    if dept_name:
                        try:
                            c.execute("INSERT INTO departments (name) VALUES (%s)", (dept_name,))
                            conn.commit()
                        except psycopg2.IntegrityError:
                            return "❌ Department already exists."
                elif action == 'delete':
                    dept_id = request.form.get('dept_id')
                    c.execute("DELETE FROM departments WHERE id = %s", (dept_id,))
                    conn.commit()
                elif action == 'update':
                    dept_id = request.form.get('dept_id')
                    new_name = request.form.get('new_name')
                    c.execute("UPDATE departments SET name = %s WHERE id = %s", (new_name, dept_id))
                    conn.commit()

            c.execute("SELECT id, name FROM departments")
            departments = c.fetchall()


    return render_template("manage_departments.html", departments=departments)

@app.route('/admin/reset-teacher-password/<int:teacher_id>', methods=['POST'])
def reset_teacher_password(teacher_id):
    if 'admin_id' not in session:
        return redirect('/')

    new_password = request.form['new_password']
    hashed_password = generate_password_hash(new_password)

    with get_connection() as conn:
        with conn.cursor() as c:
            c.execute("UPDATE teachers SET password = %s WHERE id = %s", (hashed_password, teacher_id))
            conn.commit()
 
    return redirect('/admin/manage-teachers')
@app.route('/admin/edit-teacher/<int:teacher_id>')
def edit_teacher(teacher_id):
    if 'admin_id' not in session:
        return redirect('/')
    
    with get_connection() as conn:
        with conn.cursor(cursor_factory=psycopg2.extras.DictCursor) as c:
            c.execute("SELECT username FROM teachers WHERE id = %s", (teacher_id,))
            row = c.fetchone()
            if not row:
                return redirect('/admin/manage-teachers')

            username = row['username']
            c.execute("SELECT department FROM teacher_department WHERE teacher_id = %s", (teacher_id,))
            departments = [d['department'] for d in c.fetchall()]
            c.execute("SELECT * FROM departments")
            all_departments = c.fetchall()
            c.execute('''SELECT t.id, t.username, STRING_AGG(td.department, ',') as departments
                        FROM teachers t
                        LEFT JOIN teacher_department td ON t.id = td.teacher_id
                        GROUP BY t.id''')
            teachers = c.fetchall()

    edit_teacher = {'id': teacher_id, 'username': username, 'departments': departments}
    return render_template("manage_teachers.html", edit_teacher=edit_teacher, teachers=teachers, departments=all_departments)

@app.route('/admin/delete-department/<int:dept_id>')
def delete_department_route(dept_id):
    if 'admin_id' not in session:
        return redirect('/admin/login')
    delete_department(dept_id)
    return redirect('/admin/manage-departments')

@app.route('/admin/promote-students', methods=['POST'])
def promote_students_route():
    try:
        promote_students() # Call the utility function from db_utils
        message = "✅ Students promoted to the next academic year successfully."
    except Exception as e:
        message = f"❌ Error during promotion: {e}"
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

    with get_connection() as conn:
        with conn.cursor() as c:
            c.execute("DELETE FROM teacher_subject WHERE teacher_id = %s", (teacher_id,))
            c.execute("DELETE FROM teacher_department WHERE teacher_id = %s", (teacher_id,))
            c.execute("DELETE FROM teachers WHERE id = %s", (teacher_id,))
            conn.commit()
 
    return redirect('/admin/manage-teachers')

@app.route('/admin/edit-department/<int:id>', methods=['GET', 'POST'])
def edit_department(id):
    if request.method == 'POST':
        with get_connection() as conn:
            with conn.cursor() as c:
                new_name = request.form['name']
                c.execute("UPDATE departments SET name = %s WHERE id = %s", (new_name, id))
                conn.commit()
        return redirect('/admin/manage-departments')

    with get_connection() as conn:
        with conn.cursor(cursor_factory=psycopg2.extras.DictCursor) as c:
            c.execute("SELECT id, name FROM departments WHERE id = %s", (id,))
            dept = c.fetchone()
    return render_template("edit_department.html", department=dept)

@app.route('/admin/manage-campuses', methods=['GET', 'POST'])
def manage_campuses():
    with get_connection() as conn:
        c = conn.cursor()

        if request.method == 'POST':
            name = request.form.get('campus_name')
            latitude = request.form.get('latitude')
            longitude = request.form.get('longitude')
            if name and latitude and longitude:
                try:
                    lat = float(latitude)
                    lon = float(longitude)
                    c.execute("INSERT INTO campuses (name, latitude, longitude) VALUES (%s, %s, %s)", (name, lat, lon))
                    conn.commit()
                except ValueError:
                    return "❌ Invalid latitude or longitude."
        
        c.execute("SELECT * FROM campuses")
        campuses = c.fetchall()
    return render_template("manage_campuses.html", campuses=campuses) # type: ignore


@app.route('/admin/delete-campus/<int:campus_id>', methods=['POST'])
def delete_campus(campus_id):
    with get_connection() as conn:
        c = conn.cursor()
        c.execute("DELETE FROM campuses WHERE id = %s", (campus_id,))
        conn.commit()
    return redirect(url_for('manage_campuses'))

@app.route('/admin/delete-student/<int:student_id>', methods=['POST'])
def delete_student(student_id):
    try:
        with get_connection() as conn:
            c = conn.cursor(cursor_factory=psycopg2.extras.DictCursor)
            # The 'device_id' column is removed, but we can keep this structure
            # in case we want to delete other associated data in the future.
            c.execute("SELECT id FROM students WHERE id = %s", (student_id,))
            result = c.fetchone()

            if result:
                # If there were associated files to delete, the logic would go here.
                # For example: os.remove(f"path/to/files/{student_id}.dat")

                c.execute("DELETE FROM students WHERE id = %s", (student_id,))
                conn.commit()
        return redirect(url_for('manage_students'))

    except Exception as e:
        return f"<h3>❌ Error deleting student: {e}</h3><a href='/admin/dashboard'>🏠 Return to Dashboard</a>"

@app.route('/admin/edit-campus/<int:campus_id>', methods=['GET', 'POST'])
def edit_campus(campus_id):
    if request.method == 'POST':
        try:
            name = request.form.get('campus_name')
            latitude = request.form.get('latitude')
            longitude = request.form.get('longitude')
            lat = float(latitude)
            lon = float(longitude)
            with get_connection() as conn:
                c = conn.cursor()
                c.execute("UPDATE campuses SET name = %s, latitude = %s, longitude = %s WHERE id = %s", (name, lat, lon, campus_id))
                conn.commit()
            return redirect(url_for('manage_campuses'))
        except ValueError:
            return "❌ Invalid latitude or longitude."

    with get_connection() as conn:
        c = conn.cursor()
        c.execute("SELECT * FROM campuses WHERE id = %s", (campus_id,)) # type: ignore
        campus = c.fetchone()
    if not campus:
        return "❌ Campus not found."
    return render_template("edit_campus.html", campus=campus)

@app.route('/teacher/session/<int:sid>/delete')
def delete_session(sid):
    if 'teacher_id' not in session:
        return redirect('/teacher/login')
    with get_connection() as conn: # Removed timeout=5 as get_connection does not accept it.
        with conn.cursor() as c:
            c.execute("DELETE FROM sessions WHERE id = %s AND teacher_id = %s", (sid, session['teacher_id']))
    return redirect('/teacher/dashboard')

@app.cli.command("init-db")
def init_db_command():
    """Clear existing data and create new tables."""
    init_db()
    click.echo("Initialized the database.")

# --- DANGEROUS: For one-time database initialization on Render Free Tier ---
# This endpoint will WIPE and RECREATE your entire database.
# 1. Set a very secret key in your Render Environment Variables for SECRET_INIT_KEY.
# 2. Deploy your app.
# 3. Visit https://your-app-name.onrender.com/init-db/your-secret-key ONCE.
# 4. REMOVE the SECRET_INIT_KEY environment variable from Render immediately.
@app.route('/init-db/<secret_key>')
def auto_init_db(secret_key):
    # Get the secret key from environment variables
    env_secret_key = os.getenv('SECRET_INIT_KEY')

    # If the key is not set in the environment, or if the key doesn't match, abort.
    if not env_secret_key or secret_key != env_secret_key:
        from flask import abort
        abort(404) # Return 'Not Found' to hide the endpoint's existence

    try:
        init_db()
        message = "✅ Database has been successfully initialized."
    except Exception as e:
        message = f"❌ An error occurred during database initialization: {e}"
    
    return f"<h3>{message}</h3><p><b>IMPORTANT:</b> Please remove the SECRET_INIT_KEY environment variable from your Render dashboard now.</p>"

if __name__ == '__main__':
    # The 'adhoc' SSL context is for development only.
    # Production servers like Gunicorn handle SSL.
    app.run(host='0.0.0.0', port=5000, debug=True)