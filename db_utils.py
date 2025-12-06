# d:\B.Tech Projects\AttendNow Web App - Copy\db_utils.py
import os
import psycopg2
import psycopg2.extras
from werkzeug.security import generate_password_hash
from dotenv import load_dotenv

load_dotenv()

DATABASE_URL = os.getenv("DATABASE_URL")

def get_connection():
    """Establishes a connection to the PostgreSQL database."""
    conn = psycopg2.connect(DATABASE_URL)
    return conn

def init_db():
    """
    Initializes the database with the required schema for PostgreSQL.
    This function will drop existing tables and create new ones.
    """
    # PostgreSQL uses BYTEA for binary data and SERIAL for auto-incrementing integers.
    schema = """
        DROP TABLE IF EXISTS students, teachers, admins, departments, subjects, sessions, attendance, teacher_department, teacher_subject, campuses, correction_requests CASCADE;

        CREATE TABLE departments (
            id SERIAL PRIMARY KEY,
            name TEXT UNIQUE NOT NULL
        );

        CREATE TABLE subjects (
            id SERIAL PRIMARY KEY,
            subject_name TEXT NOT NULL,
            subject_code TEXT UNIQUE NOT NULL,
            semester TEXT
        );

        CREATE TABLE students (
            id SERIAL PRIMARY KEY,
            name TEXT NOT NULL,
            department TEXT REFERENCES departments(name),
            student_id TEXT UNIQUE NOT NULL,
            roll_no TEXT NOT NULL,
            email TEXT UNIQUE NOT NULL,
            year TEXT NOT NULL,
            semester TEXT,
            credential_id BYTEA UNIQUE,
            public_key BYTEA,
            sign_count INTEGER,
            UNIQUE(roll_no, department)
        );

        CREATE TABLE teachers (
            id SERIAL PRIMARY KEY,
            username TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL
        );

        CREATE TABLE admins (
            id SERIAL PRIMARY KEY,
            username TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL
        );

        CREATE TABLE sessions (
            id SERIAL PRIMARY KEY,
            teacher_id INTEGER REFERENCES teachers(id),
            subject_id INTEGER REFERENCES subjects(id),
            date DATE NOT NULL,
            start_time TIME NOT NULL,
            time_limit INTEGER NOT NULL,
            qr_code_validity INTEGER,
            year TEXT NOT NULL,
            department TEXT REFERENCES departments(name),
            semester TEXT,
            qr_code_data TEXT,
            qr_code_expiry BIGINT
        );

        CREATE TABLE attendance (
            id SERIAL PRIMARY KEY,
            student_id INTEGER REFERENCES students(id),
            session_id INTEGER REFERENCES sessions(id),
            date DATE NOT NULL,
            time TIME NOT NULL,
            UNIQUE(student_id, session_id)
        );

        CREATE TABLE teacher_department (
            teacher_id INTEGER REFERENCES teachers(id) ON DELETE CASCADE,
            department TEXT REFERENCES departments(name) ON DELETE CASCADE,
            PRIMARY KEY (teacher_id, department)
        );

        CREATE TABLE teacher_subject (
            teacher_id INTEGER REFERENCES teachers(id) ON DELETE CASCADE,
            subject_id INTEGER REFERENCES subjects(id) ON DELETE CASCADE,
            PRIMARY KEY (teacher_id, subject_id)
        );

        CREATE TABLE campuses (
            id SERIAL PRIMARY KEY,
            name TEXT NOT NULL,
            latitude REAL NOT NULL,
            longitude REAL NOT NULL
        );

        CREATE TABLE correction_requests (
            id SERIAL PRIMARY KEY,
            student_id INTEGER REFERENCES students(id),
            message TEXT NOT NULL,
            status TEXT NOT NULL DEFAULT 'pending',
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        );
    """
    with get_connection() as conn:
        with conn.cursor() as cur:
            cur.execute(schema)

            # Add the default admin user
            hashed_password = generate_password_hash('Admin@123')
            cur.execute(
                "INSERT INTO admins (username, password) VALUES (%s, %s)",
                ('admin', hashed_password)
            )
        conn.commit()

# --- You can move other DB utility functions here ---

def get_all_departments():
    with get_connection() as conn:
        with conn.cursor(cursor_factory=psycopg2.extras.DictCursor) as cur:
            cur.execute("SELECT id, name FROM departments ORDER BY name")
            return cur.fetchall()

def add_department(dept_name):
    try:
        with get_connection() as conn:
            with conn.cursor() as cur:
                cur.execute("INSERT INTO departments (name) VALUES (%s)", (dept_name,))
            conn.commit()
    except psycopg2.IntegrityError:
        # Department already exists
        pass

def delete_department(dept_id):
    with get_connection() as conn:
        with conn.cursor() as cur:
            # Need to handle cascades or prevent deletion if in use
            cur.execute("DELETE FROM departments WHERE id = %s", (dept_id,))
        conn.commit()

def promote_students():
    with get_connection() as conn:
        with conn.cursor() as cur:
            # First, delete all students who are in their fourth year.
            cur.execute("DELETE FROM students WHERE year = 'Fourth'")
            # Then, promote the remaining students.
            cur.execute("UPDATE students SET year = 'Fourth' WHERE year = 'Third'")
            cur.execute("UPDATE students SET year = 'Third' WHERE year = 'Second'")
            cur.execute("UPDATE students SET year = 'Second' WHERE year = 'First'")
        conn.commit()

def get_student_by_student_id(student_id):
    with get_connection() as conn:
        with conn.cursor(cursor_factory=psycopg2.extras.DictCursor) as cur:
            cur.execute("SELECT * FROM students WHERE student_id = %s", (student_id,))
            return cur.fetchone()

def get_student_attendance_analytics(student_id):
    with get_connection() as conn:
        with conn.cursor(cursor_factory=psycopg2.extras.DictCursor) as cur:
            cur.execute("""
                SELECT
                    sub.subject_name,
                    sub.subject_code,
                    COUNT(DISTINCT sess.id) AS total_sessions,
                    COUNT(att.id) AS attended_sessions
                FROM
                    sessions sess
                JOIN
                    subjects sub ON sess.subject_id = sub.id
                LEFT JOIN
                    attendance att ON sess.id = att.session_id AND att.student_id = %s
                WHERE
                    -- Optionally filter by student's department/year/semester if desired for a more specific view
                    -- For now, let's assume all sessions student *could* have attended
                    TRUE
                GROUP BY
                    sub.subject_name, sub.subject_code
                ORDER BY
                    sub.subject_name
            """, (student_id,))
            return cur.fetchall()

def get_student_by_id(student_pk_id):
    with get_connection() as conn:
        with conn.cursor(cursor_factory=psycopg2.extras.DictCursor) as cur:
            cur.execute("SELECT * FROM students WHERE id = %s", (student_pk_id,))
            return cur.fetchone()

def update_student_semester(student_id, semester):
    with get_connection() as conn:
        with conn.cursor() as cur:
            cur.execute("UPDATE students SET semester = %s WHERE id = %s", (semester, student_id))
        conn.commit()

def update_student_sign_count(student_pk_id, new_count):
    with get_connection() as conn:
        with conn.cursor() as cur:
            cur.execute("UPDATE students SET sign_count = %s WHERE id = %s", (new_count, student_pk_id))
        conn.commit()

def create_correction_request(student_id, message):
    with get_connection() as conn:
        with conn.cursor() as cur:
            cur.execute(
                "INSERT INTO correction_requests (student_id, message) VALUES (%s, %s)",
                (student_id, message)
            )
        conn.commit()

def get_all_correction_requests():
    with get_connection() as conn:
        with conn.cursor(cursor_factory=psycopg2.extras.DictCursor) as cur:
            cur.execute("""
                SELECT
                    cr.id,
                    cr.message,
                    cr.status,
                    cr.created_at,
                    s.name as student_name,
                    s.student_id
                FROM
                    correction_requests cr
                JOIN
                    students s ON cr.student_id = s.id
                ORDER BY
                    cr.created_at DESC
            """)
            return cur.fetchall()

def update_correction_request_status(request_id, status):
    with get_connection() as conn:
        with conn.cursor() as cur:
            cur.execute(
                "UPDATE correction_requests SET status = %s WHERE id = %s",
                (status, request_id)
            )
        conn.commit()

