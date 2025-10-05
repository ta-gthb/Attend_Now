import sqlite3
from werkzeug.security import generate_password_hash
import os

DB_PATH = "database.db"

def get_connection():
    conn = sqlite3.connect(DB_PATH, check_same_thread=False)
    conn.row_factory = sqlite3.Row  # Access rows as dict-like objects
    return conn

# ------------------ Department Management ------------------ #

def get_all_departments():
    with get_connection() as conn:
        c = conn.cursor()
        c.execute("SELECT id, name FROM departments")
        return c.fetchall()

def add_department(name):
    with get_connection() as conn:
        c = conn.cursor()
        c.execute("INSERT OR IGNORE INTO departments (name) VALUES (?)", (name,))
        conn.commit()

def delete_department(dept_id):
    with get_connection() as conn:
        c = conn.cursor()
        c.execute("DELETE FROM departments WHERE id = ?", (dept_id,))
        conn.commit()

# ------------------ Student Management ------------------ #

def get_student_by_student_id(student_id):
    """Fetches a single student record by their student_id."""
    with get_connection() as conn:
        c = conn.cursor()
        c.execute("SELECT * FROM students WHERE student_id = ?", (student_id,))
        return c.fetchone()

def update_student_sign_count(student_pk_id, new_sign_count):
    """Updates the WebAuthn sign count for a student."""
    with get_connection() as conn:
        conn.execute("UPDATE students SET sign_count = ? WHERE id = ?", (new_sign_count, student_pk_id))

# ------------------ Teacher-Subject & Department Management ------------------ #

def get_teacher_subjects(teacher_id):
    with get_connection() as conn:
        c = conn.cursor()
        c.execute("""
            SELECT subjects.id, subjects.subject_name, subjects.subject_code
            FROM subjects
            JOIN teacher_subject ON subjects.id = teacher_subject.subject_id
            WHERE teacher_subject.teacher_id = ?
        """, (teacher_id,))
        return c.fetchall()

def get_teacher_department(teacher_id):
    with get_connection() as conn:
        c = conn.cursor()
        c.execute("SELECT department FROM teacher_department WHERE teacher_id = ?", (teacher_id,))
        return [row[0] for row in c.fetchall()]

# ------------------ Student Promotion ------------------ #

def promote_students():
    promotion_map = {"Third": "Fourth", "Second": "Third", "First": "Second"}
    with get_connection() as conn:
        c = conn.cursor()
        # First, delete fourth-year students (or they could be archived)
        c.execute("DELETE FROM students WHERE year = ?", ("Fourth",))
        # Then, promote the other years in reverse order to avoid cascading promotions.
        for current_year, next_year in promotion_map.items():
            c.execute("UPDATE students SET year = ? WHERE year = ?", (next_year, current_year))
        conn.commit()

# ------------------ Database Schema Initialization ------------------ #

def init_db():
    with get_connection() as conn:
        c = conn.cursor()

        # Students Table
        c.execute("""
            CREATE TABLE IF NOT EXISTS students (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL,
                department TEXT NOT NULL,
                student_id TEXT NOT NULL UNIQUE,
                roll_no TEXT NOT NULL,
                email TEXT NOT NULL UNIQUE,
                year TEXT NOT NULL,
                -- WebAuthn fields
                credential_id BLOB UNIQUE,
                public_key BLOB,
                sign_count INTEGER,
                UNIQUE(roll_no, department)
            ) -- Removed PIN column
        """)

        # Departments Table
        c.execute("""
            CREATE TABLE IF NOT EXISTS departments (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT UNIQUE NOT NULL
            )
        """)

        # Campuses Table
        c.execute("""
            CREATE TABLE IF NOT EXISTS campuses (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL,
                latitude REAL NOT NULL,
                longitude REAL NOT NULL
            )
        """)

        # Teachers Table
        c.execute("""
            CREATE TABLE IF NOT EXISTS teachers (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT NOT NULL UNIQUE,
                password TEXT NOT NULL
            )
        """)

        # Admins Table
        c.execute("""
            CREATE TABLE IF NOT EXISTS admins (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT NOT NULL UNIQUE,
                password TEXT NOT NULL
            )
        """)

        # Subjects Table
        c.execute("""
            CREATE TABLE IF NOT EXISTS subjects (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                subject_name TEXT NOT NULL,
                subject_code TEXT NOT NULL UNIQUE
            )
        """)

        # Teacher-Subject Assignments
        c.execute("""
            CREATE TABLE IF NOT EXISTS teacher_subject (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                teacher_id INTEGER NOT NULL,
                subject_id INTEGER NOT NULL
            )
        """)

        # Teacher-Department Assignments
        c.execute("""
            CREATE TABLE IF NOT EXISTS teacher_department (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                teacher_id INTEGER NOT NULL,
                department TEXT NOT NULL
            )
        """)

        # Sessions Table
        c.execute("""
            CREATE TABLE IF NOT EXISTS sessions (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                teacher_id INTEGER NOT NULL,
                subject_id INTEGER NOT NULL,
                date TEXT NOT NULL,
                start_time TEXT NOT NULL,
                time_limit INTEGER NOT NULL,
                department TEXT NOT NULL,
                year TEXT NOT NULL
            )
        """)

        # Attendance Records
        c.execute("""
            CREATE TABLE IF NOT EXISTS attendance (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                student_id INTEGER NOT NULL,
                session_id INTEGER NOT NULL,
                date TEXT NOT NULL,
                time TEXT NOT NULL
            )
        """)

        # Default Admin
        c.execute("SELECT * FROM admins WHERE username = ?", ("admin",))
        if not c.fetchone():
            # Load default admin password from environment variable for security
            default_password = os.getenv("DEFAULT_ADMIN_PASSWORD", "admin123")
            hashed_password = generate_password_hash(default_password)
            c.execute("INSERT INTO admins (username, password) VALUES (?, ?)", ("admin", hashed_password))

        conn.commit()
