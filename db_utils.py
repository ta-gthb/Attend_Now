# d:\B.Tech Projects\AttendNow Web App - Copy\db_utils.py
import os
import psycopg2
import psycopg2.extras
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
        DROP TABLE IF EXISTS students, teachers, admins, departments, subjects, sessions, attendance, teacher_department, teacher_subject, campuses CASCADE;

        CREATE TABLE departments (
            id SERIAL PRIMARY KEY,
            name TEXT UNIQUE NOT NULL
        );

        CREATE TABLE subjects (
            id SERIAL PRIMARY KEY,
            subject_name TEXT NOT NULL,
            subject_code TEXT UNIQUE NOT NULL
        );

        CREATE TABLE students (
            id SERIAL PRIMARY KEY,
            name TEXT NOT NULL,
            department TEXT REFERENCES departments(name),
            student_id TEXT UNIQUE NOT NULL,
            roll_no TEXT NOT NULL,
            email TEXT UNIQUE NOT NULL,
            year INTEGER NOT NULL,
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
            year INTEGER NOT NULL,
            department TEXT REFERENCES departments(name)
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
    """
    with get_connection() as conn:
        with conn.cursor() as cur:
            cur.execute(schema)
        conn.commit()

# --- You can move other DB utility functions here ---

def get_all_departments():
    with get_connection() as conn:
        with conn.cursor(cursor_factory=psycopg2.extras.DictCursor) as cur:
            cur.execute("SELECT name FROM departments ORDER BY name")
            return [row['name'] for row in cur.fetchall()]

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
            # This logic remains the same
            cur.execute("UPDATE students SET year = year + 1 WHERE year < 4")
        conn.commit()

def get_student_by_student_id(student_id):
    with get_connection() as conn:
        with conn.cursor(cursor_factory=psycopg2.extras.DictCursor) as cur:
            cur.execute("SELECT * FROM students WHERE student_id = %s", (student_id,))
            return cur.fetchone()

def update_student_sign_count(student_pk_id, new_count):
    with get_connection() as conn:
        with conn.cursor() as cur:
            cur.execute("UPDATE students SET sign_count = %s WHERE id = %s", (new_count, student_pk_id))
        conn.commit()

