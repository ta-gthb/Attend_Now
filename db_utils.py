import sqlite3

DB_PATH = "database.db"

def get_connection():
    return sqlite3.connect(DB_PATH, check_same_thread=False)

# ------------------ Department Management ------------------

def get_all_departments():
    conn = get_connection()
    c = conn.cursor()
    c.execute("SELECT id, name FROM departments")
    departments = c.fetchall()
    conn.close()
    return departments

def add_department(name):
    conn = get_connection()
    c = conn.cursor()
    c.execute("INSERT OR IGNORE INTO departments (name) VALUES (?)", (name,))
    conn.commit()
    conn.close()

def delete_department(dept_id):
    conn = get_connection()
    c = conn.cursor()
    c.execute("DELETE FROM departments WHERE id = ?", (dept_id,))
    conn.commit()
    conn.close()

# ------------------ Authentication ------------------

def verify_login(email, password):
    conn = get_connection()
    c = conn.cursor()
    c.execute("SELECT * FROM students WHERE email = ? AND password = ?", (email, password))
    result = c.fetchone()
    conn.close()
    return result

# ------------------ Student Management ------------------

def add_student(name, department, student_id, roll_no, email, year, image_path):
    conn = get_connection()
    c = conn.cursor()
    c.execute('''
        INSERT INTO students (name, department, student_id, roll_no, email, year, image_path)
        VALUES (?, ?, ?, ?, ?, ?, ?)
    ''', (name, department, student_id, roll_no, email, year, image_path))
    conn.commit()
    conn.close()

# ------------------ Teacher-Subject & Department Management ------------------

def get_teacher_subjects(teacher_id):
    conn = get_connection()
    c = conn.cursor()
    c.execute('''
        SELECT subjects.id, subjects.subject_name, subjects.subject_code
        FROM subjects
        JOIN teacher_subject ON subjects.id = teacher_subject.subject_id
        WHERE teacher_subject.teacher_id = ?
    ''', (teacher_id,))
    subjects = c.fetchall()
    conn.close()
    return subjects

def get_teacher_department(teacher_id):
    conn = get_connection()
    c = conn.cursor()
    c.execute('''
        SELECT department FROM teacher_department WHERE teacher_id = ?
    ''', (teacher_id,))
    departments = [row[0] for row in c.fetchall()]
    conn.close()
    return departments
def promote_students():
    conn = get_connection()
    c = conn.cursor()

    # Mapping for promotion
    promotion_map = {
        "First": "Second",
        "Second": "Third",
        "Third": "Fourth"
    }

    # Promote First → Second, Second → Third, Third → Fourth
    for current, next_year in promotion_map.items():
        c.execute("UPDATE students SET year = ? WHERE year = ?", (next_year, current))

    # Delete students from Fourth year (Graduated)
    c.execute("DELETE FROM students WHERE year = ?", ("Fourth",))

    conn.commit()
    conn.close()

# ------------------ Database Schema Initialization ------------------

def init_db():
    conn = get_connection()
    c = conn.cursor()

    # Students Table
    c.execute('''
        CREATE TABLE IF NOT EXISTS students (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            department TEXT NOT NULL,
            student_id TEXT NOT NULL UNIQUE,
            roll_no TEXT NOT NULL,
            email TEXT NOT NULL UNIQUE,
            year TEXT NOT NULL,
            image_path TEXT NOT NULL
        )
    ''')

    # Departments Table
    c.execute('''
        CREATE TABLE IF NOT EXISTS departments (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT UNIQUE NOT NULL
        )
    ''')
    # Campuses Table
    c.execute('''
        CREATE TABLE IF NOT EXISTS campuses (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            latitude REAL NOT NULL,
            longitude REAL NOT NULL
        )
    ''')
    # Teachers Table
    c.execute('''
        CREATE TABLE IF NOT EXISTS teachers (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL UNIQUE,
            password TEXT NOT NULL
        )
    ''')

    # Admins Table
    c.execute('''
        CREATE TABLE IF NOT EXISTS admins (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL UNIQUE,
            password TEXT NOT NULL
        )
    ''')

    # Subjects Table
    c.execute('''
        CREATE TABLE IF NOT EXISTS subjects (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            subject_name TEXT NOT NULL,
            subject_code TEXT NOT NULL UNIQUE
        )
    ''')

    # Teacher-Subject Assignment Table
    c.execute('''
        CREATE TABLE IF NOT EXISTS teacher_subject (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            teacher_id INTEGER NOT NULL,
            subject_id INTEGER NOT NULL
        )
    ''')

    # Teacher-Department Assignment Table
    c.execute('''
        CREATE TABLE IF NOT EXISTS teacher_department (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            teacher_id INTEGER NOT NULL,
            department TEXT NOT NULL
        )
    ''')

    # Attendance Sessions Table
    c.execute('''
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
    ''')

    # Attendance Records Table
    c.execute('''
        CREATE TABLE IF NOT EXISTS attendance (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            student_id INTEGER NOT NULL,
            session_id INTEGER NOT NULL,
            date TEXT NOT NULL,
            time TEXT NOT NULL
        )
    ''')

    # Default admin
    c.execute("SELECT * FROM admins WHERE username = ?", ("admin",))
    if not c.fetchone():
        c.execute("INSERT INTO admins (username, password) VALUES (?, ?)", ("admin", "admin123"))

    conn.commit()
    conn.close()
