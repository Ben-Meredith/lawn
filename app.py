from flask import Flask, render_template, request, redirect, session, url_for, jsonify
import sqlite3
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime

app = Flask(__name__)
app.secret_key = "supersecretkey"  # change this for production

DB_NAME = 'database.db'

# --- Database setup ---
def init_db():
    conn = sqlite3.connect(DB_NAME)
    c = conn.cursor()
    # Users table
    c.execute('''CREATE TABLE IF NOT EXISTS users (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    name TEXT NOT NULL,
                    email TEXT UNIQUE NOT NULL,
                    phone TEXT,
                    address TEXT,
                    password TEXT NOT NULL,
                    is_admin INTEGER DEFAULT 0
                )''')
    # Reservations table
    c.execute('''CREATE TABLE IF NOT EXISTS reservations (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    user_id INTEGER,
                    date TEXT,
                    time TEXT,
                    address TEXT,
                    FOREIGN KEY(user_id) REFERENCES users(id)
                )''')
    # Create default admin if it doesn't exist
    c.execute("SELECT * FROM users WHERE email = ?", ('admin@lawncare.com',))
    if not c.fetchone():
        hashed_pw = generate_password_hash("admin123")
        c.execute("INSERT INTO users (name, email, phone, address, password, is_admin) VALUES (?,?,?,?,?,?)",
                  ("Admin", "admin@lawncare.com", "", "", hashed_pw, 1))
    conn.commit()
    conn.close()

init_db()

# --- Routes ---
@app.route('/')
def index():
    return render_template('index.html')

@app.route('/about')
def about():
    return render_template('about.html')

@app.route('/pricing')
def pricing():
    return render_template('pricing.html')

# Sign Up
@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        name = request.form['name']
        email = request.form['email']
        phone = request.form['phone']
        address = request.form['address']
        password = generate_password_hash(request.form['password'])

        conn = sqlite3.connect(DB_NAME)
        c = conn.cursor()
        try:
            c.execute("INSERT INTO users (name,email,phone,address,password) VALUES (?,?,?,?,?)",
                      (name,email,phone,address,password))
            conn.commit()
            conn.close()
            return redirect(url_for('login'))
        except sqlite3.IntegrityError:
            conn.close()
            return "Email already exists!"
    return render_template('signup.html')

# Login
@app.route('/login', methods=['GET','POST'])
def login():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']

        conn = sqlite3.connect(DB_NAME)
        c = conn.cursor()
        c.execute("SELECT id, password, is_admin FROM users WHERE email=?", (email,))
        user = c.fetchone()
        conn.close()
        if user and check_password_hash(user[1], password):
            session['user_id'] = user[0]
            session['is_admin'] = bool(user[2])
            return redirect(url_for('index'))
        else:
            return "Invalid credentials!"
    return render_template('login.html')

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('index'))

# Reservations
@app.route('/reservations', methods=['GET','POST'])
def reservations():
    if not session.get('user_id'):
        return redirect(url_for('login'))
    if request.method == 'POST':
        date = request.form['date']
        time = request.form['time']
        user_id = session['user_id']

        conn = sqlite3.connect(DB_NAME)
        c = conn.cursor()
        # Get user's address
        c.execute("SELECT address FROM users WHERE id=?", (user_id,))
        address = c.fetchone()[0]
        c.execute("INSERT INTO reservations (user_id,date,time,address) VALUES (?,?,?,?)",
                  (user_id,date,time,address))
        conn.commit()
        conn.close()
        return redirect(url_for('dashboard'))
    return render_template('reservations.html')

# User dashboard
@app.route('/dashboard')
def dashboard():
    if not session.get('user_id'):
        return redirect(url_for('login'))
    conn = sqlite3.connect(DB_NAME)
    c = conn.cursor()
    c.execute("SELECT date,time,address FROM reservations WHERE user_id=? ORDER BY date,time", (session['user_id'],))
    reservations = [{'date': r[0], 'time': r[1], 'address': r[2]} for r in c.fetchall()]
    conn.close()
    return render_template('dashboard.html', reservations=reservations)

# Admin dashboard
@app.route('/admin')
def admin():
    if not session.get('is_admin'):
        return redirect(url_for('login'))
    conn = sqlite3.connect(DB_NAME)
    c = conn.cursor()
    c.execute("""SELECT reservations.id, users.name, reservations.date, reservations.time, reservations.address
                 FROM reservations JOIN users ON reservations.user_id = users.id""")
    events = []
    for r in c.fetchall():
        # FullCalendar expects ISO dates
        events.append({
            'title': f"{r[1]} - {r[4]}",
            'start': f"{r[2]}T{r[3]}"
        })
    conn.close()
    return render_template('admin.html', reservations=events)

if __name__ == '__main__':
    app.run(debug=True)