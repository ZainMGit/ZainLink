from flask import Flask, request, redirect, jsonify, send_file
import string, random, sqlite3
import requests
from flask_cors import CORS
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
import os
from dotenv import load_dotenv


load_dotenv()

RECAPTCHA_SECRET = os.getenv("RECAPTCHA_SECRET")


# --- Setup Flask ---
app = Flask(__name__)
app.config['SESSION_COOKIE_SAMESITE'] = "Lax"
app.config['SESSION_COOKIE_SECURE'] = False
app.secret_key = os.getenv("FLASK_SECRET_KEY")


# --- Enable CORS ---
CORS(app, supports_credentials=True)

# --- Login Setup ---
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'serve_auth'

# --- SQLite Setup ---
db_path = 'zainlink.db'
first_time_setup = not os.path.exists(db_path)
conn = sqlite3.connect(db_path, check_same_thread=False)
cur = conn.cursor()

# --- Migrate Existing DB ---
if not first_time_setup:
    cur.execute("PRAGMA table_info(users)")
    existing_columns = [col[1] for col in cur.fetchall()]
    if 'username' not in existing_columns:
        cur.execute("ALTER TABLE users ADD COLUMN username TEXT NOT NULL DEFAULT 'user'")
        conn.commit()

# --- Create Tables ---
cur.execute('''
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        email TEXT UNIQUE NOT NULL,
        username TEXT NOT NULL,
        password TEXT NOT NULL,
        is_admin BOOLEAN NOT NULL DEFAULT 0
    )
''')

cur.execute('''
    CREATE TABLE IF NOT EXISTS urls (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        short TEXT UNIQUE NOT NULL,
        original TEXT NOT NULL,
        user_id INTEGER,
        FOREIGN KEY (user_id) REFERENCES users(id)
    )
''')

conn.commit()

# --- User Class ---
class User(UserMixin):
    def __init__(self, id_, email, username, is_admin):
        self.id = id_
        self.email = email
        self.username = username
        self.is_admin = is_admin

@login_manager.user_loader
def load_user(user_id):
    cur.execute("SELECT id, email, username, is_admin FROM users WHERE id = ?", (user_id,))
    user = cur.fetchone()
    if user:
        return User(user[0], user[1], user[2], user[3])
    return None

# --- Routes ---

@app.route('/api/user')
@login_required
def get_current_user():
    return jsonify({
        'id': current_user.id,
        'email': current_user.email,
        'username': current_user.username,
        'is_admin': current_user.is_admin
    })

@app.route('/auth')
def serve_auth():
    return send_file('auth.html')

@app.route('/signup', methods=['POST'])
def signup():
    data = request.get_json()
    email = data['email']
    username = data['username']
    password = data['password']
    hashed_pw = generate_password_hash(password)
    try:
        cur.execute("INSERT INTO users (email, username, password) VALUES (?, ?, ?)", (email, username, hashed_pw))
        conn.commit()
        return jsonify({'success': True})
    except sqlite3.IntegrityError:
        return jsonify({'error': 'Email already exists'}), 400

@app.route('/login', methods=['POST'])
def login():
    data = request.get_json()
    email = data['email']
    password = data['password']
    cur.execute("SELECT id, email, username, password, is_admin FROM users WHERE email = ?", (email,))
    user = cur.fetchone()
    if user and check_password_hash(user[3], password):
        login_user(User(user[0], user[1], user[2], user[4]))
        return jsonify({'success': True})
    return jsonify({'error': 'Invalid credentials'}), 401

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return jsonify({'success': True})

def generate_short_code(length=6):
    charset = string.ascii_letters + string.digits
    while True:
        short = ''.join(random.choices(charset, k=length))
        cur.execute("SELECT 1 FROM urls WHERE short=?", (short,))
        if not cur.fetchone():
            return short

# --- Shorten Route with reCAPTCHA ---
@app.route('/shorten', methods=['POST'])
@login_required
def shorten():
    data = request.get_json()
    original = data.get('original')
    custom = data.get('custom')
    captcha_response = data.get('captcha')

    if not original:
        return jsonify({"error": "Missing 'original' field"}), 400

    if not captcha_response:
        return jsonify({"error": "CAPTCHA token missing"}), 400

    # --- Verify reCAPTCHA ---
    verify_url = "https://www.google.com/recaptcha/api/siteverify"
    payload = {
        'secret': RECAPTCHA_SECRET,
        'response': captcha_response
    }
    verify_res = requests.post(verify_url, data=payload)
    verify_result = verify_res.json()

    print("CAPTCHA verify result:", verify_result)  # Optional debug

    if not verify_result.get("success"):
        return jsonify({"error": "CAPTCHA verification failed"}), 400

    # --- Generate short code ---
    short = custom or generate_short_code()
    cur.execute("SELECT 1 FROM urls WHERE short = ?", (short,))
    if cur.fetchone():
        return jsonify({"error": "Short code already in use"}), 400

    try:
        cur.execute("INSERT INTO urls (short, original, user_id) VALUES (?, ?, ?)",
                    (short, original, current_user.id))
        conn.commit()
        return jsonify({"short": short})
    except sqlite3.IntegrityError:
        return jsonify({"error": "Database error"}), 500

@app.route('/<short_code>')
def redirect_url(short_code):
    cur.execute("SELECT original FROM urls WHERE short = ?", (short_code,))
    row = cur.fetchone()
    if row:
        return redirect(row[0])
    return "URL not found", 404

@app.route('/')
def homepage():
    return send_file('index.html')

@app.route('/dashboard')
@login_required
def dashboard():
    return send_file('dashboard.html')

@app.route('/api/links')
@login_required
def api_links():
    if current_user.is_admin:
        cur.execute("SELECT short, original FROM urls")
    else:
        cur.execute("SELECT short, original FROM urls WHERE user_id = ?", (current_user.id,))
    rows = cur.fetchall()
    links = [{'short': row[0], 'original': row[1]} for row in rows]
    return jsonify({'links': links})

@app.route('/delete/<short>', methods=['POST'])
@login_required
def delete_link(short):
    if current_user.is_admin:
        cur.execute("DELETE FROM urls WHERE short = ?", (short,))
    else:
        cur.execute("DELETE FROM urls WHERE short = ? AND user_id = ?", (short, current_user.id))
    conn.commit()
    return '', 204

# --- Debug Tables ---
cur.execute("SELECT name FROM sqlite_master WHERE type='table'")
print("Tables in DB:", cur.fetchall())

if __name__ == '__main__':
    app.run(debug=True)
