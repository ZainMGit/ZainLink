from flask import Flask, request, redirect, jsonify, send_file
import string, random, sqlite3, os, requests
from flask_cors import CORS
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from dotenv import load_dotenv

load_dotenv()

# --- Environment ---
RECAPTCHA_SECRET = os.getenv("RECAPTCHA_SECRET")
FLASK_SECRET_KEY = os.getenv("FLASK_SECRET_KEY")

# --- Setup Flask ---
app = Flask(__name__)
app.config['SESSION_COOKIE_SAMESITE'] = "None"
app.config['SESSION_COOKIE_SECURE'] = True
app.secret_key = FLASK_SECRET_KEY

# --- CORS ---
CORS(app, origins=["https://zainlink.com"], supports_credentials=True)

# --- Login Setup ---
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'serve_auth'

# --- SQLite Setup ---
db_path = 'zainlink.db'
first_time_setup = not os.path.exists(db_path)
conn = sqlite3.connect(db_path, check_same_thread=False)
cur = conn.cursor()

# --- Migrate DB ---
if not first_time_setup:
    cur.execute("PRAGMA table_info(users)")
    if 'username' not in [col[1] for col in cur.fetchall()]:
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
    row = cur.fetchone()
    if row:
        return User(*row)
    return None

# --- Routes ---

@app.route('/auth')
def serve_auth():
    return send_file('auth.html')

@app.route('/')
def homepage():
    return send_file('index.html')

@app.route('/dashboard')
@login_required
def dashboard():
    return send_file('dashboard.html')

@app.route('/api/user')
def get_current_user():
    if current_user.is_authenticated:
        return jsonify({
            'id': current_user.id,
            'email': current_user.email,
            'username': current_user.username,
            'is_admin': current_user.is_admin
        })
    return jsonify({'error': 'Not logged in'}), 401

@app.route('/signup', methods=['POST'])
def signup():
    try:
        data = request.get_json()
        email = data.get('email')
        username = data.get('username')
        password = data.get('password')

        if not email or not username or not password:
            return jsonify({'error': 'All fields are required'}), 400

        hashed_pw = generate_password_hash(password)
        cur.execute("INSERT INTO users (email, username, password) VALUES (?, ?, ?)",
                    (email, username, hashed_pw))
        conn.commit()

        # Log the user in after successful signup
        cur.execute("SELECT id FROM users WHERE email = ?", (email,))
        uid = cur.fetchone()[0]
        login_user(User(uid, email, username, is_admin=False))

        return jsonify({'success': True})

    except sqlite3.IntegrityError:
        return jsonify({'error': 'Email already exists'}), 400
    except Exception as e:
        print("Signup error:", e)
        return jsonify({'error': 'Server error'}), 500

@app.route('/login', methods=['POST'])
def login():
    try:
        data = request.get_json()
        email = data.get('email')
        password = data.get('password')

        if not email or not password:
            return jsonify({"error": "Missing email or password"}), 400

        cur.execute("SELECT id, email, username, password, is_admin FROM users WHERE email = ?", (email,))
        user = cur.fetchone()
        if user and check_password_hash(user[3], password):
            login_user(User(user[0], user[1], user[2], user[4]))
            return jsonify({'success': True})

        return jsonify({'error': 'Invalid credentials'}), 401
    except Exception as e:
        print("Login error:", e)
        return jsonify({'error': 'Server error'}), 500

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return jsonify({'success': True})

@app.route('/shorten', methods=['POST'])
@login_required
def shorten():
    try:
        data = request.get_json()
        original = data.get('original')
        custom = data.get('custom')
        captcha_response = data.get('captcha')

        if not original:
            return jsonify({"error": "Missing 'original' field"}), 400

        if not captcha_response:
            return jsonify({"error": "CAPTCHA token missing"}), 400

        # --- Verify reCAPTCHA ---
        res = requests.post("https://www.google.com/recaptcha/api/siteverify", data={
            'secret': RECAPTCHA_SECRET,
            'response': captcha_response
        })
        if not res.json().get("success"):
            return jsonify({"error": "CAPTCHA verification failed"}), 400

        # --- Generate or check short code ---
        short = custom or generate_short_code()
        cur.execute("SELECT 1 FROM urls WHERE short = ?", (short,))
        if cur.fetchone():
            return jsonify({"error": "Short code already in use"}), 400

        cur.execute("INSERT INTO urls (short, original, user_id) VALUES (?, ?, ?)",
                    (short, original, current_user.id))
        conn.commit()
        return jsonify({"short": short})
    except Exception as e:
        print("Shorten error:", e)
        return jsonify({"error": "Server error"}), 500

@app.route('/<short_code>')
def redirect_url(short_code):
    cur.execute("SELECT original FROM urls WHERE short = ?", (short_code,))
    row = cur.fetchone()
    if row:
        return redirect(row[0])
    return "URL not found", 404

@app.route('/api/links')
@login_required
def api_links():
    if current_user.is_admin:
        cur.execute("SELECT short, original FROM urls")
    else:
        cur.execute("SELECT short, original FROM urls WHERE user_id = ?", (current_user.id,))
    links = [{'short': s, 'original': o} for s, o in cur.fetchall()]
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

# --- Debug log ---
cur.execute("SELECT name FROM sqlite_master WHERE type='table'")
print("Tables in DB:", cur.fetchall())

if __name__ == '__main__':
    app.run(debug=True)
