from flask import Flask, request, redirect, jsonify, send_file
import string, random, sqlite3
from flask_cors import CORS
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
import os

# --- Setup Flask ---
app = Flask(__name__)
app.config['SESSION_COOKIE_SAMESITE'] = "Lax"
app.config['SESSION_COOKIE_SECURE'] = False  # Set to True if using HTTPS

app.secret_key = 'super-secret-zain-key'

# --- Proper CORS configuration ---
CORS(app, supports_credentials=True)

# --- Setup Login ---
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'serve_auth'

# --- Connect to SQLite ---
db_path = 'zainlink.db'
first_time_setup = not os.path.exists(db_path)
conn = sqlite3.connect(db_path, check_same_thread=False)
cur = conn.cursor()

# --- Migrate DB if needed ---
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

@app.route('/api/user')
@login_required
def get_current_user():
    return jsonify({
        'id': current_user.id,
        'email': current_user.email,
        'username': current_user.username,
        'is_admin': current_user.is_admin
    })

@login_manager.user_loader
def load_user(user_id):
    cur.execute("SELECT id, email, username, is_admin FROM users WHERE id = ?", (user_id,))
    user = cur.fetchone()
    if user:
        return User(user[0], user[1], user[2], user[3])
    return None

# --- Auth Routes ---
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

# --- Shortener ---
def generate_short_code(length=6):
    charset = string.ascii_letters + string.digits
    while True:
        short = ''.join(random.choices(charset, k=length))
        cur.execute("SELECT 1 FROM urls WHERE short=?", (short,))
        if not cur.fetchone():
            return short

@app.route('/shorten', methods=['POST'])
@login_required
def shorten():
    data = request.get_json()
    original = data.get('original')
    custom = data.get('custom')

    if not original:
        return jsonify({"error": "Missing 'original' field"}), 400

    cur.execute("SELECT short FROM urls WHERE original = ? AND user_id = ?", (original, current_user.id))
    existing = cur.fetchone()
    if existing:
        return jsonify({"short": existing[0]})

    short = custom or generate_short_code()
    try:
        cur.execute("INSERT INTO urls (short, original, user_id) VALUES (?, ?, ?)",
                    (short, original, current_user.id))
        conn.commit()
        return jsonify({"short": short})
    except sqlite3.IntegrityError:
        return jsonify({"error": "Short code already in use"}), 400

# --- Redirect Shortlink ---
@app.route('/<short_code>')
def redirect_url(short_code):
    cur.execute("SELECT original FROM urls WHERE short = ?", (short_code,))
    row = cur.fetchone()
    if row:
        return redirect(row[0])
    return "URL not found", 404

# --- Dashboard & Pages ---
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

# --- Debug: Confirm Tables ---
cur.execute("SELECT name FROM sqlite_master WHERE type='table'")
print("Tables in DB:", cur.fetchall())

# --- Run the app ---
if __name__ == '__main__':
    app.run(debug=True)
