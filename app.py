from flask import Flask, request, redirect, jsonify, send_file
import string, random, requests, os
from flask_cors import CORS
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from pymongo import MongoClient
from bson.objectid import ObjectId
from dotenv import load_dotenv

load_dotenv()

# --- Environment Variables ---
RECAPTCHA_SECRET = os.getenv("RECAPTCHA_SECRET")
MONGO_URI = os.getenv("MONGO_URI")
FLASK_SECRET_KEY = os.getenv("FLASK_SECRET_KEY")

# --- Flask Setup ---
app = Flask(__name__)
app.secret_key = FLASK_SECRET_KEY
app.config['SESSION_COOKIE_SECURE'] = True
app.config['SESSION_COOKIE_SAMESITE'] = "None"

# --- Redirect onrender.com to custom domain ---
@app.before_request
def enforce_domain():
    if request.host != "zainlink.com":
        return redirect(f"https://zainlink.com{request.full_path}", code=301)

# --- CORS Setup ---
CORS(app, origins=["https://zainlink.com"], supports_credentials=True)

# --- Login Setup ---
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'serve_auth'

# --- MongoDB Setup ---
client = MongoClient(MONGO_URI)
db = client["zainlink"]
users_col = db["users"]
urls_col = db["urls"]

# --- User Class ---
class User(UserMixin):
    def __init__(self, id_, email, username, is_admin):
        self.id = id_
        self.email = email
        self.username = username
        self.is_admin = is_admin

@login_manager.user_loader
def load_user(user_id):
    try:
        user = users_col.find_one({"_id": ObjectId(user_id)})
        if user:
            return User(str(user["_id"]), user["email"], user["username"], user.get("is_admin", False))
    except Exception as e:
        print("Error loading user:", e)
    return None

# --- Short Code Generator ---
def generate_short_code(length=6):
    charset = string.ascii_letters + string.digits
    while True:
        short = ''.join(random.choices(charset, k=length))
        if not urls_col.find_one({"short": short}):
            return short

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
    email = data.get('email')
    username = data.get('username')
    password = data.get('password')

    if not email or not username or not password:
        return jsonify({'error': 'Missing fields'}), 400

    if users_col.find_one({"email": email}):
        return jsonify({'error': 'Email already exists'}), 400

    hashed_pw = generate_password_hash(password)
    users_col.insert_one({
        "email": email,
        "username": username,
        "password": hashed_pw,
        "is_admin": False
    })
    return jsonify({'success': True})

@app.route('/login', methods=['POST'])
def login():
    data = request.get_json()
    email = data.get('email')
    password = data.get('password')

    if not email or not password:
        return jsonify({"error": "Missing email or password"}), 400

    user = users_col.find_one({"email": email})
    if user and check_password_hash(user["password"], password):
        login_user(User(str(user["_id"]), user["email"], user["username"], user.get("is_admin", False)))
        return jsonify({'success': True})
    return jsonify({'error': 'Invalid credentials'}), 401

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

        if not original or not captcha_response:
            return jsonify({"error": "Missing URL or CAPTCHA"}), 400

        verify_res = requests.post(
            "https://www.google.com/recaptcha/api/siteverify",
            data={'secret': RECAPTCHA_SECRET, 'response': captcha_response}
        ).json()

        if not verify_res.get("success"):
            return jsonify({"error": "CAPTCHA verification failed"}), 400

        short = custom or generate_short_code()
        if urls_col.find_one({"short": short}):
            return jsonify({"error": "Short code already in use"}), 400

        urls_col.insert_one({
            "short": short,
            "original": original,
            "user_id": ObjectId(current_user.id)
        })
        return jsonify({"short": short})

    except Exception as e:
        print("Shorten error:", e)
        return jsonify({"error": "Server error"}), 500

@app.route('/<short_code>')
def redirect_url(short_code):
    url = urls_col.find_one({"short": short_code})
    if url:
        original_url = url["original"]
        return f"""
        <html>
        <head>
            <meta http-equiv='refresh' content='0;url={original_url}' />
            <script>window.location.href = '{original_url}';</script>
        </head>
        <body>
            Redirecting to <a href="{original_url}">{original_url}</a>...
        </body>
        </html>
        """
    return "URL not found", 404

@app.route('/ping')
def ping():
    return "pong", 200

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
    query = {} if current_user.is_admin else {"user_id": ObjectId(current_user.id)}
    urls = urls_col.find(query)
    links = [{'short': url['short'], 'original': url['original']} for url in urls]
    return jsonify({'links': links})

@app.route('/delete/<short>', methods=['POST'])
@login_required
def delete_link(short):
    query = {"short": short}
    if not current_user.is_admin:
        query["user_id"] = ObjectId(current_user.id)
    urls_col.delete_one(query)
    return '', 204

if __name__ == '__main__':
    app.run(debug=True)
