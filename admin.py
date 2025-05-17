from pymongo import MongoClient
from werkzeug.security import generate_password_hash
from dotenv import load_dotenv
import os

load_dotenv()


ADMIN_EMAIL= os.getenv("ADMIN_EMAIL")
ADMIN_PASSWORD= os.getenv("ADMIN_PASSWORD")

# Connect to MongoDB
client = MongoClient(os.getenv("MONGO_URI"))
db = client["zainlink"]
users_col = db["users"]

# Admin credentials
username = "admin"
email = ADMIN_EMAIL
password = ADMIN_PASSWORD  
hashed_pw = generate_password_hash(password)

# Check if admin already exists
if users_col.find_one({"email": email}):
    print("Admin account already exists.")
else:
    users_col.insert_one({
        "email": email,
        "username": username,
        "password": hashed_pw,
        "is_admin": True
    })
    print("Admin account created successfully.")
