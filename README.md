https://zainlink.com/

ZainLink is a URL shortener built with Flask, MongoDB, and HTML. Users can sign up, shorten URLs, and manage their shortened links from a dashboard.

---

## 🚀 Features

- ✅ User Signup / Login / Logout 
- 🔒 CAPTCHA protection with Google reCAPTCHA 
- 🧾 Custom or random short links
- 📊 Google Analytics integration 


- 🛠 An admin account which can:
  - View all shortened links
  - Delete any user’s link
- 👤 Users can:
  - View only their links
  - Delete their own links


---

## 🧰 Tech Stack

- Backend: Flask +  PyMongo
- Database: MongoDB 
- Frontend: HTML + JS + CSS 
- Backend Hosting: Render
- Frontend Hosting: Github Pages

---

## 📦 Installation
Create a `.env` file with these variables:

- `RECAPTCHA_SECRET` – Google reCAPTCHA v2 secret key
- `FLASK_SECRET_KEY` – A secret key used to sign session cookies
- `MONGO_URI` – MongoDB connection string 
- `ADMIN_EMAIL` – Email used to create the admin account 
- `ADMIN_PASSWORD` – Password for the admin account 
- `GA_MEASUREMENT_ID` – Google Analytics tag



