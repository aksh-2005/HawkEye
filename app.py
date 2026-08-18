import os
from flask import Flask, render_template, session, redirect, url_for, request
from dotenv import load_dotenv
from db import init_db, db, User, AppItem, AppPermission, Alert

load_dotenv()

app = Flask(__name__)
app.secret_key = os.getenv("SECRET_KEY", "hawkeye_cyber_security_secret_key_demo")

# Initialize Neon DB connection
try:
    init_db(app)
    print("Database connection initialized successfully!")
except Exception as e:
    print(f"Database initialization warning: {e}")

@app.route("/")
def home():
    return render_template("home.html", active_page="home")

@app.route("/about")
def about():
    return render_template("home.html", active_page="about")

@app.route("/dashboard")
def dashboard():
    return render_template("home.html", active_page="dashboard", page_title="Dashboard - App Privilege Analyzer")

@app.route("/my-apps")
def my_apps():
    return render_template("home.html", active_page="my_apps", page_title="My Monitored Apps")

@app.route("/alerts")
def alerts():
    session['unread_alerts'] = 0
    return render_template("home.html", active_page="alerts", page_title="High Risk Privilege Flags")

@app.route("/apps/add")
def add_app():
    return render_template("home.html", active_page="add_app", page_title="Add New Application")

@app.route("/login")
def login():
    return render_template("home.html", active_page="login", page_title="Analyst Login")

@app.route("/register")
def register():
    return render_template("home.html", active_page="register", page_title="Sign Up for HawkEye")

# Demo routes to test guest vs logged-in state
@app.route("/demo/login")
def demo_login():
    session['user_id'] = "USR-88421"
    session['user_name'] = "Alex Mercer"
    session['user_email'] = "alex.mercer@sec.hawkeye.io"
    session['unread_alerts'] = 3
    return redirect(url_for('home'))

@app.route("/demo/logout")
@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for('home'))

@app.route("/demo/toggle-alerts")
def toggle_alerts():
    if session.get('unread_alerts', 0) > 0:
        session['unread_alerts'] = 0
    else:
        session['unread_alerts'] = 5
    return redirect(request.referrer or url_for('home'))

@app.route("/api/status")
def status():
    return {"status": "online", "app": "HawkEye - App Privilege Analyzer", "version": "1.0"}

if __name__ == "__main__":
    app.run(debug=True, port=5000)
