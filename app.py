import os
from flask import Flask, render_template, session, redirect, url_for, request, flash
from werkzeug.security import generate_password_hash, check_password_hash
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

@app.route("/login", methods=["GET", "POST"])
def login():
    if session.get('user_id'):
        return redirect(url_for('dashboard'))

    if request.method == "POST":
        username_or_email = request.form.get("username_or_email", "").strip()
        password = request.form.get("password", "")

        if not username_or_email or not password:
            flash("Please enter both username/email and password.", "error")
            return render_template("login.html", active_page="login", username_or_email=username_or_email)

        user = User.query.filter(
            (User.username == username_or_email) | (User.email == username_or_email)
        ).first()

        if user and check_password_hash(user.password_hash, password):
            session['user_id'] = user.id
            session['user_name'] = user.username
            session['user_email'] = user.email
            session['unread_alerts'] = 0
            flash(f"Welcome back, {user.username}!", "success")
            return redirect(url_for('dashboard'))

        flash("Invalid username/email or password.", "error")
        return render_template("login.html", active_page="login", username_or_email=username_or_email)

    return render_template("login.html", active_page="login")

@app.route("/register", methods=["GET", "POST"])
def register():
    if session.get('user_id'):
        return redirect(url_for('dashboard'))

    if request.method == "POST":
        username = request.form.get("username", "").strip()
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")
        confirm_password = request.form.get("confirm_password", "")

        if not username or not email or not password:
            flash("All fields are required.", "error")
            return render_template("register.html", active_page="register", username=username, email=email)

        if len(password) < 6:
            flash("Password must be at least 6 characters long.", "error")
            return render_template("register.html", active_page="register", username=username, email=email)

        if password != confirm_password:
            flash("Passwords do not match.", "error")
            return render_template("register.html", active_page="register", username=username, email=email)

        existing_username = User.query.filter_by(username=username).first()
        if existing_username:
            flash("Username is already taken. Please choose another.", "error")
            return render_template("register.html", active_page="register", username=username, email=email)

        existing_email = User.query.filter_by(email=email).first()
        if existing_email:
            flash("Email address is already registered.", "error")
            return render_template("register.html", active_page="register", username=username, email=email)

        try:
            hashed_pwd = generate_password_hash(password)
            new_user = User(username=username, email=email, password_hash=hashed_pwd)
            db.session.add(new_user)
            db.session.commit()

            flash("Account created successfully! Please log in.", "success")
            return redirect(url_for('login'))
        except Exception as e:
            db.session.rollback()
            flash(f"Error creating account: {str(e)}", "error")
            return render_template("register.html", active_page="register", username=username, email=email)

    return render_template("register.html", active_page="register")

@app.route("/logout")
def logout():
    session.clear()
    flash("You have been successfully logged out.", "info")
    return redirect(url_for('login'))

@app.route("/profile", methods=["GET", "POST"])
def profile():
    user_id = session.get('user_id')
    if not user_id:
        flash("Please log in to access account settings.", "warning")
        return redirect(url_for('login'))

    user = db.session.get(User, user_id)
    if not user:
        session.clear()
        flash("User account not found. Please log in again.", "error")
        return redirect(url_for('login'))

    if request.method == "POST":
        action = request.form.get("action")

        if action == "update_profile":
            username = request.form.get("username", "").strip()
            email = request.form.get("email", "").strip().lower()

            if not username or not email:
                flash("Username and Email are required.", "error")
            else:
                existing_user = User.query.filter(User.username == username, User.id != user.id).first()
                if existing_user:
                    flash("Username is already taken by another user.", "error")
                else:
                    existing_email = User.query.filter(User.email == email, User.id != user.id).first()
                    if existing_email:
                        flash("Email address is already in use by another user.", "error")
                    else:
                        user.username = username
                        user.email = email
                        try:
                            db.session.commit()
                            session['user_name'] = user.username
                            session['user_email'] = user.email
                            flash("Profile details updated successfully!", "success")
                        except Exception as e:
                            db.session.rollback()
                            flash(f"Error updating profile: {str(e)}", "error")

        elif action == "change_password":
            current_password = request.form.get("current_password", "")
            new_password = request.form.get("new_password", "")
            confirm_new_password = request.form.get("confirm_new_password", "")

            if not current_password or not new_password or not confirm_new_password:
                flash("All password fields are required.", "error")
            elif not check_password_hash(user.password_hash, current_password):
                flash("Incorrect current password.", "error")
            elif len(new_password) < 6:
                flash("New password must be at least 6 characters long.", "error")
            elif new_password != confirm_new_password:
                flash("New passwords do not match.", "error")
            else:
                user.password_hash = generate_password_hash(new_password)
                try:
                    db.session.commit()
                    flash("Password updated successfully!", "success")
                except Exception as e:
                    db.session.rollback()
                    flash(f"Error updating password: {str(e)}", "error")

        return redirect(url_for('profile'))

    app_count = AppItem.query.filter_by(user_id=user.id).count() if user else 0
    alert_count = Alert.query.filter_by(user_id=user.id, is_read=False).count() if user else 0

    return render_template("profile.html", active_page="profile", page_title="Account Settings", user=user, app_count=app_count, alert_count=alert_count)

@app.route("/api/status")
def status():
    return {"status": "online", "app": "HawkEye - App Privilege Analyzer", "version": "1.0"}

if __name__ == "__main__":
    import socket
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        local_ip = s.getsockname()[0]
        s.close()
    except Exception:
        local_ip = "127.0.0.1"
    
    print(f"\n  * Local PC access:      http://localhost:5000")
    print(f"  * Local Network access: http://{local_ip}:5000\n")
    app.run(host="0.0.0.0", port=5000, debug=True)

