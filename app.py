import os
import json
from datetime import datetime, timedelta
from flask import Flask, render_template, session, redirect, url_for, request, flash, jsonify
from werkzeug.security import generate_password_hash, check_password_hash
from dotenv import load_dotenv

from db import init_db, db, User, AppItem, AppPermission, AppSnapshot, CategoryBaseline
from scraper_utils import (
    search_playstore_apps,
    fetch_app_details,
    fetch_app_permissions_for_snapshot,
    build_category_baseline_data,
    compare_permissions,
    PERMISSION_RISK_MAP,
    SCRAPER_AVAILABLE
)

load_dotenv()

app = Flask(__name__)
app.secret_key = os.getenv("SECRET_KEY", "hawkeye_cyber_security_secret_key_demo")

# Initialize database connection (PostgreSQL / SQLite fallback)
try:
    init_db(app)
    print("Database connection initialized successfully!")
except Exception as e:
    print(f"Database initialization warning: {e}")

# Category Baseline Knowledge Matrix for Android apps (Feature 5)
CATEGORY_BASELINES = {
    "Tools": {
        "common": ["INTERNET", "ACCESS_NETWORK_STATE", "ACCESS_WIFI_STATE", "VIBRATE", "WAKE_LOCK"],
        "unusual": ["RECORD_AUDIO", "CAMERA", "READ_CONTACTS", "WRITE_CONTACTS", "READ_SMS", "RECEIVE_SMS", "SEND_SMS", "ACCESS_FINE_LOCATION", "READ_CALL_LOG", "SYSTEM_ALERT_WINDOW", "PACKAGE_USAGE_STATS"]
    },
    "Social": {
        "common": ["INTERNET", "ACCESS_NETWORK_STATE", "CAMERA", "RECORD_AUDIO", "READ_CONTACTS", "READ_EXTERNAL_STORAGE", "WRITE_EXTERNAL_STORAGE", "VIBRATE", "ACCESS_COARSE_LOCATION"],
        "unusual": ["READ_SMS", "RECEIVE_SMS", "SEND_SMS", "SYSTEM_ALERT_WINDOW", "PACKAGE_USAGE_STATS", "WRITE_SETTINGS", "READ_CALL_LOG"]
    },
    "Finance": {
        "common": ["INTERNET", "ACCESS_NETWORK_STATE", "RECEIVE_SMS", "VIBRATE", "WAKE_LOCK", "ACCESS_WIFI_STATE"],
        "unusual": ["RECORD_AUDIO", "READ_CONTACTS", "WRITE_CONTACTS", "READ_CALL_LOG", "SYSTEM_ALERT_WINDOW", "PACKAGE_USAGE_STATS", "BLUETOOTH_ADMIN", "ACCESS_BACKGROUND_LOCATION"]
    },
    "Productivity": {
        "common": ["INTERNET", "ACCESS_NETWORK_STATE", "READ_EXTERNAL_STORAGE", "WRITE_EXTERNAL_STORAGE", "GET_ACCOUNTS", "VIBRATE", "WAKE_LOCK"],
        "unusual": ["RECORD_AUDIO", "READ_SMS", "SEND_SMS", "READ_CALL_LOG", "SYSTEM_ALERT_WINDOW", "ACCESS_BACKGROUND_LOCATION"]
    },
    "Entertainment": {
        "common": ["INTERNET", "ACCESS_NETWORK_STATE", "ACCESS_WIFI_STATE", "READ_EXTERNAL_STORAGE", "RECORD_AUDIO", "WAKE_LOCK", "VIBRATE"],
        "unusual": ["READ_CONTACTS", "WRITE_CONTACTS", "READ_SMS", "RECEIVE_SMS", "SEND_SMS", "READ_CALL_LOG", "ACCESS_FINE_LOCATION", "SYSTEM_ALERT_WINDOW"]
    },
    "Photography": {
        "common": ["CAMERA", "READ_EXTERNAL_STORAGE", "WRITE_EXTERNAL_STORAGE", "INTERNET", "RECORD_AUDIO", "VIBRATE"],
        "unusual": ["READ_CONTACTS", "WRITE_CONTACTS", "READ_SMS", "RECEIVE_SMS", "SEND_SMS", "READ_CALL_LOG", "ACCESS_BACKGROUND_LOCATION", "SYSTEM_ALERT_WINDOW"]
    },
    "Health": {
        "common": ["ACCESS_FINE_LOCATION", "ACCESS_COARSE_LOCATION", "ACCESS_BACKGROUND_LOCATION", "INTERNET", "ACCESS_NETWORK_STATE", "VIBRATE", "WAKE_LOCK"],
        "unusual": ["READ_CONTACTS", "WRITE_CONTACTS", "READ_SMS", "RECEIVE_SMS", "SEND_SMS", "READ_CALL_LOG", "RECORD_AUDIO", "SYSTEM_ALERT_WINDOW"]
    }
}

def get_baseline_status(category, permission_name):
    """
    Evaluates whether a permission is 'Common for this category' or 'Unusual for this category'.
    """
    cat = category if category in CATEGORY_BASELINES else "Tools"
    cat_rule = CATEGORY_BASELINES.get(cat, CATEGORY_BASELINES["Tools"])
    common_list = cat_rule.get("common", [])
    unusual_list = cat_rule.get("unusual", [])

    if permission_name in unusual_list:
        return {
            "status": "unusual",
            "label": f"Unusual for {cat}",
            "short_label": "Unusual",
            "is_unusual": True,
            "badge_class": "baseline-unusual",
            "icon": "fa-solid fa-triangle-exclamation"
        }
    elif permission_name in common_list:
        return {
            "status": "common",
            "label": f"Common for {cat}",
            "short_label": "Common",
            "is_unusual": False,
            "badge_class": "baseline-common",
            "icon": "fa-solid fa-circle-check"
        }
    else:
        risk = PERMISSION_RISK_MAP.get(permission_name, ("LOW", ""))[0]
        if risk == "HIGH":
            return {
                "status": "unusual",
                "label": f"Unusual for {cat}",
                "short_label": "Unusual",
                "is_unusual": True,
                "badge_class": "baseline-unusual",
                "icon": "fa-solid fa-triangle-exclamation"
            }
        else:
            return {
                "status": "common",
                "label": f"Standard for {cat}",
                "short_label": "Standard",
                "is_unusual": False,
                "badge_class": "baseline-common",
                "icon": "fa-solid fa-circle-check"
            }


# =========================================================================
# PUBLIC / MARKETING ROUTES
# =========================================================================

@app.route("/")
def home():
    return render_template("home.html", active_page="home")

@app.route("/about")
def about():
    return render_template("home.html", active_page="about")

@app.route("/my-apps")
def my_apps():
    return redirect(url_for("dashboard"))


# =========================================================================
# USER AUTHENTICATION & PROFILE
# =========================================================================

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
            session['is_admin'] = user.is_admin or (user.username.lower() == 'admin')
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
            is_admin_user = (username.lower() == "admin")
            new_user = User(username=username, email=email, password_hash=hashed_pwd, is_admin=is_admin_user)
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
    return render_template("profile.html", active_page="profile", page_title="Account Settings", user=user, app_count=app_count)


# =========================================================================
# ADMIN MODULE
# =========================================================================

@app.route("/admin/users")
def admin_users():
    user_id = session.get('user_id')
    if not user_id:
        flash("Please log in to access administrator views.", "warning")
        return redirect(url_for("login"))

    current_user = db.session.get(User, user_id)
    if not current_user or not (current_user.is_admin or current_user.username.lower() == "admin"):
        flash("Access denied: Administrator privileges required.", "error")
        return redirect(url_for("dashboard"))

    # Fetch all registered users with app counts
    all_users = User.query.order_by(User.id.asc()).all()
    user_list = []
    for u in all_users:
        apps_count = AppItem.query.filter_by(user_id=u.id).count()
        user_list.append({
            "id": u.id,
            "username": u.username,
            "email": u.email,
            "is_admin": u.is_admin or (u.username.lower() == "admin"),
            "apps_count": apps_count,
            "created_at": u.created_at.strftime("%Y-%m-%d %H:%M") if u.created_at else "N/A"
        })

    return render_template("admin_users.html", active_page="admin_users", page_title="User Management - Admin", users=user_list)


# =========================================================================
# MAIN DASHBOARD
# =========================================================================

@app.route("/dashboard")
def dashboard():
    user_id = session.get('user_id')
    if not user_id:
        flash("Please log in to access your dashboard.", "info")
        return redirect(url_for("login"))

    user = db.session.get(User, user_id)
    if not user:
        session.clear()
        flash("User account not found. Please log in again.", "error")
        return redirect(url_for("login"))

    user_apps = AppItem.query.filter_by(user_id=user.id).order_by(AppItem.updated_at.desc(), AppItem.id.desc()).all()
    
    total_apps_count = len(user_apps)
    high_risk_count = 0
    med_risk_count = 0
    low_risk_count = 0
    total_permissions_count = 0
    recently_updated_count = 0
    apps_summary = []
    category_counts = {}

    cutoff_recent = datetime.utcnow() - timedelta(days=7)

    for app_item in user_apps:
        cat = app_item.category or "Tools"
        category_counts[cat] = category_counts.get(cat, 0) + 1

        permissions = AppPermission.query.filter_by(app_id=app_item.id).all()
        app_high = sum(1 for p in permissions if p.risk_level == 'HIGH')
        app_med = sum(1 for p in permissions if p.risk_level == 'MEDIUM')
        app_low = sum(1 for p in permissions if p.risk_level == 'LOW')
        app_total = len(permissions)
        has_new_perms = any(p.is_new for p in permissions)

        is_recently_updated = (app_item.updated_at and app_item.updated_at >= cutoff_recent) or has_new_perms
        if is_recently_updated:
            recently_updated_count += 1

        high_risk_count += app_high
        med_risk_count += app_med
        low_risk_count += app_low
        total_permissions_count += app_total

        # Risk level determination
        if app_high > 0:
            max_risk = 'HIGH'
        elif app_med > 0:
            max_risk = 'MEDIUM'
        elif app_low > 0:
            max_risk = 'LOW'
        else:
            max_risk = 'SAFE'

        formatted_perms = []
        newly_added_list = []
        unchanged_list = []

        for p in permissions:
            desc = PERMISSION_RISK_MAP.get(p.permission_name, ("", "Custom permission flag"))[1]
            baseline_info = get_baseline_status(cat, p.permission_name)
            perm_obj = {
                "id": p.id,
                "name": p.permission_name,
                "risk": p.risk_level,
                "is_new": p.is_new,
                "desc": desc,
                "baseline": baseline_info
            }
            formatted_perms.append(perm_obj)

            if p.is_new:
                newly_added_list.append(perm_obj)
            else:
                unchanged_list.append(perm_obj)

        # Retrieve App Snapshots for Timeline & 3-Column Diff View
        snapshots_db = AppSnapshot.query.filter_by(app_id=app_item.id).order_by(AppSnapshot.timestamp.desc()).all()
        timeline_events = []
        diff_removed_list = []

        if snapshots_db:
            latest_snap = snapshots_db[0]
            try:
                latest_added = json.loads(latest_snap.added_perms or "[]")
                latest_removed = json.loads(latest_snap.removed_perms or "[]")
                latest_unchanged = json.loads(latest_snap.unchanged_perms or "[]")
            except Exception:
                latest_added, latest_removed, latest_unchanged = [], [], []

            if latest_added:
                newly_added_list = []
                for item in latest_added:
                    pname = item.get("name", item) if isinstance(item, dict) else item
                    prisk = item.get("risk", PERMISSION_RISK_MAP.get(pname, ("LOW", ""))[0]) if isinstance(item, dict) else PERMISSION_RISK_MAP.get(pname, ("LOW", ""))[0]
                    pdesc = item.get("desc", PERMISSION_RISK_MAP.get(pname, ("", ""))[1]) if isinstance(item, dict) else PERMISSION_RISK_MAP.get(pname, ("", ""))[1]
                    newly_added_list.append({
                        "id": 0,
                        "name": pname,
                        "risk": prisk,
                        "is_new": True,
                        "desc": pdesc,
                        "baseline": get_baseline_status(cat, pname)
                    })

            if latest_removed:
                for item in latest_removed:
                    pname = item.get("name", item) if isinstance(item, dict) else item
                    prisk = item.get("risk", PERMISSION_RISK_MAP.get(pname, ("LOW", ""))[0]) if isinstance(item, dict) else PERMISSION_RISK_MAP.get(pname, ("LOW", ""))[0]
                    diff_removed_list.append({
                        "name": pname,
                        "risk": prisk,
                        "desc": PERMISSION_RISK_MAP.get(pname, ("", "Revoked permission"))[1],
                        "baseline": get_baseline_status(cat, pname)
                    })

            for s in snapshots_db:
                try:
                    s_added = json.loads(s.added_perms or "[]")
                    s_removed = json.loads(s.removed_perms or "[]")
                    s_unchanged = json.loads(s.unchanged_perms or "[]")
                except Exception:
                    s_added, s_removed, s_unchanged = [], [], []

                timeline_events.append({
                    "id": s.id,
                    "title": s.snapshot_title,
                    "date": s.timestamp.strftime("%b %d, %Y - %H:%M UTC") if s.timestamp else "Recently",
                    "added_perms": s_added,
                    "removed_perms": s_removed,
                    "unchanged_perms": s_unchanged,
                    "risk_summary": s.risk_summary,
                    "notes": s.notes
                })
        else:
            timeline_events.append({
                "id": 0,
                "title": "Initial Baseline Scan & Registration",
                "date": app_item.updated_at.strftime("%b %d, %Y - %H:%M UTC") if app_item.updated_at else "Initial Scan",
                "added_perms": [p["name"] for p in newly_added_list],
                "removed_perms": [],
                "unchanged_perms": [p["name"] for p in unchanged_list],
                "risk_summary": max_risk,
                "notes": f"Initial app package registration with {app_total} monitored permissions."
            })

        apps_summary.append({
            "id": app_item.id,
            "app_name": app_item.app_name,
            "package_name": app_item.package_name,
            "category": app_item.category,
            "updated_at": app_item.updated_at.strftime("%Y-%m-%d %H:%M") if app_item.updated_at else "N/A",
            "updated_at_timestamp": int(app_item.updated_at.timestamp()) if app_item.updated_at else 0,
            "is_recently_updated": is_recently_updated,
            "total_permissions": app_total,
            "high_risk": app_high,
            "med_risk": app_med,
            "low_risk": app_low,
            "max_risk": max_risk,
            "permissions": formatted_perms,
            "diff_added": newly_added_list,
            "diff_removed": diff_removed_list,
            "diff_unchanged": unchanged_list,
            "timeline": timeline_events
        })

    return render_template(
        "dashboard.html",
        active_page="dashboard",
        page_title="Dashboard - HawkEye",
        user=user,
        user_apps=apps_summary,
        total_apps_count=total_apps_count,
        total_permissions_count=total_permissions_count,
        high_risk_count=high_risk_count,
        med_risk_count=med_risk_count,
        low_risk_count=low_risk_count,
        recently_updated_count=recently_updated_count,
        category_counts=category_counts,
        available_permissions=PERMISSION_RISK_MAP,
        category_baselines=CATEGORY_BASELINES
    )


# =========================================================================
# APPLICATION MANAGEMENT & PERMISSION DIFF OPERATIONS
# =========================================================================

@app.route("/apps/add", methods=["POST"])
def add_app():
    user_id = session.get('user_id')
    if not user_id:
        flash("Please log in to add an application.", "warning")
        return redirect(url_for("login"))

    user = db.session.get(User, user_id)
    if not user:
        return redirect(url_for("login"))

    app_name = request.form.get("app_name", "").strip()
    package_name = request.form.get("package_name", "").strip().lower()
    category = request.form.get("category", "Tools").strip()
    selected_perms = request.form.getlist("permissions")
    custom_perm = request.form.get("custom_permission", "").strip().upper()

    if not app_name or not package_name:
        flash("Application Name and Package ID are required.", "error")
        return redirect(url_for("dashboard"))

    existing = AppItem.query.filter_by(user_id=user.id, package_name=package_name).first()
    if existing:
        flash(f"Application with package '{package_name}' is already being monitored.", "warning")
        return redirect(url_for("dashboard"))

    try:
        new_app = AppItem(
            user_id=user.id,
            app_name=app_name,
            package_name=package_name,
            category=category,
            updated_at=datetime.utcnow()
        )
        db.session.add(new_app)
        db.session.flush()

        if custom_perm and custom_perm not in selected_perms:
            selected_perms.append(custom_perm)

        high_count = 0
        added_perms_list = []
        for perm_name in selected_perms:
            risk_info = PERMISSION_RISK_MAP.get(perm_name, ("LOW", ""))
            risk_level = risk_info[0] if isinstance(risk_info, tuple) else "LOW"
            if risk_level == "HIGH":
                high_count += 1

            p = AppPermission(
                app_id=new_app.id,
                permission_name=perm_name,
                risk_level=risk_level,
                is_new=False
            )
            db.session.add(p)
            added_perms_list.append({"name": perm_name, "risk": risk_level})

        # Create Initial Baseline Snapshot for Timeline
        init_snapshot = AppSnapshot(
            app_id=new_app.id,
            snapshot_title="v1.0.0 Initial Ingestion Baseline",
            timestamp=datetime.utcnow(),
            added_perms=json.dumps(added_perms_list),
            removed_perms=json.dumps([]),
            unchanged_perms=json.dumps([]),
            risk_summary="HIGH" if high_count > 0 else "LOW",
            notes=f"Initial registration with {len(selected_perms)} permissions."
        )
        db.session.add(init_snapshot)
        db.session.commit()
        flash(f"Application '{app_name}' ({package_name}) added successfully!", "success")
    except Exception as e:
        db.session.rollback()
        flash(f"Error adding application: {str(e)}", "error")

    return redirect(url_for("dashboard"))

@app.route("/apps/delete/<int:app_id>", methods=["POST"])
def delete_app(app_id):
    user_id = session.get('user_id')
    if not user_id:
        flash("Please log in first.", "error")
        return redirect(url_for("login"))

    app_item = AppItem.query.filter_by(id=app_id, user_id=user_id).first()
    if not app_item:
        flash("Application not found.", "error")
        return redirect(url_for("dashboard"))

    try:
        # Cascade deletes permissions and snapshots automatically via relationships
        db.session.delete(app_item)
        db.session.commit()
        flash(f"Application '{app_item.app_name}' successfully removed from monitoring.", "info")
    except Exception as e:
        db.session.rollback()
        flash(f"Error deleting application: {str(e)}", "error")

    return redirect(url_for("dashboard"))

@app.route("/apps/add-permission/<int:app_id>", methods=["POST"])
def add_app_permission(app_id):
    user_id = session.get('user_id')
    if not user_id:
        flash("Please log in first.", "error")
        return redirect(url_for("login"))

    app_item = AppItem.query.filter_by(id=app_id, user_id=user_id).first()
    if not app_item:
        flash("Application not found.", "error")
        return redirect(url_for("dashboard"))

    permission_name = request.form.get("permission_name", "").strip().upper()
    if not permission_name:
        flash("Permission name is required.", "error")
        return redirect(url_for("dashboard"))

    existing_p = AppPermission.query.filter_by(app_id=app_item.id, permission_name=permission_name).first()
    if existing_p:
        flash(f"Permission '{permission_name}' is already attached to {app_item.app_name}.", "info")
        return redirect(url_for("dashboard"))

    risk_info = PERMISSION_RISK_MAP.get(permission_name, ("LOW", ""))
    risk_level = risk_info[0] if isinstance(risk_info, tuple) else "LOW"

    try:
        existing_perms = [p.permission_name for p in AppPermission.query.filter_by(app_id=app_item.id).all()]

        new_perm = AppPermission(
            app_id=app_item.id,
            permission_name=permission_name,
            risk_level=risk_level,
            is_new=True
        )
        db.session.add(new_perm)

        app_item.updated_at = datetime.utcnow()

        # Create Snapshot documenting this permission update
        new_snap = AppSnapshot(
            app_id=app_item.id,
            snapshot_title="Manual Privilege Escalation Test",
            timestamp=datetime.utcnow(),
            added_perms=json.dumps([{"name": permission_name, "risk": risk_level}]),
            removed_perms=json.dumps([]),
            unchanged_perms=json.dumps(existing_perms),
            risk_summary=risk_level,
            notes=f"Requested new {risk_level} risk permission [{permission_name}]."
        )
        db.session.add(new_snap)
        db.session.commit()
        flash(f"New permission '{permission_name}' added and flagged in 3-way diff!", "warning" if risk_level == "HIGH" else "success")
    except Exception as e:
        db.session.rollback()
        flash(f"Error adding permission: {str(e)}", "error")

    return redirect(url_for("dashboard"))

@app.route("/apps/recheck/<int:app_id>", methods=["POST"])
def recheck_app_permissions(app_id):
    """
    Re-fetches current permissions via Google Play Scraper, compares against the
    stored permissions using Python set operations (added/removed/unchanged), and saves
    a new snapshot if differences are detected.
    """
    user_id = session.get('user_id')
    if not user_id:
        flash("Please log in first.", "error")
        return redirect(url_for("login"))

    app_item = AppItem.query.filter_by(id=app_id, user_id=user_id).first()
    if not app_item:
        flash("Application not found in your monitored inventory.", "error")
        return redirect(url_for("dashboard"))

    try:
        live_perms = fetch_app_permissions_for_snapshot(app_item.package_name)
        if not live_perms:
            details = fetch_app_details(app_item.package_name)
            if details and details.get("permissions"):
                live_perms = details["permissions"]

        if not live_perms:
            flash(f"Could not retrieve live permissions for '{app_item.app_name}' ({app_item.package_name}) from Google Play. App may be region-restricted or unavailable.", "warning")
            return redirect(url_for("dashboard"))

        stored_perms = AppPermission.query.filter_by(app_id=app_item.id).all()
        stored_perm_names = [p.permission_name for p in stored_perms]
        live_perm_names = [p["name"] for p in live_perms]

        # Compare using Python set operations in scraper_utils
        diff = compare_permissions(stored_perm_names, live_perm_names)

        if not diff["has_changed"]:
            flash(f"Re-check Complete: '{app_item.app_name}' permissions match existing baseline ({len(live_perm_names)} permissions verified).", "info")
            return redirect(url_for("dashboard"))

        # Changes detected: Update DB permissions and save new snapshot
        app_item.updated_at = datetime.utcnow()

        removed_names = [p["name"] for p in diff["removed"]]
        if removed_names:
            AppPermission.query.filter(
                AppPermission.app_id == app_item.id,
                AppPermission.permission_name.in_(removed_names)
            ).delete(synchronize_session=False)

        for p in stored_perms:
            if p.permission_name not in removed_names:
                p.is_new = False

        for added_p in diff["added"]:
            new_p = AppPermission(
                app_id=app_item.id,
                permission_name=added_p["name"],
                risk_level=added_p["risk"],
                is_new=True
            )
            db.session.add(new_p)

        added_count = len(diff["added"])
        removed_count = len(diff["removed"])
        snap = AppSnapshot(
            app_id=app_item.id,
            snapshot_title=f"Live Play Store Audit (+{added_count}, -{removed_count})",
            timestamp=datetime.utcnow(),
            added_perms=json.dumps(diff["added"]),
            removed_perms=json.dumps(diff["removed"]),
            unchanged_perms=json.dumps([p["name"] for p in diff["unchanged"]]),
            risk_summary=diff["highest_new_risk"],
            notes=f"Automated Play Store sync detected: {diff['summary']}."
        )
        db.session.add(snap)
        db.session.commit()
        flash(f"Live Re-check Completed for '{app_item.app_name}': {diff['summary']}. New snapshot recorded!", "warning" if diff["highest_new_risk"] == "HIGH" else "success")

    except Exception as e:
        db.session.rollback()
        flash(f"Error during live Play Store re-check: {str(e)}", "error")

    return redirect(url_for("dashboard"))

@app.route("/dashboard/seed-demo", methods=["POST"])
def seed_demo_data():
    """
    Seeds comprehensive demo data with multiple categories, snapshots, and permission diffs.
    """
    user_id = session.get('user_id')
    if not user_id:
        flash("Please log in first.", "error")
        return redirect(url_for("login"))

    demo_apps = [
        {
            "name": "QuickLens Camera & Filters",
            "package": "com.photo.quicklens",
            "category": "Photography",
            "perms": [
                ("CAMERA", "HIGH", False),
                ("READ_EXTERNAL_STORAGE", "MEDIUM", False),
                ("WRITE_EXTERNAL_STORAGE", "MEDIUM", False),
                ("INTERNET", "LOW", False),
                ("RECORD_AUDIO", "HIGH", True),
                ("READ_CONTACTS", "HIGH", True)
            ],
            "snapshots": [
                {
                    "title": "v1.2.0 - Core Photo Release",
                    "days_ago": 18,
                    "added": ["CAMERA", "READ_EXTERNAL_STORAGE", "WRITE_EXTERNAL_STORAGE", "INTERNET"],
                    "removed": [],
                    "unchanged": [],
                    "risk": "HIGH",
                    "notes": "Initial verified release on Play Store."
                },
                {
                    "title": "v2.0.1 - Play Store Feature Update",
                    "days_ago": 2,
                    "added": [{"name": "RECORD_AUDIO", "risk": "HIGH"}, {"name": "READ_CONTACTS", "risk": "HIGH"}],
                    "removed": [],
                    "unchanged": ["CAMERA", "READ_EXTERNAL_STORAGE", "WRITE_EXTERNAL_STORAGE", "INTERNET"],
                    "risk": "HIGH",
                    "notes": "Privilege creep detected: Microphone and Contact list requested."
                }
            ]
        },
        {
            "name": "NovaPay Digital Wallet",
            "package": "com.finance.novapay",
            "category": "Finance",
            "perms": [
                ("INTERNET", "LOW", False),
                ("ACCESS_NETWORK_STATE", "LOW", False),
                ("RECEIVE_SMS", "HIGH", False),
                ("VIBRATE", "LOW", False),
                ("SYSTEM_ALERT_WINDOW", "HIGH", True)
            ],
            "snapshots": [
                {
                    "title": "v3.1.0 - Standard Release",
                    "days_ago": 30,
                    "added": ["INTERNET", "ACCESS_NETWORK_STATE", "RECEIVE_SMS", "VIBRATE"],
                    "removed": [],
                    "unchanged": [],
                    "risk": "HIGH",
                    "notes": "Banking baseline verified."
                },
                {
                    "title": "v3.4.0 - Suspicious Update",
                    "days_ago": 1,
                    "added": [{"name": "SYSTEM_ALERT_WINDOW", "risk": "HIGH"}],
                    "removed": [],
                    "unchanged": ["INTERNET", "ACCESS_NETWORK_STATE", "RECEIVE_SMS", "VIBRATE"],
                    "risk": "HIGH",
                    "notes": "Tapjacking risk: Draw overlay permission requested."
                }
            ]
        },
        {
            "name": "PulseFit Workout Tracker",
            "package": "com.health.pulsefit",
            "category": "Health",
            "perms": [
                ("ACCESS_FINE_LOCATION", "HIGH", False),
                ("ACCESS_COARSE_LOCATION", "MEDIUM", False),
                ("INTERNET", "LOW", False),
                ("ACCESS_NETWORK_STATE", "LOW", False),
                ("VIBRATE", "LOW", False),
                ("WAKE_LOCK", "LOW", False)
            ],
            "snapshots": [
                {
                    "title": "v1.0.0 - Clean Install Baseline",
                    "days_ago": 14,
                    "added": ["ACCESS_FINE_LOCATION", "ACCESS_COARSE_LOCATION", "INTERNET", "ACCESS_NETWORK_STATE", "VIBRATE", "WAKE_LOCK"],
                    "removed": [],
                    "unchanged": [],
                    "risk": "HIGH",
                    "notes": "GPS tracking baseline matches verified health profile."
                }
            ]
        },
        {
            "name": "OmniCalc & Unit Converter",
            "package": "com.tools.omnicalc",
            "category": "Tools",
            "perms": [
                ("VIBRATE", "LOW", False),
                ("WAKE_LOCK", "LOW", False)
            ],
            "snapshots": [
                {
                    "title": "v2.1.0 - Offline Utility Baseline",
                    "days_ago": 45,
                    "added": ["VIBRATE", "WAKE_LOCK"],
                    "removed": [],
                    "unchanged": [],
                    "risk": "SAFE",
                    "notes": "Completely offline, low-privilege utility."
                }
            ]
        }
    ]

    try:
        now = datetime.utcnow()
        for d in demo_apps:
            existing = AppItem.query.filter_by(user_id=user_id, package_name=d["package"]).first()
            if not existing:
                app_item = AppItem(
                    user_id=user_id,
                    app_name=d["name"],
                    package_name=d["package"],
                    category=d["category"],
                    updated_at=now
                )
                db.session.add(app_item)
                db.session.flush()

                for pname, prisk, pnew in d["perms"]:
                    p = AppPermission(
                        app_id=app_item.id,
                        permission_name=pname,
                        risk_level=prisk,
                        is_new=pnew
                    )
                    db.session.add(p)

                for snap in d["snapshots"]:
                    s = AppSnapshot(
                        app_id=app_item.id,
                        snapshot_title=snap["title"],
                        timestamp=now - timedelta(days=snap["days_ago"]),
                        added_perms=json.dumps(snap["added"]),
                        removed_perms=json.dumps(snap["removed"]),
                        unchanged_perms=json.dumps(snap["unchanged"]),
                        risk_summary=snap["risk"],
                        notes=snap["notes"]
                    )
                    db.session.add(s)

        db.session.commit()
        flash("Sample demo apps loaded successfully with snapshot history and permission diffs!", "success")
    except Exception as e:
        db.session.rollback()
        flash(f"Error seeding demo data: {str(e)}", "error")

    return redirect(url_for("dashboard"))


# =========================================================================
# GOOGLE PLAY SCRAPER INTEGRATION APIS
# =========================================================================

@app.route("/api/playstore/search", methods=["GET"])
def api_playstore_search():
    """
    Play Store Search API: Returns matching apps for autocomplete.
    """
    query = request.args.get("q", "").strip()
    if not query:
        return jsonify({"results": []})
    
    try:
        results = search_playstore_apps(query, n_hits=5)
        return jsonify({"results": results})
    except Exception as e:
        return jsonify({"error": str(e), "results": []}), 500

@app.route("/api/playstore/app/<path:package_id>", methods=["GET"])
def api_playstore_app_details(package_id):
    """
    Play Store App Details API: Returns metadata and normalized permissions.
    """
    if not package_id:
        return jsonify({"error": "Missing package_id parameter"}), 400

    try:
        details = fetch_app_details(package_id)
        if not details:
            return jsonify({"error": f"App '{package_id}' not found on Google Play Store."}), 404
        return jsonify(details)
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route("/api/playstore/build-baseline", methods=["POST"])
def api_build_baseline():
    """
    Builds category baseline by scraping top apps and storing frequency percentages.
    """
    user_id = session.get('user_id')
    if not user_id:
        return jsonify({"error": "Authentication required"}), 401

    category = request.form.get("category") or (request.json and request.json.get("category")) or "Tools"
    num_apps = int(request.form.get("num_apps") or (request.json and request.json.get("num_apps")) or 8)

    try:
        baseline_result = build_category_baseline_data(category, num_apps=num_apps)
        freqs = baseline_result.get("frequencies", {})
        sample_size = baseline_result.get("sample_size", 0)

        now = datetime.utcnow()
        for perm_name, freq_pct in freqs.items():
            existing = CategoryBaseline.query.filter_by(category=category, permission_name=perm_name).first()
            if existing:
                existing.frequency_percentage = freq_pct
                existing.sample_size = sample_size
                existing.updated_at = now
            else:
                new_entry = CategoryBaseline(
                    category=category,
                    permission_name=perm_name,
                    frequency_percentage=freq_pct,
                    sample_size=sample_size,
                    updated_at=now
                )
                db.session.add(new_entry)
        
        db.session.commit()

        if request.is_json or request.headers.get("X-Requested-With") == "XMLHttpRequest":
            return jsonify({
                "success": True,
                "category": category,
                "sample_size": sample_size,
                "sampled_apps": baseline_result.get("sampled_apps", []),
                "frequencies": freqs,
                "message": f"Successfully compiled Play Store baseline for '{category}' using {sample_size} popular apps."
            })

        flash(f"Category baseline updated for '{category}' using {sample_size} top Play Store apps!", "success")
        return redirect(url_for("dashboard"))
    except Exception as e:
        db.session.rollback()
        if request.is_json or request.headers.get("X-Requested-With") == "XMLHttpRequest":
            return jsonify({"error": str(e)}), 500
        flash(f"Error building category baseline: {str(e)}", "error")
        return redirect(url_for("dashboard"))

@app.route("/api/status")
def status():
    return {"status": "online", "app": "HawkEye - App Privilege Analyzer", "version": "1.0"}


if __name__ == "__main__":
    app.run(debug=True)
