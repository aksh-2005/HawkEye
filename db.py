import os
from datetime import datetime
from flask_sqlalchemy import SQLAlchemy
from dotenv import load_dotenv

# Load environment variables from .env file
load_dotenv()

db = SQLAlchemy()

def init_db(app):
    """
    Initializes database connection to Neon PostgreSQL (or fallback SQLite).
    """
    db_url = os.getenv("DATABASE_URL", "sqlite:///hawkeye.db")
    
    # Handle postgres:// vs postgresql:// compatibility
    if db_url.startswith("postgres://"):
        db_url = db_url.replace("postgres://", "postgresql://", 1)
        
    app.config["SQLALCHEMY_DATABASE_URI"] = db_url
    app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
    
    db.init_app(app)
    
    with app.app_context():
        db.create_all()
        # Ensure updated_at, is_admin, and created_at columns exist if migrating existing database
        try:
            from sqlalchemy import text
            db.session.execute(text("ALTER TABLE apps ADD COLUMN IF NOT EXISTS updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP;"))
            db.session.execute(text("ALTER TABLE users ADD COLUMN IF NOT EXISTS is_admin BOOLEAN DEFAULT FALSE;"))
            db.session.execute(text("ALTER TABLE users ADD COLUMN IF NOT EXISTS created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP;"))
            db.session.commit()
        except Exception:
            db.session.rollback()


# =========================================================================
# DATABASE MODELS
# =========================================================================

class User(db.Model):
    """
    User Account model supporting authentication, password hashing, and admin role.
    """
    __tablename__ = "users"
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(255), nullable=False)
    is_admin = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    # Relationships
    apps = db.relationship("AppItem", backref="owner", cascade="all, delete-orphan", lazy=True)


class AppItem(db.Model):
    """
    Monitored Application entity belonging to a user.
    """
    __tablename__ = "apps"
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False)
    app_name = db.Column(db.String(150), nullable=False)
    package_name = db.Column(db.String(200), nullable=False)
    category = db.Column(db.String(100), default="Tools")
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    # Relationships
    permissions = db.relationship("AppPermission", backref="app", cascade="all, delete-orphan", lazy=True)
    snapshots = db.relationship("AppSnapshot", backref="app", cascade="all, delete-orphan", lazy=True)


class AppPermission(db.Model):
    """
    Individual permissions attached to a monitored application.
    """
    __tablename__ = "app_permissions"
    id = db.Column(db.Integer, primary_key=True)
    app_id = db.Column(db.Integer, db.ForeignKey("apps.id"), nullable=False)
    permission_name = db.Column(db.String(200), nullable=False)
    risk_level = db.Column(db.String(20), default="LOW")  # HIGH, MEDIUM, LOW
    is_new = db.Column(db.Boolean, default=False)


class AppSnapshot(db.Model):
    """
    Historical permission snapshot used for 3-way diff comparison and timeline.
    """
    __tablename__ = "app_snapshots"
    id = db.Column(db.Integer, primary_key=True)
    app_id = db.Column(db.Integer, db.ForeignKey("apps.id"), nullable=False)
    snapshot_title = db.Column(db.String(150), nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    added_perms = db.Column(db.Text, default="[]")       # JSON list of newly added permissions
    removed_perms = db.Column(db.Text, default="[]")     # JSON list of removed permissions
    unchanged_perms = db.Column(db.Text, default="[]")   # JSON list of unchanged permissions
    risk_summary = db.Column(db.String(20), default="LOW")
    notes = db.Column(db.String(255), nullable=True)


class CategoryBaseline(db.Model):
    """
    Category baseline table storing aggregated permission frequency percentages.
    """
    __tablename__ = "category_baseline"
    id = db.Column(db.Integer, primary_key=True)
    category = db.Column(db.String(100), nullable=False)
    permission_name = db.Column(db.String(200), nullable=False)
    frequency_percentage = db.Column(db.Float, default=0.0)
    sample_size = db.Column(db.Integer, default=0)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)


