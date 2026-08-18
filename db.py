import os
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

# Models
class User(db.Model):
    __tablename__ = "users"
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(255), nullable=False)

class AppItem(db.Model):
    __tablename__ = "apps"
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False)
    app_name = db.Column(db.String(150), nullable=False)
    package_name = db.Column(db.String(200), nullable=False)
    category = db.Column(db.String(100), default="Tools")

class AppPermission(db.Model):
    __tablename__ = "app_permissions"
    id = db.Column(db.Integer, primary_key=True)
    app_id = db.Column(db.Integer, db.ForeignKey("apps.id"), nullable=False)
    permission_name = db.Column(db.String(200), nullable=False)
    risk_level = db.Column(db.String(20), default="LOW") # HIGH, MEDIUM, LOW
    is_new = db.Column(db.Boolean, default=False)

class Alert(db.Model):
    __tablename__ = "alerts"
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False)
    app_id = db.Column(db.Integer, db.ForeignKey("apps.id"), nullable=True)
    message = db.Column(db.String(255), nullable=False)
    risk_level = db.Column(db.String(20), default="HIGH")
    is_read = db.Column(db.Boolean, default=False)
