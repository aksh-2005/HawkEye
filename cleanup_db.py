"""
HawkEye - Database Cleanup & Maintenance Script
================================================
This script:
1. Drops the deprecated 'alerts' table if it exists.
2. Ensures all active tables ('users', 'apps', 'app_permissions', 'app_snapshots', 'category_baseline')
   match the updated schema.
3. Cleans up any orphan records.
4. Optionally wipes and recreates fresh tables if run with `--reset`.

Usage:
  python cleanup_db.py           # Standard cleanup (removes alerts table, fixes schema, cleans orphans)
  python cleanup_db.py --reset   # Complete database reset & fresh tables recreation
"""

import argparse
import sys
from sqlalchemy import text
from app import app
from db import db, User, AppItem, AppPermission, AppSnapshot, CategoryBaseline

def cleanup_database(reset=False):
    with app.app_context():
        engine = db.engine
        print(f"\n[*] Connecting to database: {engine.url.render_as_string(hide_password=True)}")

        if reset:
            print("[!] WARNING: Full reset requested. Dropping all existing tables...")
            try:
                # Try CASCADE drop for PostgreSQL
                with engine.connect() as conn:
                    conn.execute(text("DROP TABLE IF EXISTS alerts CASCADE;"))
                    conn.execute(text("DROP TABLE IF EXISTS app_permissions CASCADE;"))
                    conn.execute(text("DROP TABLE IF EXISTS app_snapshots CASCADE;"))
                    conn.execute(text("DROP TABLE IF EXISTS apps CASCADE;"))
                    conn.execute(text("DROP TABLE IF EXISTS category_baseline CASCADE;"))
                    conn.execute(text("DROP TABLE IF EXISTS users CASCADE;"))
                    conn.commit()
                print("[OK] All old tables dropped successfully.")
            except Exception as e:
                print(f"[!] Note on table drop: {e}")
                db.drop_all()

            print("[*] Recreating fresh schema from SQLAlchemy models...")
            db.create_all()
            print("[OK] Fresh tables created successfully!")
            
            # Create a default admin user if none exists
            from werkzeug.security import generate_password_hash
            default_admin = User(
                username="admin",
                email="admin@hawkeye.local",
                password_hash=generate_password_hash("admin123"),
                is_admin=True
            )
            db.session.add(default_admin)
            db.session.commit()
            print("[OK] Created default Administrator account:")
            print("    Username : admin")
            print("    Email    : admin@hawkeye.local")
            print("    Password : admin123\n")
            return

        # Standard Cleanup
        print("[*] Performing standard database cleanup...")
        with engine.connect() as conn:
            # 1. Drop deprecated alerts table
            try:
                conn.execute(text("DROP TABLE IF EXISTS alerts CASCADE;"))
                conn.commit()
                print("[OK] Deprecated 'alerts' table removed.")
            except Exception as e:
                print(f"[!] Info removing alerts table: {e}")

            # 2. Ensure columns exist on PostgreSQL / SQLite
            try:
                conn.execute(text("ALTER TABLE apps ADD COLUMN IF NOT EXISTS updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP;"))
                conn.execute(text("ALTER TABLE users ADD COLUMN IF NOT EXISTS is_admin BOOLEAN DEFAULT FALSE;"))
                conn.execute(text("ALTER TABLE users ADD COLUMN IF NOT EXISTS created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP;"))
                conn.commit()
                print("[OK] Verified all required table columns.")
            except Exception as e:
                # SQLite doesn't support IF NOT EXISTS on ALTER TABLE, but create_all handles it
                pass

        # 3. Create any missing model tables
        db.create_all()

        # 4. Remove orphan records
        try:
            valid_app_ids = [a.id for a in AppItem.query.all()]
            if valid_app_ids:
                orphan_perms = AppPermission.query.filter(~AppPermission.app_id.in_(valid_app_ids)).delete(synchronize_session=False)
                orphan_snaps = AppSnapshot.query.filter(~AppSnapshot.app_id.in_(valid_app_ids)).delete(synchronize_session=False)
            else:
                orphan_perms = AppPermission.query.delete()
                orphan_snaps = AppSnapshot.query.delete()

            valid_user_ids = [u.id for u in User.query.all()]
            if valid_user_ids:
                orphan_apps = AppItem.query.filter(~AppItem.user_id.in_(valid_user_ids)).delete(synchronize_session=False)
            else:
                orphan_apps = AppItem.query.delete()

            db.session.commit()
            if orphan_perms or orphan_snaps or orphan_apps:
                print(f"[OK] Cleaned orphan records: {orphan_apps} apps, {orphan_perms} permissions, {orphan_snaps} snapshots.")
            else:
                print("[OK] No orphan records found.")
        except Exception as e:
            db.session.rollback()
            print(f"[!] Note on orphan cleanup: {e}")

        # 5. Display Table Summary
        print("\n================ CURRENT DATABASE SUMMARY ================")
        user_count = User.query.count()
        app_count = AppItem.query.count()
        perm_count = AppPermission.query.count()
        snap_count = AppSnapshot.query.count()
        baseline_count = CategoryBaseline.query.count()

        print(f"  - Users              : {user_count} records")
        print(f"  - Apps               : {app_count} records")
        print(f"  - Permissions        : {perm_count} records")
        print(f"  - Snapshots          : {snap_count} records")
        print(f"  - Category Baselines : {baseline_count} records")
        print("==========================================================\n")
        print("[OK] Database cleanup completed successfully!\n")

def main():
    parser = argparse.ArgumentParser(description="HawkEye Database Cleanup & Maintenance")
    parser.add_argument("--reset", action="store_true", help="Wipe all data and recreate fresh tables with a default admin account")
    args = parser.parse_args()

    cleanup_database(reset=args.reset)

if __name__ == "__main__":
    main()
