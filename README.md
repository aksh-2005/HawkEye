# HawkEye: App Privilege Analyzer

A lightweight cybersecurity web application designed to monitor, audit, and analyze Android application permissions and detect **privilege creep** across updates.

---

## Key Features

- **User & Admin Authentication**: Secure login, registration, password hashing with Werkzeug, and an Admin user panel (`/admin/users`).
- **Live Play Store Search & Autofill**: Search applications directly from Google Play Store with automatic metadata and permission scraping.
- **3-Way Permission Diff Engine**: Mathematical set-difference comparison (`current - previous`, `previous - current`, `current & previous`) highlighting Added, Removed, and Unchanged permissions.
- **Category Baseline Anomaly Detection**: Identifies whether permissions are **Common** or **Unusual** for specific app categories (Tools, Finance, Social, Health, Photography, etc.).
- **Snapshot History Timeline**: Detailed chronological audit logs for each monitored application.
- **Clean & Minimal Dashboard**: Fast, sleek, professional dark and light themes with app searching, risk sorting, and quick inspection.

---

## Quick Start

### 1. Install Dependencies
```bash
pip install -r requirements.txt
```

### 2. Run the Application
```bash
python app.py
```
Open your browser and navigate to:
**http://127.0.0.1:5000**

---

## Category Baseline Builder (Optional CLI)

To update category permission frequency baselines:
```bash
# Update a single category
python build_baseline.py --category Tools --samples 8

# Update all categories
python build_baseline.py --all --samples 6
```
