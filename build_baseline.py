"""
HawkEye - App Privilege Analyzer
Script: build_baseline.py
Description: CLI runner to build and update Category Permission Baselines
              using google-play-scraper. Designed to be run periodically or as a batch job.

Usage:
  python build_baseline.py --category Productivity --samples 8
  python build_baseline.py --all --samples 6
"""

import argparse
import sys
from datetime import datetime
from app import app
from db import db, CategoryBaseline
from scraper_utils import build_category_baseline_data, CATEGORY_NAME_MAP

def update_category_baseline(category: str, num_apps: int = 8):
    """
    Scrapes sample apps for the category, aggregates permission percentages,
    and updates the category_baseline table in PostgreSQL / SQLite.
    """
    print(f"\n[*] Scanning Google Play Store for category: '{category}' (sampling top {num_apps} apps)...")
    result = build_category_baseline_data(category, num_apps=num_apps)
    
    sample_size = result.get("sample_size", 0)
    freqs = result.get("frequencies", {})
    sampled_apps = result.get("sampled_apps", [])
    
    if sample_size == 0:
        print(f"[!] Warning: No sample apps could be scraped for category '{category}'.")
        return False
    
    print(f"[+] Sampled {sample_size} apps: {', '.join(sampled_apps)}")
    print(f"[+] Calculating permission frequencies across category...")
    
    now = datetime.utcnow()
    with app.app_context():
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
    
    print(f"[OK] Successfully saved {len(freqs)} baseline permissions for category '{category}'!\n")
    for p, pct in sorted(freqs.items(), key=lambda x: x[1], reverse=True):
        print(f"    - {p.ljust(30)} : {pct}% of apps")
    print()
    return True

def main():
    parser = argparse.ArgumentParser(description="HawkEye Category Baseline Builder")
    parser.add_argument("--category", type=str, default="Productivity", help="Target category (e.g. Tools, Social, Finance, Productivity, Photography, Health, Entertainment)")
    parser.add_argument("--samples", type=int, default=8, help="Number of popular apps to sample per category (default: 8)")
    parser.add_argument("--all", action="store_true", help="Build baselines for all standard categories sequentially")
    
    args = parser.parse_args()
    
    categories = ["Tools", "Social", "Finance", "Productivity", "Photography", "Health", "Entertainment"]
    
    if args.all:
        print(f"[=] Starting batch baseline compilation for all {len(categories)} categories...")
        for cat in categories:
            update_category_baseline(cat, num_apps=args.samples)
    else:
        norm_cat = CATEGORY_NAME_MAP.get(args.category.upper(), args.category)
        update_category_baseline(norm_cat, num_apps=args.samples)

if __name__ == "__main__":
    main()
