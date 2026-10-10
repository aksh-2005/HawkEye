"""
HawkEye - App Privilege Analyzer
Module: scraper_utils.py
Description: Integration module for google-play-scraper providing:
 1. Live Google Play Store search and app autofill (Feature 1)
 2. Normalized permission scraping and risk level mapping (Feature 2)
 3. Category baseline aggregator and frequency percentage calculator (Feature 3)
 4. Permission snapshot comparison via Python set operations (Feature 4)
 5. Robust error handling, rate limiting safety, and in-memory TTL caching (Feature 5)
"""

import time
import json
import logging
from datetime import datetime, timedelta
from typing import Dict, List, Any, Optional, Tuple, Set

# Configure logger
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("hawkeye.scraper")

# Try importing google-play-scraper with graceful fallback
try:
    from google_play_scraper import search as gplay_search, app as gplay_app, permissions as gplay_permissions
    SCRAPER_AVAILABLE = True
except ImportError:
    SCRAPER_AVAILABLE = False
    logger.warning("google-play-scraper library is not installed. Please run `pip install google-play-scraper`.")

# -------------------------------------------------------------------------
# 5. ERROR HANDLING & RATE LIMIT SAFETY (Caching & Throttling)
# -------------------------------------------------------------------------
# In-Memory Cache with TTL (Time-To-Live: 1 hour = 3600 seconds) to avoid redundant requests
_SCRAPE_CACHE: Dict[str, Dict[str, Any]] = {}
CACHE_TTL_SECONDS = 3600  # 1 hour cache window

def _get_from_cache(cache_key: str) -> Optional[Any]:
    """
    Retrieves an item from the in-memory cache if present and not expired.
    """
    cached = _SCRAPE_CACHE.get(cache_key)
    if cached and (time.time() - cached.get("timestamp", 0)) < CACHE_TTL_SECONDS:
        return cached.get("data")
    return None

def _save_to_cache(cache_key: str, data: Any):
    """
    Saves an item to the in-memory cache with the current unix timestamp.
    """
    _SCRAPE_CACHE[cache_key] = {
        "timestamp": time.time(),
        "data": data
    }

def clear_cache():
    """Clears the in-memory scraper cache."""
    global _SCRAPE_CACHE
    _SCRAPE_CACHE.clear()

# -------------------------------------------------------------------------
# 2. PERMISSION RISK MAPPING & NORMALIZATION DEFINITIONS
# -------------------------------------------------------------------------
# Target risk categories:
#  - High: Camera, Mic, Location, Contacts, SMS
#  - Medium: Storage, Call Logs, Calendar, Settings, Accounts
#  - Low: Internet, Vibrate, Network State, Wake Lock, Boot
PERMISSION_RISK_MAP = {
    # High Risk (Camera, Mic, Location, Contacts, SMS, Overlay)
    "RECORD_AUDIO": ("HIGH", "Accesses microphone for ambient or audio recording"),
    "CAMERA": ("HIGH", "Accesses camera for photo/video capture"),
    "ACCESS_FINE_LOCATION": ("HIGH", "Precise GPS geographical location tracking"),
    "ACCESS_COARSE_LOCATION": ("HIGH", "Approximate network-based location tracking"),
    "ACCESS_BACKGROUND_LOCATION": ("HIGH", "Tracks location even when app is closed in background"),
    "READ_CONTACTS": ("HIGH", "Reads stored device contacts database"),
    "WRITE_CONTACTS": ("HIGH", "Modifies stored contacts list"),
    "READ_SMS": ("HIGH", "Reads incoming/received SMS text messages (OTP leak risk)"),
    "RECEIVE_SMS": ("HIGH", "Intercepts incoming SMS text messages"),
    "SEND_SMS": ("HIGH", "Sends SMS messages, potentially incurring carrier charges"),
    "SYSTEM_ALERT_WINDOW": ("HIGH", "Draws overlays over other apps (Phishing/tapjacking risk)"),
    
    # Medium Risk (Storage, Call Logs, Calendar, Settings, Accounts, Bluetooth)
    "READ_EXTERNAL_STORAGE": ("MEDIUM", "Reads photos, media, and files on device storage"),
    "WRITE_EXTERNAL_STORAGE": ("MEDIUM", "Modifies or deletes device storage contents"),
    "READ_CALL_LOG": ("MEDIUM", "Accesses telephony call log history"),
    "WRITE_CALL_LOG": ("MEDIUM", "Modifies telephony call log history"),
    "READ_CALENDAR": ("MEDIUM", "Accesses personal calendar entries and confidential event info"),
    "WRITE_CALENDAR": ("MEDIUM", "Modifies or adds calendar events and invites"),
    "WRITE_SETTINGS": ("MEDIUM", "Modifies system settings and configurations"),
    "PACKAGE_USAGE_STATS": ("MEDIUM", "Tracks how and when you use other applications"),
    "BLUETOOTH_ADMIN": ("MEDIUM", "Discovers and pairs Bluetooth devices"),
    "GET_ACCOUNTS": ("MEDIUM", "Accesses list of registered accounts on device"),
    
    # Low Risk (Internet, Vibrate, Network State, Wake Lock, Boot)
    "INTERNET": ("LOW", "Standard network connectivity"),
    "VIBRATE": ("LOW", "Controls haptic vibration motor"),
    "ACCESS_NETWORK_STATE": ("LOW", "Checks if device has internet connection"),
    "ACCESS_WIFI_STATE": ("LOW", "Monitors Wi-Fi connection parameters"),
    "WAKE_LOCK": ("LOW", "Prevents device from sleeping during background tasks"),
    "RECEIVE_BOOT_COMPLETED": ("LOW", "Starts background service upon device boot")
}

# Mapping from Play Store permission group names / keywords to standard Android permission names
PLAYSTORE_PERMISSION_KEYWORDS = [
    # High Risk: Camera, Mic, Location, Contacts, SMS
    (["record audio", "microphone", "audio recording"], "RECORD_AUDIO", "HIGH"),
    (["take pictures and videos", "camera", "photos and videos"], "CAMERA", "HIGH"),
    (["precise location", "gps", "fine location"], "ACCESS_FINE_LOCATION", "HIGH"),
    (["approximate location", "network-based location", "coarse location"], "ACCESS_COARSE_LOCATION", "HIGH"),
    (["location in the background", "all the time", "background location"], "ACCESS_BACKGROUND_LOCATION", "HIGH"),
    (["read your contacts", "read contacts", "contacts database"], "READ_CONTACTS", "HIGH"),
    (["modify your contacts", "write contacts"], "WRITE_CONTACTS", "HIGH"),
    (["read your text messages", "read sms", "sms or mms"], "READ_SMS", "HIGH"),
    (["receive text messages", "receive sms"], "RECEIVE_SMS", "HIGH"),
    (["send sms messages", "send sms"], "SEND_SMS", "HIGH"),
    (["draw over other apps", "display over other apps", "system alert window"], "SYSTEM_ALERT_WINDOW", "HIGH"),
    
    # Medium Risk: Storage, Call Logs, Calendar, Settings, Accounts
    (["read the contents of your usb storage", "read external storage", "read photos and media"], "READ_EXTERNAL_STORAGE", "MEDIUM"),
    (["modify or delete the contents of your usb storage", "write external storage"], "WRITE_EXTERNAL_STORAGE", "MEDIUM"),
    (["read call log", "call history", "phone calls"], "READ_CALL_LOG", "MEDIUM"),
    (["write call log", "modify call log"], "WRITE_CALL_LOG", "MEDIUM"),
    (["read calendar events", "read calendar"], "READ_CALENDAR", "MEDIUM"),
    (["add or modify calendar events", "modify calendar", "write calendar"], "WRITE_CALENDAR", "MEDIUM"),
    (["modify system settings", "write settings"], "WRITE_SETTINGS", "MEDIUM"),
    (["retrieve running apps", "usage stats", "usage access"], "PACKAGE_USAGE_STATS", "MEDIUM"),
    (["pair with bluetooth devices", "bluetooth settings", "bluetooth admin"], "BLUETOOTH_ADMIN", "MEDIUM"),
    (["find accounts on the device", "get accounts"], "GET_ACCOUNTS", "MEDIUM"),
    
    # Low Risk: Internet, Vibrate, Network State
    (["have full network access", "full network access", "internet"], "INTERNET", "LOW"),
    (["control vibration", "vibrate"], "VIBRATE", "LOW"),
    (["view network connections", "access network state"], "ACCESS_NETWORK_STATE", "LOW"),
    (["view wi-fi connections", "access wifi state", "view wifi"], "ACCESS_WIFI_STATE", "LOW"),
    (["prevent phone from sleeping", "wake lock"], "WAKE_LOCK", "LOW"),
    (["run at startup", "receive boot completed"], "RECEIVE_BOOT_COMPLETED", "LOW")
]

# Normalization for Category names
CATEGORY_NAME_MAP = {
    "TOOLS": "Tools",
    "PRODUCTIVITY": "Productivity",
    "SOCIAL": "Social",
    "COMMUNICATION": "Social",
    "FINANCE": "Finance",
    "PHOTOGRAPHY": "Photography",
    "HEALTH_AND_FITNESS": "Health",
    "FITNESS": "Health",
    "ENTERTAINMENT": "Entertainment",
    "MUSIC_AND_AUDIO": "Entertainment",
    "VIDEO_PLAYERS": "Entertainment"
}

# -------------------------------------------------------------------------
# 1. APP SEARCH & AUTOFILL FUNCTIONS
# -------------------------------------------------------------------------

def search_playstore_apps(query: str, n_hits: int = 5) -> List[Dict[str, Any]]:
    """
    Searches Google Play Store for apps matching the query string using `search(query, n_hits)`.
    Returns a list of matching apps with title, package ID (appId), icon, category, and developer.
    Cached for 1 hour to prevent rate-limiting and wrapped in try/except.
    """
    if not query or not query.strip():
        return []

    clean_query = query.strip().lower()
    cache_key = f"search:{clean_query}:{n_hits}"
    cached_result = _get_from_cache(cache_key)
    if cached_result is not None:
        return cached_result

    if not SCRAPER_AVAILABLE:
        logger.warning("google-play-scraper is unavailable. Returning empty search results.")
        return []

    try:
        # Request extra hits to account for any top result without appId
        raw_results = gplay_search(query.strip(), n_hits=max(n_hits + 5, 10), lang="en", country="us")
        formatted = []
        for r in raw_results:
            app_id = r.get("appId")
            if not app_id:
                continue  # Skip entries where package ID is missing

            cat_id = r.get("genreId") or r.get("genre") or "Tools"
            normalized_cat = CATEGORY_NAME_MAP.get(str(cat_id).upper(), "Tools")

            formatted.append({
                "title": r.get("title") or "Unknown App",
                "appId": app_id,
                "package_name": app_id,
                "icon": r.get("icon") or "",
                "developer": r.get("developer") or "Unknown Developer",
                "score": r.get("score") or 0.0,
                "category": normalized_cat,
                "summary": r.get("summary") or ""
            })

            if len(formatted) >= n_hits:
                break

        _save_to_cache(cache_key, formatted)
        return formatted
    except Exception as e:
        logger.error(f"Error during Google Play Store search for '{query}': {e}")
        return []

def fetch_app_details(package_id: str) -> Optional[Dict[str, Any]]:
    """
    Fetches full metadata and permission listing for a specific Android package ID using `app(package_id)`
    and `permissions(package_id)`.
    Returns: title, category, description, developer, current version, updated date, icon, and normalized permissions.
    """
    if not package_id or not package_id.strip():
        return None

    pkg = package_id.strip().lower()
    cache_key = f"app_details:{pkg}"
    cached_result = _get_from_cache(cache_key)
    if cached_result is not None:
        return cached_result

    if not SCRAPER_AVAILABLE:
        logger.warning("google-play-scraper is unavailable.")
        return None

    try:
        details = gplay_app(pkg, lang="en", country="us")
        if not details:
            return None

        cat_raw = details.get("genreId") or details.get("genre") or "Tools"
        category = CATEGORY_NAME_MAP.get(str(cat_raw).upper(), "Tools")

        # Fetch listed permissions via scraper
        scraped_perms_raw = {}
        try:
            scraped_perms_raw = gplay_permissions(pkg, lang="en", country="us")
        except Exception as perm_err:
            logger.warning(f"Could not fetch permission list for {pkg}: {perm_err}")

        normalized_perms = normalize_scraped_permissions(scraped_perms_raw)

        result = {
            "app_name": details.get("title") or pkg,
            "title": details.get("title") or pkg,
            "package_name": pkg,
            "category": category,
            "description": details.get("summary") or details.get("description") or "",
            "developer": details.get("developer") or "",
            "version": str(details.get("version") or "1.0.0"),
            "updated": str(details.get("updated") or details.get("lastUpdatedOn") or ""),
            "icon": details.get("icon") or "",
            "permissions": normalized_perms,
            "permission_names": [p["name"] for p in normalized_perms]
        }

        _save_to_cache(cache_key, result)
        return result
    except Exception as e:
        logger.error(f"Error fetching app details for package '{package_id}': {e}")
        return None

# -------------------------------------------------------------------------
# 2. PERMISSION FETCH & NORMALIZATION FOR SNAPSHOTS
# -------------------------------------------------------------------------

def normalize_scraped_permissions(scraped_dict: Any) -> List[Dict[str, Any]]:
    """
    Normalizes Google Play Scraper's permission descriptions into standard Android
    permission names (e.g. RECORD_AUDIO, CAMERA, ACCESS_FINE_LOCATION, READ_CONTACTS, READ_SMS)
    and assigns risk levels (HIGH, MEDIUM, LOW).
    """
    if not scraped_dict:
        return []

    identified_perms: Dict[str, Dict[str, Any]] = {}

    # Extract all text descriptions from the scraper structure
    all_texts = []
    if isinstance(scraped_dict, dict):
        for group_name, perms_list in scraped_dict.items():
            all_texts.append(str(group_name).lower())
            if isinstance(perms_list, list):
                for p in perms_list:
                    if isinstance(p, dict):
                        all_texts.append(str(p.get("description") or p.get("name") or "").lower())
                    else:
                        all_texts.append(str(p).lower())
    elif isinstance(scraped_dict, list):
        for item in scraped_dict:
            if isinstance(item, dict):
                all_texts.append(str(item.get("description") or item.get("name") or "").lower())
            else:
                all_texts.append(str(item).lower())

    # Match text descriptions against Android permission keyword patterns
    for keywords, perm_name, risk_level in PLAYSTORE_PERMISSION_KEYWORDS:
        for kw in keywords:
            matched = any(kw in txt for txt in all_texts)
            if matched and perm_name not in identified_perms:
                desc = PERMISSION_RISK_MAP.get(perm_name, ("", "Standard Android permission"))[1]
                identified_perms[perm_name] = {
                    "name": perm_name,
                    "risk": risk_level,
                    "desc": desc
                }
                break

    # If no network permissions matched, but internet is indicated, include standard INTERNET baseline
    if "INTERNET" not in identified_perms and any("internet" in txt or "network" in txt for txt in all_texts):
        identified_perms["INTERNET"] = {
            "name": "INTERNET",
            "risk": "LOW",
            "desc": PERMISSION_RISK_MAP["INTERNET"][1]
        }

    return list(identified_perms.values())

def fetch_app_permissions_for_snapshot(package_id: str) -> List[Dict[str, Any]]:
    """
    Uses `permissions(package_id)` from google-play-scraper to fetch and normalize
    an app's currently listed permissions.
    """
    if not package_id or not package_id.strip():
        return []

    pkg = package_id.strip().lower()
    if not SCRAPER_AVAILABLE:
        return []

    try:
        perms_raw = gplay_permissions(pkg, lang="en", country="us")
        return normalize_scraped_permissions(perms_raw)
    except Exception as e:
        logger.error(f"Failed to fetch permissions for package '{pkg}': {e}")
        return []

def save_permission_snapshot_db(app_id: int, permissions_list: List[Dict[str, Any]], snapshot_title: Optional[str] = None, notes: Optional[str] = None) -> bool:
    """
    Saves a normalized list of permissions as a new timestamped row in `app_snapshots`
    linked to the app's `apps.id`.
    """
    try:
        from db import db, AppSnapshot
        
        high_count = sum(1 for p in permissions_list if p.get("risk") == "HIGH")
        med_count = sum(1 for p in permissions_list if p.get("risk") == "MEDIUM")
        risk_summary = "HIGH" if high_count > 0 else ("MEDIUM" if med_count > 0 else "LOW")
        
        snap = AppSnapshot(
            app_id=app_id,
            snapshot_title=snapshot_title or f"Play Store Permission Audit ({datetime.utcnow().strftime('%b %d, %Y')})",
            timestamp=datetime.utcnow(),
            added_perms=json.dumps(permissions_list),
            removed_perms=json.dumps([]),
            unchanged_perms=json.dumps([]),
            risk_summary=risk_summary,
            notes=notes or f"Saved snapshot with {len(permissions_list)} permissions."
        )
        db.session.add(snap)
        db.session.commit()
        return True
    except Exception as e:
        logger.error(f"Error saving permission snapshot for app_id {app_id}: {e}")
        return False

# -------------------------------------------------------------------------
# 3. CATEGORY BASELINE BUILDER
# -------------------------------------------------------------------------

def build_category_baseline_data(category_name: str, num_apps: int = 8) -> Dict[str, Any]:
    """
    Batch function that, given a category (e.g., 'Productivity'), uses `search()` to find
    top apps in that category, then calls `app()` and `permissions()` for each to collect
    their permission sets. Aggregates this into a baseline calculating what percentage of
    apps in that category typically request each permission.
    Designed to run as a periodic/one-time script to avoid rate limiting.
    """
    if not SCRAPER_AVAILABLE:
        return {"category": category_name, "sample_size": 0, "frequencies": {}}

    search_query = category_name.strip()
    apps_found = search_playstore_apps(search_query, n_hits=num_apps)

    if not apps_found or len(apps_found) < 3:
        # Fallback to category query search
        fallback_apps = search_playstore_apps("popular " + search_query, n_hits=num_apps)
        existing_pkg_ids = {a["appId"] for a in apps_found}
        for fa in fallback_apps:
            if fa["appId"] not in existing_pkg_ids:
                apps_found.append(fa)

    total_scanned = 0
    perm_counter: Dict[str, int] = {}
    sampled_app_names = []

    for app_meta in apps_found[:num_apps]:
        pkg = app_meta.get("appId")
        if not pkg:
            continue

        try:
            # Respect rate limits with brief throttle delay
            time.sleep(0.35)
            perms = fetch_app_permissions_for_snapshot(pkg)
            if perms:
                total_scanned += 1
                sampled_app_names.append(app_meta.get("title", pkg))
                for p in perms:
                    pname = p["name"]
                    perm_counter[pname] = perm_counter.get(pname, 0) + 1
        except Exception as err:
            logger.warning(f"Error scraping permissions for sample app {pkg}: {err}")
            continue

    # Calculate frequency percentages
    frequencies: Dict[str, float] = {}
    if total_scanned > 0:
        for perm_name, count in perm_counter.items():
            freq_pct = round((count / total_scanned) * 100.0, 1)
            frequencies[perm_name] = freq_pct

    return {
        "category": category_name,
        "sample_size": total_scanned,
        "sampled_apps": sampled_app_names,
        "frequencies": frequencies,
        "generated_at": datetime.utcnow().isoformat()
    }

# -------------------------------------------------------------------------
# 4. RE-CHECK & PERMISSION DIFF COMPARISON (Set Operations)
# -------------------------------------------------------------------------

def compare_permissions(previous_perm_names: List[str], current_perm_names: List[str]) -> Dict[str, Any]:
    """
    Compares two lists of permission names using Python set operations:
      - added = curr_set - prev_set
      - removed = prev_set - curr_set
      - unchanged = curr_set & prev_set

    Returns:
      - has_changed: True if permissions were added or removed
      - added: List of newly introduced permissions with risk & desc
      - removed: List of removed/revoked permissions
      - unchanged: List of maintained baseline permissions
      - highest_new_risk: Highest risk among newly added permissions (HIGH/MEDIUM/LOW)
      - summary: Descriptive string summary
    """
    prev_set: Set[str] = set(p.strip().upper() for p in previous_perm_names if p)
    curr_set: Set[str] = set(p.strip().upper() for p in current_perm_names if p)

    added_set = curr_set - prev_set
    removed_set = prev_set - curr_set
    unchanged_set = curr_set & prev_set

    # Format into detailed items
    added_list = []
    for p in sorted(added_set):
        risk = PERMISSION_RISK_MAP.get(p, ("LOW", ""))[0]
        desc = PERMISSION_RISK_MAP.get(p, ("", "Custom permission flag"))[1]
        added_list.append({"name": p, "risk": risk, "desc": desc})

    removed_list = []
    for p in sorted(removed_set):
        risk = PERMISSION_RISK_MAP.get(p, ("LOW", ""))[0]
        desc = PERMISSION_RISK_MAP.get(p, ("", "Revoked permission"))[1]
        removed_list.append({"name": p, "risk": risk, "desc": desc})

    unchanged_list = []
    for p in sorted(unchanged_set):
        risk = PERMISSION_RISK_MAP.get(p, ("LOW", ""))[0]
        desc = PERMISSION_RISK_MAP.get(p, ("", "Baseline permission"))[1]
        unchanged_list.append({"name": p, "risk": risk, "desc": desc})

    has_changed = bool(added_set or removed_set)

    # Determine highest risk escalation among newly added permissions
    highest_new_risk = "LOW"
    if any(item["risk"] == "HIGH" for item in added_list):
        highest_new_risk = "HIGH"
    elif any(item["risk"] == "MEDIUM" for item in added_list):
        highest_new_risk = "MEDIUM"

    return {
        "has_changed": has_changed,
        "added": added_list,
        "removed": removed_list,
        "unchanged": unchanged_list,
        "highest_new_risk": highest_new_risk,
        "summary": f"+{len(added_list)} added, -{len(removed_list)} removed, {len(unchanged_list)} unchanged"
    }
