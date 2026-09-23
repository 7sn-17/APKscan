# -*- coding: utf-8 -*-
"""
JSONBin Helper - حفظ وتحميل الإحصائيات من JSONBin.io
"""
import os
import requests
from datetime import datetime


# ============ الإعدادات ============
JSONBIN_KEY = os.environ.get("JSONBIN_KEY", "")
JSONBIN_BIN_ID = os.environ.get("JSONBIN_BIN_ID", "")
JSONBIN_URL = f"https://api.jsonbin.io/v3/b/{JSONBIN_BIN_ID}"
JSONBIN_HEADERS = {
    "X-Master-Key": JSONBIN_KEY,
    "Content-Type": "application/json",
}


# ============ الإحصائيات الافتراضية ============
DEFAULT_STATS = {
    "total_scans": 0,
    "unique_users": 0,
    "user_ids": [],
    "total_files": 0,
    "total_size_mb": 0,
    "by_day": {},
    "started_at": datetime.now().isoformat(),
}


# ============ التحميل ============
def load_stats():
    """تحميل الإحصائيات من JSONBin"""
    if not JSONBIN_KEY or not JSONBIN_BIN_ID:
        print("[JSONBIN] Missing key or bin ID — using defaults")
        return DEFAULT_STATS.copy()
    
    try:
        r = requests.get(
            f"{JSONBIN_URL}/latest",
            headers=JSONBIN_HEADERS,
            timeout=10,
        )
        
        if r.status_code == 200:
            data = r.json()
            record = data.get("record", {})
            
            # تأكد من وجود كل الحقول
            for key, default_value in DEFAULT_STATS.items():
                if key not in record:
                    record[key] = default_value
            
            print(f"[JSONBIN] Loaded: {record.get('total_scans', 0)} scans")
            return record
        else:
            print(f"[JSONBIN] Load failed: HTTP {r.status_code}")
            return DEFAULT_STATS.copy()
    
    except Exception as e:
        print(f"[JSONBIN] Load error: {e}")
        return DEFAULT_STATS.copy()


# ============ الحفظ ============
def save_stats_to_bin(stats):
    """حفظ الإحصائيات إلى JSONBin"""
    if not JSONBIN_KEY or not JSONBIN_BIN_ID:
        print("[JSONBIN] Missing config — skip save")
        return False
    
    try:
        r = requests.put(
            JSONBIN_URL,
            headers=JSONBIN_HEADERS,
            json=stats,
            timeout=10,
        )
        
        if r.status_code == 200:
            print(f"[JSONBIN] Saved: {stats.get('total_scans', 0)} scans")
            return True
        else:
            print(f"[JSONBIN] Save failed: HTTP {r.status_code}")
            return False
    
    except Exception as e:
        print(f"[JSONBIN] Save error: {e}")
        return False