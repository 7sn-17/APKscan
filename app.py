# -*- coding: utf-8 -*-
"""
APK Scanner Web - Flask Server v1.5.1
- حد أقصى 450 MB لكل ملف
- طابور ذكي (Queue) — لا انهيار
- حذف التقارير بعد 5 دقائق
- تنظيف تلقائي كل 5 دقائق
- إحصائيات دائمة عبر JSONBin مع مزامنة كاملة
- زر إلغاء المهمة
- إصلاح: لا chdir — استخدام output_dir مباشرة
"""

import os
import sys
import io
import json
import uuid
import shutil
import tempfile
import threading
import traceback
import contextlib
import time
import queue
from datetime import datetime, timedelta
from flask import Flask, request, jsonify, send_file, render_template, make_response

# ============ إعداد المسارات ============
SCANNER_DIR = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, SCANNER_DIR)

from apk_scanner_v7 import analyze_apk
from jsonbin_helper import load_stats, save_stats_to_bin, DEFAULT_STATS

# ============ Flask App ============
app = Flask(__name__)
app.config['MAX_CONTENT_LENGTH'] = 450 * 1024 * 1024  # 450 MB
app.secret_key = os.environ.get("SECRET_KEY", "apkscan_web_secret_v1")

# ============ المجلدات المؤقتة ============
UPLOAD_DIR = tempfile.mkdtemp(prefix="apk_up_")
REPORTS_DIR = tempfile.mkdtemp(prefix="apk_rp_")

# ============ ثوابت ============
REPORT_LIFETIME_MINUTES = 5
CLEANUP_INTERVAL_SECONDS = 300
MAX_QUEUE_SIZE = 20
COOKIE_NAME = "apk_scanner_uid"
COOKIE_MAX_AGE = 365 * 24 * 3600
STATS_CACHE_SECONDS = 30

# ============ الذاكرة ============
JOBS = {}
JOB_QUEUE = queue.Queue()
IS_PROCESSING = threading.Event()
STATS_LOCK = threading.Lock()
LAST_STATS_LOAD = [0]


# ============ تحميل الإحصائيات الأولي ============
print("[INIT] Loading stats from JSONBin...")
try:
    loaded = load_stats()
    STATS = loaded
    if "user_ids" not in STATS:
        STATS["user_ids"] = []
    STATS["unique_users"] = len(STATS["user_ids"])
    print(f"[INIT] Stats loaded: {STATS['total_scans']} scans, {STATS['unique_users']} users")
except Exception as e:
    print(f"[INIT] Failed to load stats: {e}")
    STATS = DEFAULT_STATS.copy()
    STATS["user_ids"] = []


# ============ مساعدات الإحصائيات ============
def refresh_stats_from_bin(force=False):
    """🔄 تحميل الإحصائيات من JSONBin"""
    now = time.time()
    if not force and (now - LAST_STATS_LOAD[0]) < STATS_CACHE_SECONDS:
        return False
    
    try:
        fresh = load_stats()
        
        with STATS_LOCK:
            if fresh.get("total_scans", 0) >= STATS.get("total_scans", 0):
                old_user_ids = set(STATS.get("user_ids", []))
                new_user_ids = set(fresh.get("user_ids", []))
                merged_user_ids = list(old_user_ids | new_user_ids)
                
                STATS.update(fresh)
                STATS["user_ids"] = merged_user_ids
                STATS["unique_users"] = len(merged_user_ids)
            
            LAST_STATS_LOAD[0] = now
        
        print(f"[REFRESH] Stats: {STATS['total_scans']} scans, {STATS['unique_users']} users")
        return True
    except Exception as e:
        print(f"[REFRESH] Failed: {e}")
        return False


def save_stats(force=False):
    """💾 حفظ الإحصائيات إلى JSONBin"""
    with STATS_LOCK:
        snapshot = STATS.copy()
    
    try:
        result = save_stats_to_bin(snapshot)
        
        if result:
            print(f"[SAVE] ✓ {snapshot.get('total_scans', 0)} scans, {snapshot.get('total_size_mb', 0)} MB")
            return True
        else:
            print(f"[SAVE] ✗ First attempt failed, retrying...")
            time.sleep(1)
            result = save_stats_to_bin(snapshot)
            print(f"[SAVE] Retry: {'✓' if result else '✗'}")
            return result
    except Exception as e:
        print(f"[SAVE] Exception: {e}")
        return False


# ============ Cleanup ============
def cleanup_old_jobs():
    """حذف التقارير الأقدم من 5 دقائق"""
    now = datetime.now()
    to_delete = []
    for job_id, job in list(JOBS.items()):
        try:
            created = datetime.fromisoformat(job["created_at"])
            if now - created > timedelta(minutes=REPORT_LIFETIME_MINUTES):
                to_delete.append(job_id)
        except Exception:
            pass
    
    for job_id in to_delete:
        job = JOBS.pop(job_id, None)
        if job:
            try:
                if job.get("upload_path") and os.path.exists(job["upload_path"]):
                    os.remove(job["upload_path"])
            except Exception:
                pass
            try:
                if job.get("output_dir") and os.path.exists(job["output_dir"]):
                    shutil.rmtree(job["output_dir"], ignore_errors=True)
            except Exception:
                pass
    
    if to_delete:
        print(f"[CLEANUP] {len(to_delete)} job(s) removed")


def background_cleanup():
    """تنظيف تلقائي كل 5 دقائق"""
    while True:
        try:
            time.sleep(CLEANUP_INTERVAL_SECONDS)
            cleanup_old_jobs()
        except Exception as e:
            print(f"[CLEANUP] Error: {e}")


def background_stats_refresh():
    """🔄 تحديث الإحصائيات من JSONBin كل 60 ثانية"""
    while True:
        try:
            time.sleep(60)
            refresh_stats_from_bin(force=True)
        except Exception as e:
            print(f"[BG-REFRESH] Error: {e}")


# ============ Analysis ============
def run_analysis_quiet(apk_path, output_dir):
    """
    🆕 تشغيل analyze_apk مع:
    - تمرير output_dir مباشرة (بدون chdir)
    - redirect للـ stdout
    """
    buf = io.StringIO()
    
    try:
        print(f"[ANALYSIS] Starting: {apk_path}")
        print(f"[ANALYSIS] Output: {output_dir}")
        
        with contextlib.redirect_stdout(buf):
            report = analyze_apk(apk_path, output_dir)
        
        print(f"[ANALYSIS] Report generated: {bool(report)}")
        
        if report:
            # ابحث عن التقرير في output_dir
            try:
                html_files = [
                    f for f in os.listdir(output_dir)
                    if f.endswith('.html') and f.startswith('apk_report_')
                ]
                if html_files:
                    report["html_path"] = os.path.join(output_dir, html_files[0])
                    print(f"[ANALYSIS] HTML: {html_files[0]}")
                
                json_files = [
                    f for f in os.listdir(output_dir)
                    if f.endswith('.json') and f.startswith('apk_report_')
                ]
                if json_files:
                    report["json_path"] = os.path.join(output_dir, json_files[0])
                    print(f"[ANALYSIS] JSON: {json_files[0]}")
            except Exception as e:
                print(f"[ANALYSIS] Listdir error: {e}")
        
        return report
    except Exception as e:
        print(f"[ANALYSIS] ERROR: {e}")
        print(f"[ANALYSIS] Traceback:")
        traceback.print_exc()
        return None


def process_apk(job_id):
    """معالجة ملف واحد (يُستدعى من العامل)"""
    job = JOBS.get(job_id)
    if not job:
        print(f"[PROCESS] Job not found: {job_id[:8]}")
        return
    
    try:
        print(f"[PROCESS] Starting: {job_id[:8]}")
        job["status"] = "scanning"
        job["progress"] = 30
        job["stage"] = "تحليل الملف..."
        job["queue_position"] = 0
        
        output_dir = job["output_dir"]
        report = run_analysis_quiet(job["upload_path"], output_dir)
        
        if not report:
            job["status"] = "error"
            job["error"] = "فشل تحليل الملف"
            print(f"[PROCESS] Failed: {job_id[:8]}")
            return
        
        job["progress"] = 95
        job["stage"] = "إنشاء التقرير..."
        job["status"] = "done"
        job["report_path"] = report.get("html_path")
        job["report"] = {
            "score": report.get("score", 0),
            "verdict": report.get("verdict", {}),
            "file": report.get("file", ""),
            "size_mb": report.get("size_mb", 0),
        }
        
        # 🔄 1. حمّل الإحصائيات الحديثة
        print(f"[SCAN] Before update: {STATS.get('total_scans', 0)} scans")
        refresh_stats_from_bin(force=True)
        
        # ✅ 2. أضف الفحص الجديد
        with STATS_LOCK:
            STATS["total_scans"] = STATS.get("total_scans", 0) + 1
            STATS["total_files"] = STATS.get("total_files", 0) + 1
            STATS["total_size_mb"] = round(
                STATS.get("total_size_mb", 0) + report.get("size_mb", 0), 2
            )
            today = datetime.now().strftime("%Y-%m-%d")
            STATS.setdefault("by_day", {})
            STATS["by_day"][today] = STATS["by_day"].get(today, 0) + 1
            
            new_count = STATS["total_scans"]
            new_size = STATS["total_size_mb"]
        
        print(f"[SCAN] After update: {new_count} scans, {new_size} MB")
        
        # 💾 3. احفظ
        save_stats(force=True)
        
        # حذف ملف الرفع
        try:
            if os.path.exists(job["upload_path"]):
                os.remove(job["upload_path"])
                job["upload_path"] = None
        except Exception:
            pass
        
        print(f"[PROCESS] Done: {job_id[:8]}")
        
    except Exception as e:
        job["status"] = "error"
        job["error"] = str(e)
        print(f"[PROCESS] Exception: {e}")
        traceback.print_exc()


def process_queue_worker():
    """عامل يعالج المهام واحدة تلو الأخرى"""
    while True:
        try:
            job_id = JOB_QUEUE.get(timeout=1)
            
            job = JOBS.get(job_id)
            if not job:
                JOB_QUEUE.task_done()
                continue
            
            IS_PROCESSING.set()
            job["queue_position"] = 0
            
            process_apk(job_id)
            
            IS_PROCESSING.clear()
            JOB_QUEUE.task_done()
            
        except queue.Empty:
            continue
        except Exception as e:
            print(f"[QUEUE] Error: {e}")
            traceback.print_exc()
            IS_PROCESSING.clear()


# ============ بدء الخيوط ============
cleanup_thread = threading.Thread(target=background_cleanup, daemon=True)
cleanup_thread.start()

queue_worker = threading.Thread(target=process_queue_worker, daemon=True)
queue_worker.start()

stats_refresh_thread = threading.Thread(target=background_stats_refresh, daemon=True)
stats_refresh_thread.start()

print("[INIT] All background threads started ✓")


# ============ Routes ============
@app.route("/")
def index():
    refresh_stats_from_bin()
    
    user_id = request.cookies.get(COOKIE_NAME)
    is_new_user = False
    
    if not user_id:
        user_id = str(uuid.uuid4())
        is_new_user = True
    
    with STATS_LOCK:
        if user_id not in STATS.get("user_ids", []):
            STATS.setdefault("user_ids", []).append(user_id)
            STATS["unique_users"] = len(STATS["user_ids"])
            user_added = True
        else:
            user_added = False
    
    if user_added:
        print(f"[USER] New user added: {user_id[:8]}...")
        save_stats()
    
    resp = make_response(render_template("index.html", stats=STATS))
    
    if is_new_user:
        resp.set_cookie(
            COOKIE_NAME,
            user_id,
            max_age=COOKIE_MAX_AGE,
            samesite="Lax",
            httponly=False,
        )
    
    return resp


@app.route("/api/upload", methods=["POST"])
def upload():
    if "file" not in request.files:
        return jsonify({"error": "لم يتم رفع ملف"}), 400
    
    file = request.files["file"]
    if not file.filename:
        return jsonify({"error": "اسم الملف فارغ"}), 400
    
    fname = file.filename
    if not (fname.lower().endswith(".apk") or fname.lower().endswith(".xapk")):
        return jsonify({"error": "فقط ملفات APK و XAPK مدعومة"}), 400
    
    if JOB_QUEUE.qsize() >= MAX_QUEUE_SIZE:
        return jsonify({
            "error": f"الطابور ممتلئ حالياً ({MAX_QUEUE_SIZE} مستخدم). حاول بعد دقائق."
        }), 503
    
    job_id = str(uuid.uuid4())
    safe_name = fname.replace("/", "_").replace("\\", "_")
    upload_path = os.path.join(UPLOAD_DIR, f"{job_id}_{safe_name}")
    
    try:
        file.save(upload_path)
    except Exception as e:
        return jsonify({"error": f"فشل حفظ الملف: {str(e)}"}), 500
    
    output_dir = os.path.join(REPORTS_DIR, job_id)
    os.makedirs(output_dir, exist_ok=True)
    
    qsize = JOB_QUEUE.qsize()
    queue_position = qsize + 1
    if IS_PROCESSING.is_set():
        queue_position += 1
    
    JOBS[job_id] = {
        "id": job_id,
        "filename": fname,
        "status": "queued",
        "progress": 5,
        "stage": "في قائمة الانتظار...",
        "upload_path": upload_path,
        "output_dir": output_dir,
        "created_at": datetime.now().isoformat(),
        "queue_position": queue_position,
    }
    
    JOB_QUEUE.put(job_id)
    
    print(f"[UPLOAD] Job {job_id[:8]}... → position {queue_position}")
    
    return jsonify({
        "job_id": job_id,
        "status": "queued",
        "queue_position": queue_position,
        "queue_size": qsize,
    })


@app.route("/api/status/<job_id>")
def job_status(job_id):
    job = JOBS.get(job_id)
    if not job:
        return jsonify({"error": "المهمة غير موجودة أو انتهت صلاحيتها"}), 404
    
    if job.get("status") == "queued":
        try:
            current_queue = list(JOB_QUEUE.queue)
            if job_id in current_queue:
                idx = current_queue.index(job_id)
                pos = idx + 1
                if IS_PROCESSING.is_set():
                    pos += 1
                job["queue_position"] = pos
            else:
                job["queue_position"] = 1
        except Exception:
            pass
    
    return jsonify({
        "status": job["status"],
        "progress": job.get("progress", 0),
        "stage": job.get("stage", ""),
        "filename": job.get("filename", ""),
        "error": job.get("error"),
        "report": job.get("report"),
        "queue_position": job.get("queue_position", 0),
        "queue_size": JOB_QUEUE.qsize() + (1 if IS_PROCESSING.is_set() else 0),
    })


# ============ 🆕 CANCEL JOB ============
@app.route("/api/cancel/<job_id>", methods=["POST"])
def cancel_job(job_id):
    """إلغاء مهمة في الطابور أو قيد المعالجة"""
    job = JOBS.get(job_id)
    if not job:
        return jsonify({"error": "المهمة غير موجودة"}), 404
    
    if job["status"] == "scanning":
        return jsonify({
            "error": "لا يمكن الإلغاء — الفحص جاري الآن"
        }), 400
    
    if job["status"] == "queued":
        try:
            with JOB_QUEUE.mutex:
                queue_list = list(JOB_QUEUE.queue)
                if job_id in queue_list:
                    queue_list.remove(job_id)
                    JOB_QUEUE.queue.clear()
                    for item in queue_list:
                        JOB_QUEUE.put(item)
                    print(f"[CANCEL] Job {job_id[:8]}... removed from queue")
        except Exception as e:
            print(f"[CANCEL] Queue error: {e}")
    
    try:
        if job.get("upload_path") and os.path.exists(job["upload_path"]):
            os.remove(job["upload_path"])
    except Exception:
        pass
    
    try:
        if job.get("output_dir") and os.path.exists(job["output_dir"]):
            shutil.rmtree(job["output_dir"], ignore_errors=True)
    except Exception:
        pass
    
    JOBS.pop(job_id, None)
    
    print(f"[CANCEL] Job {job_id[:8]}... cancelled")
    
    return jsonify({
        "success": True,
        "message": "تم إلغاء الفحص"
    })


@app.route("/result/<job_id>")
def show_result(job_id):
    job = JOBS.get(job_id)
    if not job:
        return "انتهت صلاحية التقرير (يُحذف بعد 5 دقائق)", 404
    if job["status"] != "done":
        return "التقرير لم يكتمل بعد", 404
    report_path = job.get("report_path")
    if not report_path or not os.path.exists(report_path):
        return "ملف التقرير غير موجود", 404
    return send_file(report_path, mimetype="text/html")


@app.route("/api/stats")
def api_stats():
    refresh_stats_from_bin()
    
    return jsonify({
        "total_scans": STATS.get("total_scans", 0),
        "unique_users": STATS.get("unique_users", 0),
        "total_files": STATS.get("total_files", 0),
        "total_size_mb": STATS.get("total_size_mb", 0),
        "today": STATS.get("by_day", {}).get(datetime.now().strftime("%Y-%m-%d"), 0),
        "queue_size": JOB_QUEUE.qsize(),
    })


@app.errorhandler(413)
def too_large(e):
    return jsonify({"error": "حجم الملف أكبر من 450 ميجابايت"}), 413


@app.errorhandler(500)
def server_error(e):
    return jsonify({"error": "خطأ في السيرفر"}), 500


# ============ Legal Pages ============
@app.route("/privacy")
def privacy():
    return render_template("privacy.html")


@app.route("/terms")
def terms():
    return render_template("terms.html")


@app.route("/contact")
def contact():
    return render_template("contact.html")


if __name__ == "__main__":
    port = int(os.environ.get("PORT", 7860))
    app.run(host="0.0.0.0", port=port, debug=False, threaded=True)
