# -*- coding: utf-8 -*-
"""
APK Scanner Web - Flask Server v1.1
- حذف التقارير بعد 30 دقيقة
- إحصائيات: مستخدمين فريدين، فحوصات، ملفات، حجم
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
from datetime import datetime, timedelta
from flask import Flask, request, jsonify, send_file, render_template, make_response

# ============ إعداد المسارات ============
SCANNER_DIR = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, SCANNER_DIR)

from apk_scanner_v7 import analyze_apk

# ============ Flask App ============
app = Flask(__name__)
app.config['MAX_CONTENT_LENGTH'] = 2 * 1024 * 1024 * 1024  # 2 GB
app.secret_key = os.environ.get("SECRET_KEY", "apkscan_web_secret_v1")

# ============ المجلدات المؤقتة ============
UPLOAD_DIR = tempfile.mkdtemp(prefix="apk_up_")
REPORTS_DIR = tempfile.mkdtemp(prefix="apk_rp_")
STATS_FILE = os.path.join(SCANNER_DIR, "apkscan_stats.json")

# ============ ثوابت ============
REPORT_LIFETIME_MINUTES = 30  # ⏱️ حذف التقارير بعد 30 دقيقة
COOKIE_NAME = "apk_scanner_uid"
COOKIE_MAX_AGE = 365 * 24 * 3600  # سنة

# ============ الذاكرة ============
JOBS = {}
STATS = {
    "total_scans": 0,
    "unique_users": 0,
    "user_ids": [],
    "total_files": 0,
    "total_size_mb": 0,
    "by_day": {},
    "started_at": datetime.now().isoformat(),
}

# ============ تحميل الإحصائيات ============
if os.path.exists(STATS_FILE):
    try:
        with open(STATS_FILE, "r", encoding="utf-8") as f:
            loaded = json.load(f)
            STATS.update(loaded)
            # تأكد أن user_ids موجودة
            if "user_ids" not in STATS:
                STATS["user_ids"] = []
            STATS["unique_users"] = len(STATS["user_ids"])
    except Exception:
        pass


def save_stats():
    try:
        with open(STATS_FILE, "w", encoding="utf-8") as f:
            json.dump(STATS, f, ensure_ascii=False, indent=2)
    except Exception:
        pass


def cleanup_old_jobs():
    """حذف التقارير الأقدم من 30 دقيقة"""
    now = datetime.now()
    to_delete = []
    for job_id, job in JOBS.items():
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


def run_analysis_quiet(apk_path, output_dir):
    old_cwd = os.getcwd()
    os.chdir(output_dir)
    try:
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            report = analyze_apk(apk_path)
        
        if report:
            html_files = [
                f for f in os.listdir('.')
                if f.endswith('.html') and f.startswith('apk_report_')
            ]
            if html_files:
                report["html_path"] = os.path.join(output_dir, html_files[0])
            
            json_files = [
                f for f in os.listdir('.')
                if f.endswith('.json') and f.startswith('apk_report_')
            ]
            if json_files:
                report["json_path"] = os.path.join(output_dir, json_files[0])
        return report
    finally:
        os.chdir(old_cwd)


def process_apk(job_id):
    job = JOBS.get(job_id)
    if not job:
        return
    try:
        job["status"] = "scanning"
        job["progress"] = 30
        job["stage"] = "تحليل الملف..."
        
        output_dir = job["output_dir"]
        report = run_analysis_quiet(job["upload_path"], output_dir)
        
        if not report:
            job["status"] = "error"
            job["error"] = "فشل تحليل الملف"
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
        
        # تحديث الإحصائيات
        STATS["total_scans"] = STATS.get("total_scans", 0) + 1
        STATS["total_files"] = STATS.get("total_files", 0) + 1
        STATS["total_size_mb"] = round(
            STATS.get("total_size_mb", 0) + report.get("size_mb", 0), 2
        )
        today = datetime.now().strftime("%Y-%m-%d")
        STATS.setdefault("by_day", {})
        STATS["by_day"][today] = STATS["by_day"].get(today, 0) + 1
        save_stats()
        
        # حذف ملف الرفع
        try:
            if os.path.exists(job["upload_path"]):
                os.remove(job["upload_path"])
                job["upload_path"] = None
        except Exception:
            pass
        
    except Exception as e:
        job["status"] = "error"
        job["error"] = str(e)
        traceback.print_exc()


# ============ Routes ============

@app.route("/")
def index():
    cleanup_old_jobs()
    
    # تتبع المستخدم الفريد عبر Cookie
    user_id = request.cookies.get(COOKIE_NAME)
    is_new_user = False
    if not user_id:
        user_id = str(uuid.uuid4())
        is_new_user = True
    
    # تسجيل المستخدم إذا كان جديداً
    if user_id not in STATS.get("user_ids", []):
        STATS.setdefault("user_ids", []).append(user_id)
        STATS["unique_users"] = len(STATS["user_ids"])
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
    
    job_id = str(uuid.uuid4())
    safe_name = fname.replace("/", "_").replace("\\", "_")
    upload_path = os.path.join(UPLOAD_DIR, f"{job_id}_{safe_name}")
    
    try:
        file.save(upload_path)
    except Exception as e:
        return jsonify({"error": f"فشل حفظ الملف: {str(e)}"}), 500
    
    output_dir = os.path.join(REPORTS_DIR, job_id)
    os.makedirs(output_dir, exist_ok=True)
    
    JOBS[job_id] = {
        "id": job_id,
        "filename": fname,
        "status": "queued",
        "progress": 10,
        "stage": "في قائمة الانتظار...",
        "upload_path": upload_path,
        "output_dir": output_dir,
        "created_at": datetime.now().isoformat(),
    }
    
    t = threading.Thread(target=process_apk, args=(job_id,))
    t.daemon = True
    t.start()
    
    return jsonify({"job_id": job_id, "status": "queued"})


@app.route("/api/status/<job_id>")
def job_status(job_id):
    job = JOBS.get(job_id)
    if not job:
        return jsonify({"error": "المهمة غير موجودة أو انتهت صلاحيتها"}), 404
    
    return jsonify({
        "status": job["status"],
        "progress": job.get("progress", 0),
        "stage": job.get("stage", ""),
        "filename": job.get("filename", ""),
        "error": job.get("error"),
        "report": job.get("report"),
    })


@app.route("/result/<job_id>")
def show_result(job_id):
    job = JOBS.get(job_id)
    if not job:
        return "انتهت صلاحية التقرير (يُحذف بعد 30 دقيقة)", 404
    if job["status"] != "done":
        return "التقرير لم يكتمل بعد", 404
    report_path = job.get("report_path")
    if not report_path or not os.path.exists(report_path):
        return "ملف التقرير غير موجود", 404
    return send_file(report_path, mimetype="text/html")


@app.route("/api/stats")
def api_stats():
    return jsonify({
        "total_scans": STATS.get("total_scans", 0),
        "unique_users": STATS.get("unique_users", 0),
        "total_files": STATS.get("total_files", 0),
        "total_size_mb": STATS.get("total_size_mb", 0),
        "today": STATS.get("by_day", {}).get(datetime.now().strftime("%Y-%m-%d"), 0),
    })


@app.errorhandler(413)
def too_large(e):
    return jsonify({"error": "حجم الملف أكبر من 2 جيجابايت"}), 413


@app.errorhandler(500)
def server_error(e):
    return jsonify({"error": "خطأ في السيرفر"}), 500


if __name__ == "__main__":
    port = int(os.environ.get("PORT", 7860))
    app.run(host="0.0.0.0", port=port, debug=False, threaded=True)