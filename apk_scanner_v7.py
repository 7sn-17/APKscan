# -*- coding: utf-8 -*-
"""
APK Scanner v7.0 - Advanced Edition
- 200+ known apps database
- 60+ known native libraries
- Deep content analysis (URLs, Shell, Libs)
- Full XAPK support (all APKs + OBB)
- Neutral evaluation (mod-agnostic)
- Balanced scoring system
- Professional Arabic HTML report
"""

import os
import sys
import json
import hashlib
import subprocess
import zipfile
import re
import shutil
import tempfile
from datetime import datetime
from collections import Counter, defaultdict


# ============ Colors ============
class C:
    R = "\033[91m"
    G = "\033[92m"
    Y = "\033[93m"
    B = "\033[94m"
    M = "\033[95m"
    C = "\033[96m"
    W = "\033[97m"
    BOLD = "\033[1m"
    END = "\033[0m"


def title(text, color=C.G):
    print("\n" + "=" * 70)
    print(f"  {color}{C.BOLD}{text}{C.END}")
    print("=" * 70)


# ============ Permission Database ============
PERMISSIONS_DB = {
    "android.permission.READ_SMS": {"level": "CRITICAL", "icon": "fa-envelope-open-text", "name_ar": "قراءة الرسائل النصية", "why_ar": "التطبيق يقدر يقرأ كل رسائلك", "abuse_ar": "سرقة رموز التحقق OTP", "explain": "تسمح للتطبيق بالاطلاع على جميع الرسائل النصية SMS."},
    "android.permission.RECEIVE_SMS": {"level": "CRITICAL", "icon": "fa-inbox", "name_ar": "استقبال الرسائل", "why_ar": "يعترض رسائلك الواردة", "abuse_ar": "اعتراض رمز OTP", "explain": "تسمح بالتقاط الرسائل لحظة وصولها."},
    "android.permission.SEND_SMS": {"level": "CRITICAL", "icon": "fa-paper-plane", "name_ar": "إرسال رسائل نصية", "why_ar": "يرسل رسائل من رقمك", "abuse_ar": "اشتراك بخدمات مدفوعة", "explain": "تسمح بإرسال رسائل SMS من رقمك."},
    "android.permission.READ_CALL_LOG": {"level": "CRITICAL", "icon": "fa-phone", "name_ar": "قراءة سجل المكالمات", "why_ar": "يطّلع على مكالماتك", "abuse_ar": "انتهاك خصوصية", "explain": "تسمح بالوصول لسجل المكالمات الكامل."},
    "android.permission.PROCESS_OUTGOING_CALLS": {"level": "CRITICAL", "icon": "fa-phone-volume", "name_ar": "اعتراض المكالمات", "why_ar": "يتدخل في مكالماتك", "abuse_ar": "تحويل المكالمات", "explain": "تسمح بمراقبة أو تعديل المكالمات الصادرة."},
    "android.permission.CALL_PHONE": {"level": "CRITICAL", "icon": "fa-phone-flip", "name_ar": "إجراء مكالمات", "why_ar": "يتصل بدون إذنك", "abuse_ar": "اتصال بأرقام مدفوعة", "explain": "تسمح بإجراء مكالمات مباشرة."},
    "android.permission.RECORD_AUDIO": {"level": "CRITICAL", "icon": "fa-microphone", "name_ar": "تسجيل الصوت", "why_ar": "يسجل صوتك", "abuse_ar": "تسجيل محادثاتك", "explain": "تسمح باستخدام الميكروفون."},
    "android.permission.CAMERA": {"level": "CRITICAL", "icon": "fa-camera", "name_ar": "الكاميرا", "why_ar": "يستخدم الكاميرا", "abuse_ar": "التقاط صور بدون علمك", "explain": "تسمح بالوصول للكاميرا."},
    "android.permission.ACCESS_BACKGROUND_LOCATION": {"level": "CRITICAL", "icon": "fa-location-dot", "name_ar": "الموقع في الخلفية", "why_ar": "يتابع موقعك دائماً", "abuse_ar": "تتبع يومي", "explain": "تسمح بتتبع موقعك حتى لو التطبيق مغلق."},
    "android.permission.SYSTEM_ALERT_WINDOW": {"level": "CRITICAL", "icon": "fa-window-restore", "name_ar": "العرض فوق التطبيقات", "why_ar": "يعرض نوافذ فوق تطبيقاتك", "abuse_ar": "Clickjacking", "explain": "تسمح بعرض نوافذ فوق التطبيقات."},
    "android.permission.REQUEST_INSTALL_PACKAGES": {"level": "CRITICAL", "icon": "fa-download", "name_ar": "تثبيت تطبيقات", "why_ar": "ينزّل ويثبت تطبيقات", "abuse_ar": "تثبيت فيروسات", "explain": "تسمح بتثبيت تطبيقات APK أخرى."},
    "android.permission.BIND_ACCESSIBILITY_SERVICE": {"level": "CRITICAL", "icon": "fa-universal-access", "name_ar": "خدمة الوصول", "why_ar": "يقرأ كل شاشاتك", "abuse_ar": "Keylogger", "explain": "أخطر صلاحية — تقرأ كل ما على الشاشة."},
    "android.permission.BIND_DEVICE_ADMIN": {"level": "CRITICAL", "icon": "fa-user-shield", "name_ar": "مسؤول الجهاز", "why_ar": "تحكم كامل بالجهاز", "abuse_ar": "قفل ومسح بيانات", "explain": "تسمح بالتحكم الكامل بالجهاز."},
    "android.permission.READ_CONTACTS": {"level": "HIGH", "icon": "fa-address-book", "name_ar": "قراءة جهات الاتصال", "why_ar": "يطّلع على جهاتك", "abuse_ar": "تسريب الأرقام", "explain": "تسمح بالوصول لجهات الاتصال."},
    "android.permission.WRITE_CONTACTS": {"level": "HIGH", "icon": "fa-address-book", "name_ar": "تعديل جهات الاتصال", "why_ar": "يضيف/يحذف جهات", "abuse_ar": "إضافة إعلانات", "explain": "تسمح بتعديل جهات الاتصال."},
    "android.permission.ACCESS_FINE_LOCATION": {"level": "HIGH", "icon": "fa-crosshairs", "name_ar": "الموقع الدقيق", "why_ar": "موقعك بدقة عالية", "abuse_ar": "معرفة مكانك", "explain": "تسمح بالوصول لموقعك الدقيق عبر GPS."},
    "android.permission.ACCESS_COARSE_LOCATION": {"level": "HIGH", "icon": "fa-location-crosshairs", "name_ar": "الموقع التقريبي", "why_ar": "منطقتك العامة", "abuse_ar": "إعلانات مستهدفة", "explain": "تسمح بمعرفة موقعك التقريبي."},
    "android.permission.READ_EXTERNAL_STORAGE": {"level": "HIGH", "icon": "fa-folder-open", "name_ar": "قراءة الملفات", "why_ar": "يطّلع على ملفاتك", "abuse_ar": "تسريب الصور", "explain": "تسمح بقراءة الملفات والصور."},
    "android.permission.WRITE_EXTERNAL_STORAGE": {"level": "HIGH", "icon": "fa-file-pen", "name_ar": "كتابة الملفات", "why_ar": "يعدل ملفاتك", "abuse_ar": "حذف ملفاتك", "explain": "تسمح بتعديل وحذف الملفات."},
    "android.permission.READ_PHONE_STATE": {"level": "HIGH", "icon": "fa-mobile-screen", "name_ar": "معلومات الجهاز", "why_ar": "IMEI ورقمك", "abuse_ar": "تتبع الجهاز", "explain": "تسمح بالوصول لمعلومات الجهاز."},
    "android.permission.GET_ACCOUNTS": {"level": "HIGH", "icon": "fa-at", "name_ar": "الحسابات", "why_ar": "حساباتك على الجهاز", "abuse_ar": "معرفة إيميلاتك", "explain": "تسمح بالوصول لجميع الحسابات."},
    "android.permission.READ_CALENDAR": {"level": "HIGH", "icon": "fa-calendar-days", "name_ar": "قراءة التقويم", "why_ar": "مواعيدك", "abuse_ar": "معرفة اجتماعاتك", "explain": "تسمح بالوصول لمواعيدك."},
    "android.permission.WRITE_CALENDAR": {"level": "HIGH", "icon": "fa-calendar-plus", "name_ar": "تعديل التقويم", "why_ar": "يضيف مواعيد", "abuse_ar": "إضافة إعلانات", "explain": "تسمح بإضافة مواعيد للتقويم."},
    "android.permission.PACKAGE_USAGE_STATS": {"level": "HIGH", "icon": "fa-chart-simple", "name_ar": "إحصائيات الاستخدام", "why_ar": "يعرف تطبيقاتك", "abuse_ar": "بناء ملف عنك", "explain": "تسمح بمراقبة استخدامك للتطبيقات."},
    "android.permission.READ_PHONE_NUMBERS": {"level": "HIGH", "icon": "fa-phone-office", "name_ar": "قراءة رقم الهاتف", "why_ar": "رقم هاتفك", "abuse_ar": "تسجيل رقمك", "explain": "تسمح بالوصول لرقم هاتفك."},
    "android.permission.QUERY_ALL_PACKAGES": {"level": "HIGH", "icon": "fa-cubes", "name_ar": "كل التطبيقات", "why_ar": "تطبيقاتك المثبتة", "abuse_ar": "تحليل سلوكك", "explain": "تسمح بمعرفة كل التطبيقات المثبتة."},
    "android.permission.MANAGE_EXTERNAL_STORAGE": {"level": "HIGH", "icon": "fa-hard-drive", "name_ar": "إدارة كل الملفات", "why_ar": "تحكم كامل بالملفات", "abuse_ar": "حذف/تعديل ملفات النظام", "explain": "تسمح بإدارة كل ملفات التخزين."},
    "android.permission.WRITE_SECURE_SETTINGS": {"level": "HIGH", "icon": "fa-shield-halved", "name_ar": "كتابة إعدادات النظام", "why_ar": "يعدل إعدادات النظام", "abuse_ar": "تعطيل حماية", "explain": "تسمح بتعديل إعدادات النظام الحساسة."},
    "android.permission.READ_LOGS": {"level": "HIGH", "icon": "fa-file-lines", "name_ar": "قراءة سجلات النظام", "why_ar": "يطّلع على سجلات النظام", "abuse_ar": "سرقة معلومات", "explain": "تسمح بقراءة سجلات النظام."},
    "android.permission.DUMP": {"level": "HIGH", "icon": "fa-bug", "name_ar": "Dump النظام", "why_ar": "يستخرج بيانات النظام", "abuse_ar": "سرقة بيانات حساسة", "explain": "تسمح بالوصول لبيانات النظام التشخيصية."},
    "android.permission.INTERNET": {"level": "MEDIUM", "icon": "fa-wifi", "name_ar": "الإنترنت", "why_ar": "يتصل بالإنترنت", "abuse_ar": "طبيعي", "explain": "تسمح بالاتصال بالإنترنت."},
    "android.permission.ACCESS_NETWORK_STATE": {"level": "MEDIUM", "icon": "fa-signal", "name_ar": "حالة الشبكة", "why_ar": "يعرف حالة الشبكة", "abuse_ar": "طبيعي", "explain": "تسمح بمعرفة حالة الشبكة."},
    "android.permission.WAKE_LOCK": {"level": "MEDIUM", "icon": "fa-moon", "name_ar": "منع النوم", "why_ar": "يمنع نوم الجهاز", "abuse_ar": "استهلاك بطارية", "explain": "تسمح بإبقاء الجهاز نشطاً."},
    "android.permission.VIBRATE": {"level": "LOW", "icon": "fa-mobile", "name_ar": "الاهتزاز", "why_ar": "يهز الجهاز", "abuse_ar": "طبيعي", "explain": "تسمح بالتحكم في الاهتزاز."},
    "android.permission.FOREGROUND_SERVICE": {"level": "MEDIUM", "icon": "fa-layer-group", "name_ar": "خدمة أمامية", "why_ar": "يشتغل في الخلفية", "abuse_ar": "استهلاك موارد", "explain": "تسمح بتشغيل خدمة في الخلفية."},
    "android.permission.RECEIVE_BOOT_COMPLETED": {"level": "MEDIUM", "icon": "fa-power-off", "name_ar": "التشغيل عند الإقلاع", "why_ar": "يشتغل تلقائياً", "abuse_ar": "تشغيل خبيث", "explain": "تسمح بالتشغيل التلقائي عند الإقلاع."},
    "android.permission.REQUEST_IGNORE_BATTERY_OPTIMIZATIONS": {"level": "MEDIUM", "icon": "fa-battery-full", "name_ar": "تجاهل توفير البطارية", "why_ar": "يعمل بدون قيود", "abuse_ar": "استهلاك بطارية", "explain": "تسمح بتجاهل تحسينات البطارية."},
    "android.permission.FOREGROUND_SERVICE_SPECIAL_USE": {"level": "MEDIUM", "icon": "fa-layer-group", "name_ar": "خدمة أمامية خاصة", "why_ar": "خدمة في الخلفية", "abuse_ar": "استهلاك موارد", "explain": "خدمة أمامية للاستخدام الخاص."},
}

# ============ Suspicious Code Patterns ============
SUSPICIOUS_PATTERNS = {
    "Accessibility Abuse": {"category": "danger", "patterns": [r"AccessibilityService"], "name_ar": "استخدام خدمة الوصول", "short_ar": "أخطر صلاحية", "explain": "خدمة الوصول — قد تقرأ كل ما على الشاشة."},
    "Notification Listener": {"category": "danger", "patterns": [r"NotificationListenerService"], "name_ar": "قراءة الإشعارات", "short_ar": "خطر شديد", "explain": "يقرأ كل إشعاراتك."},
    "Dynamic Code Loading": {"category": "warn", "patterns": [r"DexClassLoader", r"PathClassLoader", r"loadClass"], "name_ar": "تحميل كود ديناميكي", "short_ar": "يُحمّل كوداً خارجياً", "explain": "يُحمّل كوداً من الإنترنت وقت التشغيل."},
    "Shell Commands": {"category": "danger", "patterns": [r"Runtime\.getRuntime", r"exec\("], "name_ar": "تنفيذ أوامر نظام", "short_ar": "خطير", "explain": "ينفذ أوامر نظام."},
    "Root Detection": {"category": "info", "patterns": [r"isRooted", r"/system/bin/su", r"Superuser\.apk", r"magisk"], "name_ar": "فحص Root", "short_ar": "سلوك شائع", "explain": "يفحص حالة Root."},
    "Emulator Check": {"category": "info", "patterns": [r"goldfish", r"genymotion", r"isEmulator", r"ro\.kernel\.qemu"], "name_ar": "فحص المحاكي", "short_ar": "سلوك شائع", "explain": "يفحص إذا يعمل على محاكي."},
    "Debug Detection": {"category": "info", "patterns": [r"isDebuggerConnected", r"android\.os\.Debug"], "name_ar": "فحص مصحح الأخطاء", "short_ar": "سلوك شائع", "explain": "يكتشف الـ Debugger."},
    "Reflection Usage": {"category": "info", "patterns": [r"java\.lang\.reflect", r"Class\.forName"], "name_ar": "استخدام الانعكاس", "short_ar": "تقنية شائعة", "explain": "استخدام Reflection."},
    "Native Code": {"category": "info", "patterns": [r"System\.loadLibrary", r"\.so$"], "name_ar": "مكتبات أصلية", "short_ar": "سلوك طبيعي", "explain": "مكتبات Native (C/C++)."},
    "Crypto Usage": {"category": "info", "patterns": [r"javax\.crypto", r"Cipher\.getInstance"], "name_ar": "استخدام التشفير", "short_ar": "جيد للأمان", "explain": "يستخدم التشفير."},
    "Base64 Obfuscation": {"category": "warn", "patterns": [r"Base64\.decode", r"Base64\.encode"], "name_ar": "تشفير Base64", "short_ar": "قد يُخفي نصوص", "explain": "يستخدم Base64."},
    "Clipboard Access": {"category": "warn", "patterns": [r"ClipboardManager", r"getPrimaryClip"], "name_ar": "قراءة الحافظة", "short_ar": "قد يقرأ كلمات السر", "explain": "يقرأ الحافظة."},
    "Screenshot Detection": {"category": "info", "patterns": [r"FLAG_SECURE", r"onWindowFocusChanged"], "name_ar": "منع لقطات الشاشة", "short_ar": "جيد للخصوصية", "explain": "يمنع اللقطات."},
    "Installed Apps Enum": {"category": "warn", "patterns": [r"getInstalledPackages", r"getInstalledApplications"], "name_ar": "تعداد التطبيقات", "short_ar": "قد يبني ملف عنك", "explain": "يعدد التطبيقات المثبتة."},
    "Location Tracking": {"category": "warn", "patterns": [r"LocationManager", r"requestLocationUpdates"], "name_ar": "تتبع الموقع", "short_ar": "تأكد من السبب", "explain": "يتتبع موقعك."},
    "Contact Reading": {"category": "warn", "patterns": [r"ContactsContract", r"getContacts"], "name_ar": "قراءة جهات الاتصال", "short_ar": "تحقق من السبب", "explain": "يقرأ جهات الاتصال."},
    "SMS Reading": {"category": "danger", "patterns": [r"SmsManager", r"Telephony\.Sms"], "name_ar": "قراءة/إرسال SMS", "short_ar": "خطير", "explain": "يتعامل مع SMS."},
    "Audio Recording": {"category": "warn", "patterns": [r"MediaRecorder", r"AudioRecord"], "name_ar": "تسجيل الصوت", "short_ar": "تحقق من السبب", "explain": "يسجل الصوت."},
    "Camera Usage": {"category": "warn", "patterns": [r"Camera\.open", r"Camera2"], "name_ar": "استخدام الكاميرا", "short_ar": "تحقق من السبب", "explain": "يستخدم الكاميرا."},
    "File Access": {"category": "info", "patterns": [r"FileInputStream", r"FileOutputStream"], "name_ar": "الوصول للملفات", "short_ar": "سلوك طبيعي", "explain": "يقرأ/يكتب ملفات."},
    "Network Socket": {"category": "info", "patterns": [r"Socket\(", r"ServerSocket"], "name_ar": "اتصالات Socket", "short_ar": "سلوك طبيعي", "explain": "يفتح اتصالات Socket."},
    "HTTP Requests": {"category": "info", "patterns": [r"HttpURLConnection", r"OkHttp"], "name_ar": "طلبات HTTP", "short_ar": "تأكد من HTTPS", "explain": "يجري طلبات HTTP."},
    "WebView Usage": {"category": "warn", "patterns": [r"WebView", r"loadUrl"], "name_ar": "استخدام WebView", "short_ar": "تأكد من HTTPS", "explain": "ينشئ متصفحاً داخلياً."},
}

# ============ Known Trackers ============
KNOWN_TRACKERS = {
    "Facebook Analytics": ["com/facebook/analytics", "com/facebook/appevents"],
    "Google Analytics": ["com/google/android/gms/analytics"],
    "Firebase Analytics": ["com/google/firebase/analytics"],
    "Firebase Crashlytics": ["com/google/firebase/crashlytics"],
    "Adjust": ["com/adjust/sdk"],
    "AppsFlyer": ["com/appsflyer"],
    "Unity Ads": ["com/unity3d/ads"],
    "AppLovin": ["com/applovin"],
    "AdMob": ["com/google/android/gms/ads"],
    "Flurry": ["com/flurry"],
    "Mixpanel": ["com/mixpanel"],
    "Amplitude": ["com/amplitude"],
    "Sentry": ["io/sentry"],
    "Braze": ["com/braze"],
    "OneSignal": ["com/onesignal"],
    "Segment": ["com/segment/analytics"],
    "Branch": ["io/branch"],
    "Kochava": ["com/kochava"],
    "Vungle": ["com/vungle"],
    "Chartboost": ["com/chartboost"],
    "IronSource": ["com/ironsource"],
    "MoPub": ["com/mopub"],
    "InMobi": ["com/inmobi"],
    "Pangle": ["com/bytedance/sdk"],
    "TikTok SDK": ["com/tiktok"],
    "Fyber": ["com/fyber"],
}

TRACKER_EXPLAINS = {
    "Facebook Analytics": "تحليلات فيسبوك.",
    "Google Analytics": "تحليلات Google.",
    "Firebase Analytics": "تحليلات Firebase.",
    "Firebase Crashlytics": "تتبع الأعطال.",
    "Adjust": "تسويق وقياس إعلانات.",
    "AppsFlyer": "قياس حملات.",
    "Unity Ads": "إعلانات Unity.",
    "AppLovin": "إعلانات ألعاب.",
    "AdMob": "إعلانات Google.",
    "Flurry": "تحليلات Yahoo.",
    "Mixpanel": "تحليلات متقدمة.",
    "Amplitude": "تحليلات تجربة المستخدم.",
    "Sentry": "تتبع الأخطاء.",
    "Braze": "تسويق تفاعلي.",
    "OneSignal": "إشعارات Push.",
    "Segment": "توجيه البيانات.",
    "Branch": "ربط الروابط.",
    "Kochava": "قياس إعلانات.",
    "Vungle": "إعلانات فيديو.",
    "Chartboost": "إعلانات ألعاب.",
    "IronSource": "منصة إعلانات.",
    "MoPub": "شبكة إعلانات.",
    "InMobi": "إعلانات جوال.",
    "Pangle": "إعلانات TikTok.",
    "TikTok SDK": "SDK تيك توك.",
    "Fyber": "شبكة إعلانات.",
}

# ============ Known Native Libraries (60+) ============
KNOWN_LIBRARIES = {
    # Frameworks
    "libflutter.so": "Flutter Engine",
    "libhermes.so": "Hermes JavaScript Engine (React Native)",
    "libhermes-executor-debug.so": "Hermes Debug",
    "libhermes-executor-release.so": "Hermes Release",
    "libjsc.so": "JavaScriptCore",
    "libunity.so": "Unity Engine",
    "libil2cpp.so": "Unity IL2CPP",
    "libmonobdwgc-2.0.so": "Unity Mono",
    "libmonobdwgc-2.0-bdwgc.so": "Unity Mono BDWGC",
    "libmain.so": "Main Library",
    "libreactnativejni.so": "React Native JNI",
    "libfbjni.so": "Facebook JNI",
    "libappmodules.so": "App Modules",
    "libreact_codegen_rncore.so": "RN Core Codegen",
    "libreact_debug.so": "React Native Debug",
    "libreact_nativemodule_core.so": "RN Native Module Core",
    "libreact_newarchdefaults.so": "RN New Arch",
    "libreact_render_animations.so": "RN Animations",
    "libreact_render_componentregistry.so": "RN Component Registry",
    "libreact_render_consistency.so": "RN Consistency",
    "libreact_render_core.so": "RN Render Core",
    "libreact_render_debug.so": "RN Render Debug",
    "libreact_render_graphics.so": "RN Render Graphics",
    "libreact_render_leakchecker.so": "RN Leak Checker",
    "libreact_render_mapbuffer.so": "RN Map Buffer",
    "libreact_render_mounting.so": "RN Mounting",
    "libreact_render_runtimescheduler.so": "RN Runtime Scheduler",
    "libreact_render_scheduler.so": "RN Scheduler",
    "libreact_render_uimanager.so": "RN UI Manager",
    "libreact_utils.so": "RN Utils",
    "librrc_image.so": "RN Image",
    "librrc_root.so": "RN Root",
    "librrc_text.so": "RN Text",
    "librrc_textinput.so": "RN Text Input",
    "librrc_view.so": "RN View",
    "libruntimeexecutor.so": "Runtime Executor",
    "libturbomodulejsijni.so": "Turbo Module JSI",
    "libyoga.so": "Yoga Layout (React Native)",
    
    # Databases
    "libsqlite.so": "SQLite",
    "libsqlcipher.so": "SQLCipher (Encrypted SQLite)",
    "librealm-jni.so": "Realm Database",
    "liblmdb.so": "LMDB Database",
    
    # Crypto
    "libcryptopp_shared.so": "Crypto++",
    "librncrypto.so": "React Native Crypto",
    "libconceal.so": "Conceal Crypto",
    "libsodium.so": "Sodium Crypto",
    "libssl.so": "OpenSSL",
    "libcrypto.so": "OpenSSL Crypto",
    "libboringssl.so": "BoringSSL",
    
    # Media
    "libduktape.so": "Duktape JS Engine",
    "libavcodec.so": "FFmpeg Codec",
    "libavformat.so": "FFmpeg Format",
    "libavutil.so": "FFmpeg Utils",
    "libswscale.so": "FFmpeg Scale",
    "libswresample.so": "FFmpeg Resample",
    "libwebrtc.so": "WebRTC",
    "libjingle_peerconnection_so.so": "WebRTC PeerConnection",
    "libopencv_java4.so": "OpenCV 4",
    "libopencv_java3.so": "OpenCV 3",
    
    # System / Standard
    "libc++_shared.so": "libc++ Shared",
    "libgnustl_shared.so": "GNU STL Shared",
    "libstdc++.so": "stdc++",
    "libc.so": "C Library",
    "libm.so": "Math Library",
    "libdl.so": "Dynamic Linker",
    "liblog.so": "Android Log",
    "libz.so": "zlib Compression",
    "liblog.so": "Log Library",
    "libandroid.so": "Android Native",
    "libjnigraphics.so": "Android Graphics",
    "libEGL.so": "EGL Graphics",
    "libGLESv2.so": "OpenGL ES 2",
    "libGLESv3.so": "OpenGL ES 3",
    "libvulkan.so": "Vulkan",
    "libOpenSLES.so": "OpenSL ES Audio",
    "libOpenMAXAL.so": "OpenMAX AL",
    
    # Crash / Analytics
    "libbugsnag-ndk.so": "Bugsnag NDK",
    "libcrashlytics.so": "Crashlytics",
    "libcrashlytics-common.so": "Crashlytics Common",
    "libcrashlytics-handler.so": "Crashlytics Handler",
    "libcrashlytics-trampoline.so": "Crashlytics Trampoline",
    "libfabric.so": "Fabric (Crashlytics)",
    
    # Expo
    "libexpo-modules-core.so": "Expo Modules Core",
    "libexpo-application.so": "Expo Application",
    "libexpo-constants.so": "Expo Constants",
    "libexpo-file-system.so": "Expo File System",
    "libexpo-font.so": "Expo Font",
    "libexpo-keep-awake.so": "Expo Keep Awake",
    "libexpo-linking.so": "Expo Linking",
    "libexpo-notifications.so": "Expo Notifications",
    "libexpo-web-browser.so": "Expo Web Browser",
    
    # Termux
    "libtermux.so": "Termux Core",
    "libtermux-bootstrap.so": "Termux Bootstrap",
    
    # Game engines
    "libcocos2d.so": "Cocos2d-x",
    "libcocos2djs.so": "Cocos2d-x JS",
    "libgodot.so": "Godot Engine",
    "libue4.so": "Unreal Engine 4",
    "libUE4.so": "Unreal Engine 4",
    "libmain.so": "Main Library",
}

LIB_EXPLAINS = {
    "libcryptopp_shared.so": "مكتبة تشفير Crypto++ — تُستخدم لتشفير البيانات.",
    "libduktape.so": "محرك JavaScript خفيف — لتشغيل أكواد JS داخل التطبيق.",
    "libgnustl_shared.so": "مكتبة C++ القياسية من GNU.",
    "libnative-lib.so": "كود أصلي خاص بالمطوّر (C/C++).",
    "librncrypto.so": "مكتبة تشفير لـ React Native.",
    "libtermux-bootstrap.so": "مكتبة Termux Bootstrap — لأدوات المطوّرين.",
    "libtermux.so": "مكتبة Termux الرئيسية.",
    "libflutter.so": "محرك Flutter من Google — لتطبيقات Flutter.",
    "libhermes.so": "محرك JavaScript Hermes من Meta — لتطبيقات React Native.",
    "libjsc.so": "محرك JavaScriptCore من Apple/WebKit.",
    "libunity.so": "محرك Unity للألعاب والتطبيقات ثلاثية الأبعاد.",
    "libil2cpp.so": "مترجم Unity IL2CPP — يحوّل C# إلى C++.",
    "libmonobdwgc-2.0.so": "مكتبة Unity Mono للألعاب.",
    "libreactnativejni.so": "جسر React Native JNI.",
    "libsqlite.so": "مكتبة قاعدة بيانات SQLite.",
    "libsqlcipher.so": "قاعدة بيانات SQLite مشفرة.",
    "libopencv_java4.so": "مكتبة OpenCV 4 للرؤية الحاسوبية.",
    "librealm-jni.so": "قاعدة بيانات Realm.",
    "libbugsnag-ndk.so": "مكتبة Bugsnag (تتبع الأخطاء).",
    "libavcodec.so": "مكتبة FFmpeg لفك وترميز الفيديو.",
    "libwebrtc.so": "مكتبة WebRTC للمكالمات الصوتية/المرئية.",
    "libssl.so": "مكتبة OpenSSL للتشفير.",
    "libcrypto.so": "مكتبة OpenSSL Crypto.",
    "libconceal.so": "مكتبة Conceal للتشفير من Facebook.",
    "libsodium.so": "مكتبة Sodium للتشفير الحديث.",
    "libcocos2d.so": "محرك Cocos2d-x للألعاب.",
    "libgodot.so": "محرك Godot للألعاب مفتوح المصدر.",
    "libue4.so": "محرك Unreal Engine 4.",
    "libUE4.so": "محرك Unreal Engine 4.",
    "libvulkan.so": "مكتبة Vulkan للرسومات.",
    "libGLESv2.so": "مكتبة OpenGL ES 2 للرسومات.",
    "libGLESv3.so": "مكتبة OpenGL ES 3 للرسومات.",
}

# ============ Known Packages Database ============
KNOWN_PACKAGES = {
    # Developer Tools
    "com.termux": {"name": "Termux", "category": "developer_tool", "trust": 100, "signer": "Termux Team"},
    "com.termux.api": {"name": "Termux:API", "category": "developer_tool", "trust": 100, "signer": "Termux Team"},
    "com.termux.boot": {"name": "Termux:Boot", "category": "developer_tool", "trust": 100, "signer": "Termux Team"},
    "com.termux.widget": {"name": "Termux:Widget", "category": "developer_tool", "trust": 100, "signer": "Termux Team"},
    "com.termux.styling": {"name": "Termux:Styling", "category": "developer_tool", "trust": 100, "signer": "Termux Team"},
    "com.termux.tasker": {"name": "Termux:Tasker", "category": "developer_tool", "trust": 100, "signer": "Termux Team"},
    "com.termux.gui": {"name": "Termux:GUI", "category": "developer_tool", "trust": 100, "signer": "Termux Team"},
    "com.aurora.store": {"name": "Aurora Store", "category": "app_store", "trust": 95, "signer": "Aurora OSS"},
    "org.fdroid.fdroid": {"name": "F-Droid", "category": "app_store", "trust": 100, "signer": "F-Droid Team"},
    "com.github.android": {"name": "GitHub", "category": "developer_tool", "trust": 100, "signer": "GitHub Inc"},
    "com.gitlab.android": {"name": "GitLab", "category": "developer_tool", "trust": 100, "signer": "GitLab Inc"},
    "org.mozilla.fenix": {"name": "Firefox Nightly", "category": "browser", "trust": 100, "signer": "Mozilla"},
    
    # App Stores
    "com.android.vending": {"name": "Google Play", "category": "system", "trust": 100, "signer": "Google"},
    "com.google.android.gms": {"name": "Google Play Services", "category": "system", "trust": 100, "signer": "Google"},
    "com.amazon.venezia": {"name": "Amazon Appstore", "category": "app_store", "trust": 95, "signer": "Amazon"},
    "com.huawei.appmarket": {"name": "Huawei AppGallery", "category": "app_store", "trust": 95, "signer": "Huawei"},
    "com.sec.android.app.samsungapps": {"name": "Galaxy Store", "category": "app_store", "trust": 100, "signer": "Samsung"},
    
    # Browsers
    "com.android.chrome": {"name": "Chrome", "category": "browser", "trust": 100, "signer": "Google"},
    "com.chrome.beta": {"name": "Chrome Beta", "category": "browser", "trust": 100, "signer": "Google"},
    "com.chrome.dev": {"name": "Chrome Dev", "category": "browser", "trust": 100, "signer": "Google"},
    "com.chrome.canary": {"name": "Chrome Canary", "category": "browser", "trust": 100, "signer": "Google"},
    "org.mozilla.firefox": {"name": "Firefox", "category": "browser", "trust": 100, "signer": "Mozilla"},
    "org.mozilla.firefox_beta": {"name": "Firefox Beta", "category": "browser", "trust": 100, "signer": "Mozilla"},
    "org.mozilla.focus": {"name": "Firefox Focus", "category": "browser", "trust": 100, "signer": "Mozilla"},
    "com.brave.browser": {"name": "Brave", "category": "browser", "trust": 100, "signer": "Brave Software"},
    "com.opera.browser": {"name": "Opera", "category": "browser", "trust": 95, "signer": "Opera"},
    "com.opera.mini.native": {"name": "Opera Mini", "category": "browser", "trust": 95, "signer": "Opera"},
    "com.microsoft.emmx": {"name": "Edge", "category": "browser", "trust": 100, "signer": "Microsoft"},
    "com.duckduckgo.mobile.android": {"name": "DuckDuckGo", "category": "browser", "trust": 100, "signer": "DuckDuckGo"},
    "com.vivaldi.browser": {"name": "Vivaldi", "category": "browser", "trust": 100, "signer": "Vivaldi"},
    "com.kiwibrowser.browser": {"name": "Kiwi Browser", "category": "browser", "trust": 95, "signer": "Kiwi"},
    
    # Social
    "com.whatsapp": {"name": "WhatsApp", "category": "messaging", "trust": 100, "signer": "Meta"},
    "com.whatsapp.w4b": {"name": "WhatsApp Business", "category": "messaging", "trust": 100, "signer": "Meta"},
    "org.telegram.messenger": {"name": "Telegram", "category": "messaging", "trust": 100, "signer": "Telegram"},
    "org.telegram.messenger.web": {"name": "Telegram Web", "category": "messaging", "trust": 95, "signer": "Telegram"},
    "org.thunderdog.challegram": {"name": "Telegram X", "category": "messaging", "trust": 95, "signer": "Telegram"},
    "com.instagram.android": {"name": "Instagram", "category": "social", "trust": 100, "signer": "Meta"},
    "com.facebook.katana": {"name": "Facebook", "category": "social", "trust": 100, "signer": "Meta"},
    "com.facebook.orca": {"name": "Messenger", "category": "messaging", "trust": 100, "signer": "Meta"},
    "com.facebook.lite": {"name": "Facebook Lite", "category": "social", "trust": 100, "signer": "Meta"},
    "com.twitter.android": {"name": "Twitter/X", "category": "social", "trust": 100, "signer": "X Corp"},
    "com.snapchat.android": {"name": "Snapchat", "category": "social", "trust": 100, "signer": "Snap Inc"},
    "com.tiktok": {"name": "TikTok", "category": "social", "trust": 95, "signer": "ByteDance"},
    "com.zhiliaoapp.musically": {"name": "TikTok", "category": "social", "trust": 95, "signer": "ByteDance"},
    "com.discord": {"name": "Discord", "category": "messaging", "trust": 100, "signer": "Discord Inc"},
    "org.thoughtcrime.securesms": {"name": "Signal", "category": "messaging", "trust": 100, "signer": "Signal Foundation"},
    "com.viber.voip": {"name": "Viber", "category": "messaging", "trust": 95, "signer": "Rakuten"},
    "com.skype.raider": {"name": "Skype", "category": "messaging", "trust": 100, "signer": "Microsoft"},
    "com.imo.android.imoim": {"name": "IMO", "category": "messaging", "trust": 90, "signer": "IMO"},
    "com.tencent.mm": {"name": "WeChat", "category": "messaging", "trust": 95, "signer": "Tencent"},
    "jp.naver.line.android": {"name": "LINE", "category": "messaging", "trust": 95, "signer": "LINE Corp"},
    "com.kakao.talk": {"name": "KakaoTalk", "category": "messaging", "trust": 95, "signer": "Kakao"},
    "com.reddit.frontpage": {"name": "Reddit", "category": "social", "trust": 95, "signer": "Reddit Inc"},
    "com.linkedin.android": {"name": "LinkedIn", "category": "professional", "trust": 100, "signer": "LinkedIn"},
    "com.pinterest": {"name": "Pinterest", "category": "social", "trust": 100, "signer": "Pinterest"},
    "com.tumblr": {"name": "Tumblr", "category": "social", "trust": 95, "signer": "Automattic"},
    "com.medium.reader": {"name": "Medium", "category": "reader", "trust": 100, "signer": "Medium"},
    "com.quora.android": {"name": "Quora", "category": "social", "trust": 95, "signer": "Quora"},
    
    # Media
    "com.google.android.youtube": {"name": "YouTube", "category": "media", "trust": 100, "signer": "Google"},
    "com.google.android.apps.youtube.music": {"name": "YouTube Music", "category": "media", "trust": 100, "signer": "Google"},
    "com.google.android.apps.youtube.kids": {"name": "YouTube Kids", "category": "media", "trust": 100, "signer": "Google"},
    "org.videolan.vlc": {"name": "VLC", "category": "media_player", "trust": 100, "signer": "VideoLAN"},
    "com.spotify.music": {"name": "Spotify", "category": "music", "trust": 100, "signer": "Spotify"},
    "com.netflix.mediaclient": {"name": "Netflix", "category": "streaming", "trust": 100, "signer": "Netflix"},
    "com.amazon.avod.thirdpartyclient": {"name": "Prime Video", "category": "streaming", "trust": 100, "signer": "Amazon"},
    "com.disney.disneyplus": {"name": "Disney+", "category": "streaming", "trust": 100, "signer": "Disney"},
    "com.shahid.net": {"name": "Shahid", "category": "streaming", "trust": 95, "signer": "MBC"},
    "com.anghami": {"name": "Anghami", "category": "music", "trust": 95, "signer": "Anghami"},
    "com.soundcloud.android": {"name": "SoundCloud", "category": "music", "trust": 100, "signer": "SoundCloud"},
    "com.deezer.android.app": {"name": "Deezer", "category": "music", "trust": 95, "signer": "Deezer"},
    "com.twitch.android.app": {"name": "Twitch", "category": "streaming", "trust": 100, "signer": "Twitch"},
    
    # Google
    "com.google.android.apps.maps": {"name": "Google Maps", "category": "navigation", "trust": 100, "signer": "Google"},
    "com.google.android.apps.photos": {"name": "Google Photos", "category": "photos", "trust": 100, "signer": "Google"},
    "com.google.android.gm": {"name": "Gmail", "category": "email", "trust": 100, "signer": "Google"},
    "com.google.android.apps.docs": {"name": "Google Drive", "category": "cloud", "trust": 100, "signer": "Google"},
    "com.google.android.calendar": {"name": "Google Calendar", "category": "productivity", "trust": 100, "signer": "Google"},
    "com.google.android.keep": {"name": "Google Keep", "category": "productivity", "trust": 100, "signer": "Google"},
    "com.google.android.apps.tachyon": {"name": "Google Meet", "category": "messaging", "trust": 100, "signer": "Google"},
    "com.google.android.apps.nbu.files": {"name": "Files by Google", "category": "files", "trust": 100, "signer": "Google"},
    "com.google.android.googlequicksearchbox": {"name": "Google", "category": "search", "trust": 100, "signer": "Google"},
    "com.google.android.apps.translate": {"name": "Google Translate", "category": "productivity", "trust": 100, "signer": "Google"},
    "com.google.android.contacts": {"name": "Google Contacts", "category": "system", "trust": 100, "signer": "Google"},
    "com.google.android.dialer": {"name": "Google Phone", "category": "system", "trust": 100, "signer": "Google"},
    "com.google.android.apps.messaging": {"name": "Google Messages", "category": "messaging", "trust": 100, "signer": "Google"},
    "com.google.android.deskclock": {"name": "Google Clock", "category": "system", "trust": 100, "signer": "Google"},
    "com.google.android.apps.walletnfcrel": {"name": "Google Wallet", "category": "finance", "trust": 100, "signer": "Google"},
    "com.google.android.apps.tasks": {"name": "Google Tasks", "category": "productivity", "trust": 100, "signer": "Google"},
    "com.google.android.apps.podcasts": {"name": "Google Podcasts", "category": "media", "trust": 100, "signer": "Google"},
    "com.google.android.apps.books": {"name": "Google Play Books", "category": "reader", "trust": 100, "signer": "Google"},
    "com.google.android.videos": {"name": "Google TV", "category": "streaming", "trust": 100, "signer": "Google"},
    
    # Microsoft
    "com.microsoft.office.word": {"name": "Word", "category": "productivity", "trust": 100, "signer": "Microsoft"},
    "com.microsoft.office.excel": {"name": "Excel", "category": "productivity", "trust": 100, "signer": "Microsoft"},
    "com.microsoft.office.powerpoint": {"name": "PowerPoint", "category": "productivity", "trust": 100, "signer": "Microsoft"},
    "com.microsoft.office.outlook": {"name": "Outlook", "category": "email", "trust": 100, "signer": "Microsoft"},
    "com.microsoft.office.onenote": {"name": "OneNote", "category": "productivity", "trust": 100, "signer": "Microsoft"},
    "com.microsoft.teams": {"name": "Teams", "category": "messaging", "trust": 100, "signer": "Microsoft"},
    "com.microsoft.skydrive": {"name": "OneDrive", "category": "cloud", "trust": 100, "signer": "Microsoft"},
    
    # Games
    "com.tencent.ig": {"name": "PUBG Mobile", "category": "game", "trust": 95, "signer": "Tencent"},
    "com.pubg.imobile": {"name": "BGMI", "category": "game", "trust": 95, "signer": "Krafton"},
    "com.rekoo.pubgm": {"name": "PUBG Mobile KR", "category": "game", "trust": 95, "signer": "Krafton"},
    "com.dts.freefireth": {"name": "Free Fire", "category": "game", "trust": 90, "signer": "Garena"},
    "com.dts.freefiremax": {"name": "Free Fire MAX", "category": "game", "trust": 90, "signer": "Garena"},
    "com.activision.callofduty.shooter": {"name": "CODM", "category": "game", "trust": 95, "signer": "Activision"},
    "com.tencent.tmgp.cod": {"name": "CODM CN", "category": "game", "trust": 95, "signer": "Tencent"},
    "com.mojang.minecraftpe": {"name": "Minecraft", "category": "game", "trust": 100, "signer": "Mojang"},
    "com.roblox.client": {"name": "Roblox", "category": "game", "trust": 95, "signer": "Roblox"},
    "com.supercell.clashofclans": {"name": "Clash of Clans", "category": "game", "trust": 100, "signer": "Supercell"},
    "com.supercell.clashroyale": {"name": "Clash Royale", "category": "game", "trust": 100, "signer": "Supercell"},
    "com.supercell.brawlstars": {"name": "Brawl Stars", "category": "game", "trust": 100, "signer": "Supercell"},
    "com.supercell.hayday": {"name": "Hay Day", "category": "game", "trust": 100, "signer": "Supercell"},
    "com.miHoYo.GenshinImpact": {"name": "Genshin Impact", "category": "game", "trust": 95, "signer": "HoYoverse"},
    "com.miHoYo.hkrpg": {"name": "Honkai Star Rail", "category": "game", "trust": 95, "signer": "HoYoverse"},
    "com.HoYoverse.hkrpgoversea": {"name": "HSR Global", "category": "game", "trust": 95, "signer": "HoYoverse"},
    "com.epicgames.fortnite": {"name": "Fortnite", "category": "game", "trust": 95, "signer": "Epic"},
    "com.epicgames.portal": {"name": "Epic Games", "category": "game", "trust": 95, "signer": "Epic"},
    "com.ea.game.pvz2_row": {"name": "PvZ 2", "category": "game", "trust": 95, "signer": "EA"},
    "com.ea.gp.fifamobile": {"name": "FIFA Mobile", "category": "game", "trust": 95, "signer": "EA"},
    "com.gameloft.android.ANMP.GloftA9HM": {"name": "Asphalt 9", "category": "game", "trust": 95, "signer": "Gameloft"},
    "com.rockstargames.gtasa": {"name": "GTA: SA", "category": "game", "trust": 95, "signer": "Rockstar"},
    "com.rockstargames.gtavc": {"name": "GTA: VC", "category": "game", "trust": 95, "signer": "Rockstar"},
    "com.king.candycrushsaga": {"name": "Candy Crush", "category": "game", "trust": 100, "signer": "King"},
    "com.king.candycrushsodasaga": {"name": "Candy Crush Soda", "category": "game", "trust": 100, "signer": "King"},
    
    # VPN / Security
    "com.wireguard.android": {"name": "WireGuard", "category": "vpn", "trust": 100, "signer": "WireGuard"},
    "org.torproject.android": {"name": "Tor Browser", "category": "vpn", "trust": 100, "signer": "Tor Project"},
    "org.torproject.torbrowser": {"name": "Tor Browser", "category": "vpn", "trust": 100, "signer": "Tor Project"},
    "com.expressvpn.vpn": {"name": "ExpressVPN", "category": "vpn", "trust": 95, "signer": "ExpressVPN"},
    "com.nordvpn.android": {"name": "NordVPN", "category": "vpn", "trust": 95, "signer": "NordVPN"},
    "com.privateinternetaccess.android": {"name": "PIA VPN", "category": "vpn", "trust": 95, "signer": "PIA"},
    "ch.protonvpn.android": {"name": "ProtonVPN", "category": "vpn", "trust": 100, "signer": "Proton"},
    "ch.protonmail.android": {"name": "ProtonMail", "category": "email", "trust": 100, "signer": "Proton"},
    "com.surfshark.vpnclient.android": {"name": "Surfshark", "category": "vpn", "trust": 95, "signer": "Surfshark"},
    "com.tunnelbear.android": {"name": "TunnelBear", "category": "vpn", "trust": 95, "signer": "TunnelBear"},
    
    # Education
    "com.duolingo": {"name": "Duolingo", "category": "education", "trust": 100, "signer": "Duolingo"},
    "org.khanacademy.android": {"name": "Khan Academy", "category": "education", "trust": 100, "signer": "Khan Academy"},
    "com.coursera.android": {"name": "Coursera", "category": "education", "trust": 100, "signer": "Coursera"},
    "com.udemy.android": {"name": "Udemy", "category": "education", "trust": 100, "signer": "Udemy"},
    "com.edx.android": {"name": "edX", "category": "education", "trust": 100, "signer": "edX"},
    "com.memrise.android.memrisecompanion": {"name": "Memrise", "category": "education", "trust": 100, "signer": "Memrise"},
    "com.busuu.android.enc": {"name": "Busuu", "category": "education", "trust": 100, "signer": "Busuu"},
    
    # Tools
    "com.simplemobiletools.gallery.pro": {"name": "Simple Gallery", "category": "gallery", "trust": 100, "signer": "Simple Mobile Tools"},
    "com.simplemobiletools.filemanager.pro": {"name": "Simple File Manager", "category": "files", "trust": 100, "signer": "Simple Mobile Tools"},
    "com.simplemobiletools.calculator.pro": {"name": "Simple Calculator", "category": "tools", "trust": 100, "signer": "Simple Mobile Tools"},
    "com.simplemobiletools.calendar.pro": {"name": "Simple Calendar", "category": "productivity", "trust": 100, "signer": "Simple Mobile Tools"},
    "com.simplemobiletools.notes.pro": {"name": "Simple Notes", "category": "productivity", "trust": 100, "signer": "Simple Mobile Tools"},
    "com.simplemobiletools.musicplayer": {"name": "Simple Music", "category": "music", "trust": 100, "signer": "Simple Mobile Tools"},
    "org.sufficientlysecure.materialistic": {"name": "Materialistic", "category": "reader", "trust": 95, "signer": "Sufficiently Secure"},
    "com.adobe.reader": {"name": "Adobe Reader", "category": "productivity", "trust": 100, "signer": "Adobe"},
    "com.dropbox.android": {"name": "Dropbox", "category": "cloud", "trust": 100, "signer": "Dropbox"},
    "com.box.android": {"name": "Box", "category": "cloud", "trust": 100, "signer": "Box"},
    "com.paypal.android.p2pmobile": {"name": "PayPal", "category": "finance", "trust": 100, "signer": "PayPal"},
}

# ============ Category Context ============
CATEGORY_CONTEXT = {
    "developer_tool": {"name_ar": "أداة مطوّر", "risky_perms_ok": ["android.permission.REQUEST_INSTALL_PACKAGES", "android.permission.SYSTEM_ALERT_WINDOW", "android.permission.WRITE_EXTERNAL_STORAGE", "android.permission.READ_EXTERNAL_STORAGE", "android.permission.PACKAGE_USAGE_STATS", "android.permission.MANAGE_EXTERNAL_STORAGE", "android.permission.WRITE_SECURE_SETTINGS", "android.permission.READ_LOGS", "android.permission.DUMP", "android.permission.FOREGROUND_SERVICE", "android.permission.WAKE_LOCK"], "penalty_reduction": 0.7},
    "browser": {"name_ar": "متصفح", "risky_perms_ok": ["android.permission.INTERNET", "android.permission.ACCESS_NETWORK_STATE", "android.permission.WRITE_EXTERNAL_STORAGE", "android.permission.READ_EXTERNAL_STORAGE"], "penalty_reduction": 0.5},
    "vpn": {"name_ar": "VPN", "risky_perms_ok": ["android.permission.FOREGROUND_SERVICE", "android.permission.INTERNET", "android.permission.ACCESS_NETWORK_STATE"], "penalty_reduction": 0.5},
    "system": {"name_ar": "تطبيق نظام", "risky_perms_ok": [], "penalty_reduction": 0.3},
    "game": {"name_ar": "لعبة", "risky_perms_ok": ["android.permission.INTERNET", "android.permission.ACCESS_NETWORK_STATE"], "penalty_reduction": 0.8},
    "messaging": {"name_ar": "تطبيق تواصل", "risky_perms_ok": ["android.permission.READ_CONTACTS", "android.permission.CAMERA", "android.permission.RECORD_AUDIO"], "penalty_reduction": 0.6},
    "social": {"name_ar": "شبكة اجتماعية", "risky_perms_ok": ["android.permission.READ_CONTACTS", "android.permission.CAMERA", "android.permission.RECORD_AUDIO", "android.permission.ACCESS_FINE_LOCATION"], "penalty_reduction": 0.6},
    "app_store": {"name_ar": "متجر تطبيقات", "risky_perms_ok": ["android.permission.REQUEST_INSTALL_PACKAGES", "android.permission.WRITE_EXTERNAL_STORAGE"], "penalty_reduction": 0.5},
    "media": {"name_ar": "وسائط", "risky_perms_ok": ["android.permission.INTERNET", "android.permission.WRITE_EXTERNAL_STORAGE"], "penalty_reduction": 0.6},
    "streaming": {"name_ar": "بث", "risky_perms_ok": ["android.permission.INTERNET", "android.permission.WRITE_EXTERNAL_STORAGE"], "penalty_reduction": 0.6},
    "music": {"name_ar": "موسيقى", "risky_perms_ok": ["android.permission.INTERNET", "android.permission.WRITE_EXTERNAL_STORAGE"], "penalty_reduction": 0.6},
    "education": {"name_ar": "تعليم", "risky_perms_ok": ["android.permission.INTERNET", "android.permission.WRITE_EXTERNAL_STORAGE"], "penalty_reduction": 0.6},
    "productivity": {"name_ar": "إنتاجية", "risky_perms_ok": ["android.permission.INTERNET", "android.permission.WRITE_EXTERNAL_STORAGE", "android.permission.READ_EXTERNAL_STORAGE"], "penalty_reduction": 0.6},
    "cloud": {"name_ar": "تخزين سحابي", "risky_perms_ok": ["android.permission.INTERNET", "android.permission.WRITE_EXTERNAL_STORAGE", "android.permission.READ_EXTERNAL_STORAGE"], "penalty_reduction": 0.6},
}

# ============ Suspicious URLs ============
SUSPICIOUS_TLDS = [".ru", ".tk", ".ml", ".ga", ".cf", ".xyz", ".top", ".work", ".click", ".link", ".download"]
SUSPICIOUS_URL_KEYWORDS = ["malware", "hack", "crack", "cheat", "free-", "mod-", "keygen", "patch", "warez", "nulled", "cracked", "unlock"]
SUSPICIOUS_DOMAINS = ["pastebin.com", "anonfiles.com", "mediafire.com", "mega.nz", "workupload.com", "anonfile.com", "discord.gg", "bit.ly", "tinyurl.com", "t.me"]

# ============ Hash Functions ============
def sha256_file(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def md5_file(path):
    h = hashlib.md5()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


# ============ XAPK Full Analysis ============
def is_xapk(path):
    """XAPK = ملف ZIP يحتوي على APK + OBB"""
    try:
        with zipfile.ZipFile(path, "r") as z:
            names = z.namelist()
            has_apk = any(n.endswith(".apk") for n in names)
            has_manifest = "manifest.json" in names
            has_obb = any(n.startswith("Android/obb/") for n in names)
            return has_apk and (has_manifest or has_obb)
    except Exception:
        return False


def analyze_xapk_full(xapk_path):
    """
    فحص كامل لـ XAPK:
    - استخراج كل APK
    - فحص كل واحد
    - مقارنة الصلاحيات بين base والـ config
    """
    temp_dir = tempfile.mkdtemp(prefix="xapk_")
    result = {
        "is_xapk": True,
        "temp_dir": temp_dir,
        "base_apk": None,
        "apks": [],
        "config_apks": [],
        "obb_files": [],
        "all_permissions": [],
        "base_permissions": [],
        "extra_permissions": [],
        "has_manifest": False,
        "error": None,
    }
    
    try:
        with zipfile.ZipFile(xapk_path, "r") as z:
            # 1. استخراج كل شيء
            for name in z.namelist():
                if name.endswith(".apk"):
                    z.extract(name, temp_dir)
                    full_path = os.path.join(temp_dir, name)
                    result["apks"].append({
                        "name": name.split("/")[-1],
                        "path": full_path,
                        "size": z.getinfo(name).file_size,
                    })
                elif name.startswith("Android/obb/"):
                    result["obb_files"].append(name.split("/")[-1])
                elif name == "manifest.json":
                    result["has_manifest"] = True
                    z.extract(name, temp_dir)
            
            # 2. تصنيف: base vs config
            if not result["apks"]:
                result["error"] = "No APK files found in XAPK"
                return result
            
            # أكبر APK = base (عادة)
            base_candidates = [a for a in result["apks"] if "base" in a["name"].lower()]
            if base_candidates:
                result["base_apk"] = base_candidates[0]
            else:
                # أكبر ملف
                result["base_apk"] = max(result["apks"], key=lambda x: x["size"])
            
            # config APKs = الباقي
            result["config_apks"] = [a for a in result["apks"] if a["path"] != result["base_apk"]["path"]]
            
            # 3. فحص كل APK
            try:
                from pyaxmlparser import APK
                base_perms = set()
                all_perms = set()
                
                # Base APK
                try:
                    base = APK(result["base_apk"]["path"])
                    base_perms = set(base.get_permissions())
                    all_perms.update(base_perms)
                    result["base_permissions"] = sorted(base_perms)
                except Exception as e:
                    result["error"] = f"Base APK parse error: {e}"
                
                # Config APKs
                for cfg in result["config_apks"]:
                    try:
                        cfg_apk = APK(cfg["path"])
                        cfg_perms = set(cfg_apk.get_permissions())
                        cfg["permissions"] = sorted(cfg_perms)
                        all_perms.update(cfg_perms)
                    except Exception:
                        cfg["permissions"] = []
                
                # 4. الصلاحيات الزائدة عن base
                extra = all_perms - base_perms
                result["extra_permissions"] = sorted(extra)
                result["all_permissions"] = sorted(all_perms)
                
            except ImportError:
                result["error"] = "pyaxmlparser not installed"
        
    except Exception as e:
        result["error"] = str(e)
    
    return result


def cleanup_xapk_temp(xapk_info):
    """حذف الملفات المؤقتة"""
    if xapk_info and xapk_info.get("temp_dir"):
        try:
            shutil.rmtree(xapk_info["temp_dir"], ignore_errors=True)
        except Exception:
            pass


# ============ DEX Analysis ============
def extract_dex_strings(apk_path):
    """استخراج كل النصوص من ملفات .dex"""
    all_strings = []
    try:
        with zipfile.ZipFile(apk_path, "r") as z:
            for name in z.namelist():
                if name.endswith(".dex"):
                    try:
                        data = z.read(name)
                        strings = re.findall(rb"[\x20-\x7e]{6,}", data)
                        for s in strings:
                            try:
                                all_strings.append(s.decode("ascii", errors="ignore"))
                            except Exception:
                                pass
                    except Exception:
                        continue
    except Exception:
        pass
    return all_strings


def detect_suspicious_code(all_strings):
    """كشف الأنماط المشبوهة في الكود"""
    findings = {}
    joined = "\n".join(all_strings)
    
    for pattern_name, info in SUSPICIOUS_PATTERNS.items():
        matches = []
        for pattern in info["patterns"]:
            if re.search(pattern, joined, re.IGNORECASE):
                matches.append(pattern)
        if matches:
            findings[pattern_name] = {
                "matches": matches,
                "explain": info["explain"],
                "category": info.get("category", "info"),
                "name_ar": info.get("name_ar", pattern_name),
                "short_ar": info.get("short_ar", ""),
            }
    return findings


def detect_trackers_from_strings(all_strings):
    """كشف مكتبات التتبع"""
    joined = "\n".join(all_strings)
    found = []
    for tracker_name, patterns in KNOWN_TRACKERS.items():
        for pattern in patterns:
            if pattern in joined:
                found.append(tracker_name)
                break
    return sorted(set(found))


def extract_libraries(apk_path):
    """استخراج المكتبات الأصلية (.so)"""
    libs = []
    try:
        with zipfile.ZipFile(apk_path, "r") as z:
            for name in z.namelist():
                if name.startswith("lib/") and name.endswith(".so"):
                    libs.append(name.split("/")[-1])
    except Exception:
        pass
    return sorted(set(libs))


def count_dex_files(apk_path):
    """عدد ملفات DEX"""
    count = 0
    try:
        with zipfile.ZipFile(apk_path, "r") as z:
            for name in z.namelist():
                if name.endswith(".dex"):
                    count += 1
    except Exception:
        pass
    return count


def count_total_files(apk_path):
    """إجمالي الملفات داخل APK"""
    try:
        with zipfile.ZipFile(apk_path, "r") as z:
            return len(z.namelist())
    except Exception:
        return 0


# ============ Deep Content Analysis ============
def extract_urls(all_strings):
    """استخراج كل URLs من النصوص"""
    url_pattern = re.compile(r'https?://[a-zA-Z0-9\-\.]+\.[a-zA-Z]{2,}[^\s"\'<>\\]*')
    urls = set()
    for s in all_strings:
        try:
            matches = url_pattern.findall(s)
            for u in matches:
                # تنظيف
                u = u.rstrip('.,;:)"\'>')
                if len(u) > 10 and len(u) < 200:
                    urls.add(u)
        except Exception:
            continue
    return sorted(urls)


def is_suspicious_url(url):
    """فحص إذا كان URL مشبوهاً"""
    url_lower = url.lower()
    
    # فحص TLDs
    for tld in SUSPICIOUS_TLDS:
        if tld + "/" in url_lower or url_lower.endswith(tld):
            return True, f"TLD مشبوه ({tld})"
    
    # فحص كلمات مفتاحية
    for kw in SUSPICIOUS_URL_KEYWORDS:
        if kw in url_lower:
            return True, f"كلمة مفتاحية ({kw})"
    
    # فحص نطاقات مشبوهة
    for domain in SUSPICIOUS_DOMAINS:
        if domain in url_lower:
            return True, f"نطاق مشبوه ({domain})"
    
    return False, None


def analyze_urls(all_strings):
    """تحليل كل URLs وإرجاع المشبوهة"""
    urls = extract_urls(all_strings)
    suspicious = []
    safe_count = 0
    
    for url in urls[:500]:  # أول 500 URL
        is_sus, reason = is_suspicious_url(url)
        if is_sus:
            suspicious.append({"url": url, "reason": reason})
        else:
            safe_count += 1
    
    return {
        "total": len(urls),
        "safe": safe_count,
        "suspicious": suspicious[:50],  # أول 50
        "suspicious_count": len(suspicious),
    }


def classify_libraries(libs):
    """تصنيف المكتبات: معروفة / مجهولة"""
    known = []
    unknown = []
    
    for lib in libs:
        if lib in KNOWN_LIBRARIES:
            known.append({"name": lib, "desc": KNOWN_LIBRARIES[lib]})
        else:
            unknown.append(lib)
    
    return {
        "known": known,
        "unknown": unknown,
        "known_count": len(known),
        "unknown_count": len(unknown),
    }


def deep_content_analysis(apk_path, all_strings, libs):
    """
    تحليل عميق للمحتوى الفعلي للتطبيق
    - URLs
    - المكتبات
    - Shell commands محددة
    """
    result = {
        "urls": analyze_urls(all_strings),
        "libraries": classify_libraries(libs),
        "shell_analysis": analyze_shell_commands(all_strings),
    }
    return result


def analyze_shell_commands(all_strings):
    """تحليل أوامر Shell إن وجدت"""
    shell_patterns = [
        (r"Runtime\.getRuntime\(\)\.exec\([^)]{0,200}\)", "exec مباشر"),
        (r"ProcessBuilder\([^)]{0,200}\)", "ProcessBuilder"),
        (r"su\s+-c", "أمر su (Root)"),
        (r"/system/bin/sh", "Shell النظام"),
        (r"pm\s+install", "تثبيت APK"),
        (r"am\s+start", "تشغيل Activity"),
        (r"chmod\s+[0-9]{3,4}", "تعديل صلاحيات ملفات"),
        (r"rm\s+-rf", "حذف قسري"),
        (r"curl\s+", "أمر curl (تحميل)"),
        (r"wget\s+", "أمر wget (تحميل)"),
    ]
    
    found = []
    joined = "\n".join(all_strings)
    
    for pattern, name in shell_patterns:
        if re.search(pattern, joined, re.IGNORECASE):
            found.append(name)
    
    return {
        "found": found,
        "count": len(found),
        "risky": any(x in found for x in ["أمر su (Root)", "pm install", "rm -rf", "chmod"]),
    }


# ============ APK Analysis ============
def analyze_with_pyaxml(apk_path):
    """قراءة AndroidManifest"""
    try:
        from pyaxmlparser import APK
        apk = APK(apk_path)
        return {
            "package": apk.package,
            "app_name": apk.application,
            "version_name": apk.version_name,
            "version_code": apk.version_code,
            "min_sdk": apk.get_min_sdk_version(),
            "target_sdk": apk.get_target_sdk_version(),
            "permissions": apk.get_permissions(),
            "activities": apk.get_activities(),
            "services": apk.get_services(),
            "receivers": apk.get_receivers(),
            "providers": apk.get_providers(),
            "main_activity": apk.get_main_activity(),
            "signed": apk.is_signed(),
            "signed_v1": apk.is_signed_v1(),
            "signed_v2": apk.is_signed_v2(),
            "signed_v3": apk.is_signed_v3(),
            "files": apk.get_files(),
        }
    except ImportError:
        return None
    except Exception as e:
        return {"error": str(e)}


def get_signature_info(apk_path):
    """معلومات التوقيع من META-INF"""
    sig_files = []
    cert_files = []
    try:
        with zipfile.ZipFile(apk_path, "r") as z:
            for name in z.namelist():
                if name.startswith("META-INF/"):
                    if name.endswith((".RSA", ".DSA", ".EC")):
                        sig_files.append(name)
                    if name.endswith((".SF", ".MF")):
                        cert_files.append(name)
    except Exception:
        pass
    return {"signatures": sig_files, "certificates": cert_files}


# ============ Package Identification ============
def identify_package(package_name):
    """تحديد التطبيق من قاعدة البيانات"""
    if package_name in KNOWN_PACKAGES:
        return KNOWN_PACKAGES[package_name]
    return None


# ============ Contextual Score Helpers ============
def get_contextual_penalty(perm, app_info):
    """تخفيف خصم الصلاحيات حسب فئة التطبيق"""
    if not app_info:
        return 1.0
    category = app_info.get("category", "")
    ctx = CATEGORY_CONTEXT.get(category)
    if ctx and perm in ctx.get("risky_perms_ok", []):
        return ctx.get("penalty_reduction", 1.0)
    return 1.0


# ============ Score Calculator ============
def calculate_score(apk_data, trackers, suspicious, libs, app_info=None, content=None, xapk_info=None):
    """
    الحساب المتوازن:
    - إذا تطبيق أصلي موثوق: score عالي
    - إذا mod/مجهول: نعتمد على فحص المحتوى
    - الحيادية: لا نحكم قبل الفحص
    """
    score = 100
    breakdown = []
    
    perms = apk_data.get("permissions", []) if apk_data else []
    
    # تصنيف الصلاحيات
    critical, high, medium = [], [], []
    for p in perms:
        if p in PERMISSIONS_DB:
            lvl = PERMISSIONS_DB[p]["level"]
            if lvl == "CRITICAL": critical.append(p)
            elif lvl == "HIGH": high.append(p)
            elif lvl == "MEDIUM": medium.append(p)
    
    # ============ Trust Bonus ============
    trust_bonus = 0
    if app_info:
        trust = app_info.get("trust", 0)
        if trust >= 100:
            trust_bonus = 25
        elif trust >= 95:
            trust_bonus = 20
        elif trust >= 90:
            trust_bonus = 15
        elif trust >= 85:
            trust_bonus = 10
        
        if trust_bonus > 0:
            breakdown.append({
                "lbl": f"✅ تطبيق موثوق ({app_info['name']})",
                "val": f"+{trust_bonus}",
                "type": "pos"
            })
    
    # ============ Signature Check ============
    if apk_data and not apk_data.get("signed"):
        score -= 30
        breakdown.append({"lbl": "❌ التطبيق غير موقّع رقمياً", "val": "-30", "type": "neg"})
    
    # ============ Critical Permissions ============
    if critical:
        effective = sum(8 * get_contextual_penalty(p, app_info) for p in critical)
        penalty = int(effective)
        score -= penalty
        label = f"🔴 {len(critical)} صلاحية حرجة"
        if app_info:
            label += " (مخففة)"
        breakdown.append({"lbl": label, "val": f"-{penalty}", "type": "neg"})
    
    # ============ High Permissions ============
    if high:
        effective = sum(3 * get_contextual_penalty(p, app_info) for p in high)
        penalty = int(effective)
        score -= penalty
        breakdown.append({"lbl": f"🟡 {len(high)} صلاحيات عالية", "val": f"-{penalty}", "type": "neg"})
    
    # ============ Trackers ============
    if len(trackers) > 8:
        score -= 15
        breakdown.append({"lbl": f"📊 {len(trackers)} مكتبة تتبع", "val": "-15", "type": "neg"})
    elif len(trackers) > 4:
        score -= 8
        breakdown.append({"lbl": f"📊 {len(trackers)} مكتبات تتبع", "val": "-8", "type": "neg"})
    
    # ============ Suspicious Code ============
    if "Accessibility Abuse" in suspicious:
        score -= 20
        breakdown.append({"lbl": "🚨 خدمة الوصول (Accessibility)", "val": "-20", "type": "neg"})
    if "Notification Listener" in suspicious:
        score -= 12
        breakdown.append({"lbl": "🚨 يقرأ الإشعارات", "val": "-12", "type": "neg"})
    if "SMS Reading" in suspicious:
        score -= 12
        breakdown.append({"lbl": "🚨 يتعامل مع SMS", "val": "-12", "type": "neg"})
    
    # Shell commands — حيادي حسب الفئة
    if "Shell Commands" in suspicious:
        is_developer_tool = app_info and app_info.get("category") == "developer_tool"
        if is_developer_tool:
            score -= 2
            breakdown.append({"lbl": "ℹ️ أوامر نظام (طبيعي لأداة مطوّر)", "val": "-2", "type": "neg"})
        else:
            score -= 12
            breakdown.append({"lbl": "🚨 تنفيذ أوامر نظام", "val": "-12", "type": "neg"})
    
    if "Dynamic Code Loading" in suspicious:
        score -= 8
        breakdown.append({"lbl": "⚠️ تحميل كود ديناميكي", "val": "-8", "type": "neg"})
    if "Root Detection" in suspicious:
        score -= 3
        breakdown.append({"lbl": "ℹ️ يفحص Root", "val": "-3", "type": "neg"})
    if "Emulator Check" in suspicious:
        score -= 3
        breakdown.append({"lbl": "ℹ️ يفحص المحاكي", "val": "-3", "type": "neg"})
    if "Clipboard Access" in suspicious:
        score -= 5
        breakdown.append({"lbl": "⚠️ يقرأ الحافظة", "val": "-5", "type": "neg"})
    
    # ============ Old minSdk ============
    min_sdk = apk_data.get("min_sdk") if apk_data else None
    if min_sdk and str(min_sdk).isdigit() and int(min_sdk) < 21:
        score -= 10
        breakdown.append({"lbl": f"⚠️ minSdk قديم ({min_sdk})", "val": "-10", "type": "neg"})
    
    # ============ Native Libs ============
    if len(libs) > 10:
        score -= 5
        breakdown.append({"lbl": f"📚 {len(libs)} مكتبة أصلية", "val": "-5", "type": "neg"})
    
    # ============ Content Analysis (URLs / Unknown Libs / Shell) ============
    if content:
        urls_info = content.get("urls", {})
        sus_urls = urls_info.get("suspicious_count", 0)
        if sus_urls > 5:
            score -= 20
            breakdown.append({"lbl": f"🌐 {sus_urls} URLs مشبوهة", "val": "-20", "type": "neg"})
        elif sus_urls > 0:
            score -= 5
            breakdown.append({"lbl": f"🌐 {sus_urls} URLs مشبوهة", "val": "-5", "type": "neg"})
        
        libs_info = content.get("libraries", {})
        unknown_libs = libs_info.get("unknown_count", 0)
        if unknown_libs > 5:
            score -= 10
            breakdown.append({"lbl": f"📚 {unknown_libs} مكتبات أصلية مجهولة", "val": "-10", "type": "neg"})
        elif unknown_libs > 2:
            score -= 4
            breakdown.append({"lbl": f"📚 {unknown_libs} مكتبات مجهولة", "val": "-4", "type": "neg"})
        
        shell_info = content.get("shell_analysis", {})
        if shell_info.get("risky"):
            score -= 10
            breakdown.append({"lbl": "🚨 أوامر نظام خطيرة", "val": "-10", "type": "neg"})
    
    # ============ XAPK Extra Permissions ============
    if xapk_info and xapk_info.get("extra_permissions"):
        extra_count = len(xapk_info["extra_permissions"])
        score -= extra_count * 3
        breakdown.append({
            "lbl": f"⚠️ {extra_count} صلاحيات إضافية في XAPK",
            "val": f"-{extra_count * 3}",
            "type": "neg"
        })
    
    # ============ Apply Trust Bonus ============
    score += trust_bonus
    
    score = max(0, min(100, score))
    return score, breakdown


# ============ Verdict ============
def get_verdict(score, app_info=None):
    if score >= 80:
        return {
            "level": "safe",
            "icon": "fa-circle-check",
            "title": "آمن للاستخدام",
            "advice": "التطبيق يبدو آمناً. لا توجد مؤشرات خطر كبيرة. يمكنك استخدامه بثقة، لكن راقب سلوكه في الأسبوع الأول.",
            "short": "آمن"
        }
    elif score >= 60:
        return {
            "level": "caution",
            "icon": "fa-triangle-exclamation",
            "title": "يحتاج حذر",
            "advice": "التطبيق يحتوي على بعض التنبيهات. راجع قائمة التنبيهات قبل الاستخدام ولا تمنحه صلاحيات إضافية.",
            "short": "حذر"
        }
    elif score >= 40:
        return {
            "level": "caution",
            "icon": "fa-circle-exclamation",
            "title": "استخدمه بحذر",
            "advice": "التطبيق مشبوه نسبياً. يحتوي على صلاحيات أو أنماط قد تشكل خطراً. راجع التنبيهات بعناية.",
            "short": "مشبوه"
        }
    else:
        return {
            "level": "danger",
            "icon": "fa-skull-crossbones",
            "title": "خطر — لا تستخدمه",
            "advice": "التطبيق يحتوي على مؤشرات خطر متعددة. ننصح بعدم تثبيته أو حذفه فوراً إذا كان مثبتاً.",
            "short": "خطر"
        }


def perm_sort_key(perm):
    """ترتيب الصلاحيات حسب الخطورة"""
    if perm in PERMISSIONS_DB:
        order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
        return order.get(PERMISSIONS_DB[perm]["level"], 4)
    return 5


def alert_sort_key(alert):
    """ترتيب التنبيهات حسب الخطورة"""
    order = {"danger": 0, "warn": 1, "info": 2, "safe": 3}
    return order.get(alert.get("level", "info"), 4)
    
    # ============ HTML Report Generator ============
def generate_html_report(report, filename):
    p = report.get("apk_data", {}) or {}
    perms = report.get("all_permissions", [])
    trackers = report.get("trackers", [])
    suspicious = report.get("suspicious_code", {})
    libs = report.get("native_libs", [])
    score = report.get("score", 0)
    breakdown = report.get("score_breakdown", [])
    sig_info = report.get("signature_info", {})
    app_info = report.get("known_app")
    xapk_info = report.get("xapk_info")
    content = report.get("content_analysis", {})
    
    verdict = get_verdict(score, app_info)
    perms_sorted = sorted(perms, key=perm_sort_key)
    
    # ===== Trust section =====
    trust_html = ""
    if app_info:
        trust_color = "#059669" if app_info.get("trust", 0) >= 95 else "#d97706"
        trust_icon = "fa-circle-check" if app_info.get("trust", 0) >= 95 else "fa-circle-info"
        trust_label = "تطبيق موثوق" if app_info.get("trust", 0) >= 95 else "تطبيق معروف"
        category_name = CATEGORY_CONTEXT.get(app_info.get("category", ""), {}).get("name_ar", app_info.get("category", ""))
        
        trust_html = f"""
        <div class="trust-card" style="border-right-color:{trust_color}; background:{trust_color}10;">
          <div class="trust-head">
            <i class="fa-solid {trust_icon}" style="color:{trust_color}; font-size:1.5rem;"></i>
            <div style="flex:1;">
              <div style="font-weight:800; color:{trust_color}; font-size:0.95rem;">{trust_label}</div>
              <div style="font-size:0.78rem; color:var(--text-sub); margin-top:2px;">{app_info['name']} — {category_name}</div>
            </div>
            <span style="font-size:0.7rem; padding:5px 10px; border-radius:12px; background:{trust_color}; color:#fff; font-weight:700;">{app_info.get('trust', 0)}%</span>
          </div>
        </div>"""
    
    # ===== XAPK Section =====
    xapk_html = ""
    if xapk_info and xapk_info.get("is_xapk"):
        extra_perms = xapk_info.get("extra_permissions", [])
        extra_warning = ""
        if extra_perms:
            extra_warning = f"""
            <div class="xapk-warning">
              <i class="fa-solid fa-triangle-exclamation"></i>
              <div>
                <strong>{len(extra_perms)} صلاحيات إضافية في config APKs</strong>
                <div style="font-size:0.75rem; margin-top:4px;">قد تكون مخفية عن المستخدم</div>
              </div>
            </div>"""
        
        xapk_html = f"""
        <div class="section-title"><i class="fa-solid fa-box-open"></i><span>XAPK Bundle</span></div>
        <div class="info-card open">
          <div class="info-card-head" onclick="this.parentElement.classList.toggle('open')">
            <span><i class="fa-solid fa-cube" style="color:var(--primary);"></i> محتوى XAPK</span>
            <i class="fa-solid fa-chevron-down chev"></i>
          </div>
          <div class="info-card-body">
            <div class="data-row"><span class="lbl">إجمالي ملفات APK</span><span class="val">{len(xapk_info.get('apks', []))}</span></div>
            <div class="data-row"><span class="lbl">APK رئيسي</span><span class="val">{xapk_info['base_apk']['name'] if xapk_info.get('base_apk') else 'N/A'}</span></div>
            <div class="data-row"><span class="lbl">Config APKs</span><span class="val">{len(xapk_info.get('config_apks', []))}</span></div>
            <div class="data-row"><span class="lbl">ملفات OBB</span><span class="val">{len(xapk_info.get('obb_files', []))}</span></div>
            <div class="data-row"><span class="lbl">manifest.json</span><span class="val">{'✅ موجود' if xapk_info.get('has_manifest') else '❌ غير موجود'}</span></div>
            {extra_warning}
          </div>
        </div>"""
    
    # ===== Content Analysis Section =====
    content_html = ""
    if content:
        urls_info = content.get("urls", {})
        libs_info = content.get("libraries", {})
        shell_info = content.get("shell_analysis", {})
        
        # URLs
        sus_urls = urls_info.get("suspicious", [])
        urls_display = ""
        if sus_urls:
            for u in sus_urls[:10]:
                urls_display += f'<div class="url-item"><i class="fa-solid fa-triangle-exclamation"></i><span class="url-text">{u["url"]}</span><span class="url-reason">{u["reason"]}</span></div>'
        else:
            urls_display = '<div class="empty-mini"><i class="fa-solid fa-check-circle"></i> لا توجد URLs مشبوهة</div>'
        
        # Libraries
        known_libs = libs_info.get("known", [])
        unknown_libs = libs_info.get("unknown", [])
        libs_display = ""
        if known_libs:
            libs_display += '<div class="lib-group"><strong style="color:#059669;">✅ مكتبات معروفة:</strong><div class="chips-wrap">'
            for l in known_libs[:15]:
                libs_display += f'<span class="chip chip-ok" onclick="showSheet(\'lib_{l["name"].replace(".","_").replace("-","_")}\')" title="{l["desc"]}"><i class="fa-solid fa-cube"></i> {l["name"]}</span>'
            libs_display += '</div></div>'
        if unknown_libs:
            libs_display += '<div class="lib-group"><strong style="color:#d97706;">⚠️ مكتبات مجهولة:</strong><div class="chips-wrap">'
            for l in unknown_libs[:15]:
                libs_display += f'<span class="chip chip-warn"><i class="fa-solid fa-question"></i> {l}</span>'
            libs_display += '</div></div>'
        if not known_libs and not unknown_libs:
            libs_display = '<div class="empty-mini"><i class="fa-solid fa-info-circle"></i> لا توجد مكتبات أصلية</div>'
        
        # Shell
        shell_found = shell_info.get("found", [])
        if shell_found:
            shell_display = '<div class="chips-wrap">'
            for s in shell_found:
                chip_class = "chip-danger" if s in ["أمر su (Root)", "pm install", "rm -rf", "chmod"] else "chip-warn"
                shell_display += f'<span class="chip {chip_class}"><i class="fa-solid fa-terminal"></i> {s}</span>'
            shell_display += '</div>'
        else:
            shell_display = '<div class="empty-mini"><i class="fa-solid fa-check-circle"></i> لا توجد أوامر Shell</div>'
        
        content_html = f"""
        <div class="section-title"><i class="fa-solid fa-microscope"></i><span>تحليل المحتوى</span></div>
        
        <div class="content-card">
          <div class="content-head">
            <i class="fa-solid fa-link"></i>
            <span>الروابط (URLs)</span>
            <span class="content-badge">{urls_info.get('total', 0)}</span>
          </div>
          <div class="content-body">
            <div class="url-stats">
              <span class="stat-chip"><i class="fa-solid fa-check"></i> {urls_info.get('safe', 0)} آمن</span>
              <span class="stat-chip warn"><i class="fa-solid fa-triangle-exclamation"></i> {urls_info.get('suspicious_count', 0)} مشبوه</span>
            </div>
            {urls_display}
          </div>
        </div>
        
        <div class="content-card">
          <div class="content-head">
            <i class="fa-solid fa-cube"></i>
            <span>المكتبات الأصلية</span>
            <span class="content-badge">{libs_info.get('known_count', 0)} معروفة / {libs_info.get('unknown_count', 0)} مجهولة</span>
          </div>
          <div class="content-body">
            {libs_display}
          </div>
        </div>
        
        <div class="content-card">
          <div class="content-head">
            <i class="fa-solid fa-terminal"></i>
            <span>أوامر النظام (Shell)</span>
            <span class="content-badge">{shell_info.get('count', 0)}</span>
          </div>
          <div class="content-body">
            {shell_display}
          </div>
        </div>"""
    
    # ===== Build Alerts =====
    unified_alerts = []
    
    if "Accessibility Abuse" in suspicious:
        unified_alerts.append({"id": "accessibility", "level": "danger", "icon": "🚨", "title": "يستخدم خدمة الوصول (Accessibility)", "summary": "أخطر صلاحية — قد يقرأ كل ما على شاشتك بما فيها كلمات السر", "badge": "خطر شديد"})
    if "Notification Listener" in suspicious:
        unified_alerts.append({"id": "notif_listener", "level": "danger", "icon": "🚨", "title": "يقرأ الإشعارات", "summary": "قد يقرأ كل إشعاراتك بما فيها رموز التحقق", "badge": "خطر شديد"})
    if "SMS Reading" in suspicious or "android.permission.READ_SMS" in perms or "android.permission.SEND_SMS" in perms:
        unified_alerts.append({"id": "sms_access", "level": "danger", "icon": "🚨", "title": "يتعامل مع الرسائل (SMS)", "summary": "قد يسرق رموز التحقق OTP", "badge": "خطر شديد"})
    if "android.permission.REQUEST_INSTALL_PACKAGES" in perms:
        unified_alerts.append({"id": "install_pkg", "level": "danger", "icon": "🔴", "title": "طلب صلاحية تثبيت تطبيقات", "summary": "قد يثبت تطبيقات أخرى بدون علمك", "badge": "حرج"})
    if "Shell Commands" in suspicious:
        lvl = "info" if app_info and app_info.get("category") == "developer_tool" else "danger"
        unified_alerts.append({"id": "shell_cmds", "level": lvl, "icon": "ℹ️" if lvl == "info" else "🚨", "title": "تنفيذ أوامر نظام (Shell)", "summary": "طبيعي لأدوات المطورين" if lvl == "info" else "قد يتحكم بالجهاز", "badge": "معلوماتي" if lvl == "info" else "خطر"})
    if "Dynamic Code Loading" in suspicious:
        unified_alerts.append({"id": "dynamic_code", "level": "warn", "icon": "⚠️", "title": "تحميل كود ديناميكي", "summary": "يُحمّل كوداً من الخارج — قد يُساء استخدامه", "badge": "تحذير"})
    if "Clipboard Access" in suspicious:
        unified_alerts.append({"id": "clipboard", "level": "warn", "icon": "⚠️", "title": "يقرأ الحافظة (Clipboard)", "summary": "قد يقرأ كلمات السر أو البيانات المنسوخة", "badge": "تحذير"})
    
    min_sdk = p.get("min_sdk", "")
    if min_sdk and str(min_sdk).isdigit() and int(min_sdk) < 21:
        unified_alerts.append({"id": "old_sdk", "level": "warn", "icon": "⚠️", "title": f"minSdk قديم (Android {min_sdk})", "summary": "يعمل على أنظمة قديمة = ثغرات أمنية", "badge": "تحذير"})
    
    high_perms = [x for x in perms if x in PERMISSIONS_DB and PERMISSIONS_DB[x]["level"] == "HIGH"]
    if high_perms:
        unified_alerts.append({"id": "high_perms", "level": "warn", "icon": "🟡", "title": f"{len(high_perms)} صلاحيات عالية الخطورة", "summary": "قراءة/كتابة الملفات، إلخ", "badge": "تحذير"})
    
    if "WebView Usage" in suspicious:
        unified_alerts.append({"id": "webview", "level": "warn", "icon": "⚠️", "title": "يستخدم WebView (متصفح داخلي)", "summary": "تأكد من استخدام HTTPS", "badge": "تحذير"})
    
    # Content-based alerts
    if content:
        sus_count = content.get("urls", {}).get("suspicious_count", 0)
        if sus_count > 0:
            unified_alerts.append({"id": "suspicious_urls", "level": "warn" if sus_count <= 5 else "danger", "icon": "🌐", "title": f"{sus_count} URLs مشبوهة", "summary": "روابط قد تشير لنشاط خبيث", "badge": "تحذير" if sus_count <= 5 else "خطر"})
        
        unk_libs = content.get("libraries", {}).get("unknown_count", 0)
        if unk_libs > 3:
            unified_alerts.append({"id": "unknown_libs", "level": "info", "icon": "ℹ️", "title": f"{unk_libs} مكتبات أصلية مجهولة", "summary": "غير موجودة في قاعدة البيانات", "badge": "معلوماتي"})
    
    # XAPK
    if xapk_info and xapk_info.get("extra_permissions"):
        unified_alerts.append({"id": "xapk_extra", "level": "warn", "icon": "⚠️", "title": f"صلاحيات إضافية في XAPK ({len(xapk_info['extra_permissions'])})", "summary": "قد تكون مخفية في config APKs", "badge": "تحذير"})
    
    if "Root Detection" in suspicious or "Emulator Check" in suspicious:
        unified_alerts.append({"id": "root_check", "level": "info", "icon": "ℹ️", "title": "فحص حالة Root والمحاكي", "summary": "سلوك شائع — ليس خطراً بحد ذاته", "badge": "معلوماتي"})
    
    if trackers:
        unified_alerts.append({"id": "trackers_info", "level": "info", "icon": "ℹ️", "title": f"{len(trackers)} مكتبة تتبع", "summary": "تتبع استخدامك — شائع في معظم التطبيقات", "badge": "معلوماتي"})
    
    unified_alerts.sort(key=alert_sort_key)
    
    alerts_html = ""
    for alert in unified_alerts:
        alerts_html += f"""
        <div class="alert-card {alert['level']}" onclick="showSheet('{alert['id']}')">
          <div class="alert-head">
            <div class="alert-title"><span>{alert['icon']}</span><span>{alert['title']}</span></div>
            <span class="alert-badge {alert['level']}">{alert['badge']}</span>
          </div>
          <div class="alert-summary">{alert['summary']}</div>
        </div>"""
    
    alert_count = len(unified_alerts)
    
    # ===== Permissions =====
    perms_html = ""
    perm_icons = {
        "CRITICAL": ("fa-download", "#dc2626", "حرج"),
        "HIGH": ("fa-folder-open", "#ea580c", "عالي"),
        "MEDIUM": ("fa-wifi", "#d97706", "متوسط"),
        "LOW": ("fa-circle", "#059669", "منخفض"),
    }
    for perm in perms_sorted:
        short = perm.replace("android.permission.", "")
        if perm in PERMISSIONS_DB:
            info = PERMISSIONS_DB[perm]
            level = info["level"]
            icon_name, color, level_ar = perm_icons.get(level, ("fa-circle", "#64748b", "عادي"))
            name_ar = info["name_ar"]
            sheet_key = "perm_" + short.lower().replace(".", "_")
            perms_html += f"""
        <div class="perm-card" onclick="showSheet('{sheet_key}')">
          <div class="perm-icon-wrap" style="background:{color};"><i class="fa-solid {icon_name}"></i></div>
          <div class="perm-info">
            <div class="perm-name">{name_ar}</div>
            <div class="perm-tech">{short}</div>
          </div>
          <span class="perm-level-badge" style="background:{color};">{level_ar}</span>
        </div>"""
        else:
            perms_html += f"""
        <div class="perm-card" onclick="showSheet('generic_perm')">
          <div class="perm-icon-wrap" style="background:#64748b;"><i class="fa-solid fa-circle"></i></div>
          <div class="perm-info">
            <div class="perm-name">صلاحية نظام</div>
            <div class="perm-tech">{short}</div>
          </div>
          <span class="perm-level-badge" style="background:#64748b;">عادي</span>
        </div>"""
    
    # ===== Trackers =====
    trackers_html = ""
    if trackers:
        for t in trackers:
            key = "tracker_" + t.replace(" ", "_").lower()
            trackers_html += f"""
        <div class="alert-card warn" onclick="showSheet('{key}')" style="margin-bottom:6px;">
          <div class="alert-head">
            <div class="alert-title"><span>📊</span><span>{t}</span></div>
            <span class="alert-badge warn">تتبع</span>
          </div>
        </div>"""
    else:
        trackers_html = '<div class="empty-state"><i class="fa-solid fa-check-circle"></i> لا توجد مكتبات تتبع</div>'
    
    # ===== Signature =====
    sig_html = ""
    for s in sig_info.get("signatures", []):
        sig_html += f'<span class="chip chip-ok"><i class="fa-solid fa-lock"></i> {s}</span>'
    for c in sig_info.get("certificates", []):
        sig_html += f'<span class="chip chip-info"><i class="fa-solid fa-file-shield"></i> {c}</span>'
    if not sig_html:
        sig_html = '<div class="empty-state"><i class="fa-solid fa-triangle-exclamation"></i> لا توجد ملفات توقيع</div>'
    
    # ===== Data =====
    analyzed_at = report.get('analyzed_at', '')[:16].replace('T', ' ')
    app_name = p.get('app_name', 'N/A') or 'N/A'
    package_name = p.get('package', 'N/A') or 'N/A'
    version_name = p.get('version_name', 'N/A') or 'N/A'
    version_code = p.get('version_code', 'N/A') or 'N/A'
    min_sdk_val = p.get('min_sdk', 'N/A') or 'N/A'
    target_sdk_val = p.get('target_sdk', 'N/A') or 'N/A'
    size_mb = report.get('size_mb', 0)
    is_signed = p.get('signed', False)
    sha256 = report.get('sha256', '')
    md5 = report.get('md5', '')
    dex_count = report.get('dex_count', 0)
    total_files = report.get('total_files', 0)
    file_name = report.get('file', 'APK')
    
    signed_text = '<i class="fa-solid fa-shield"></i> موقّع رسمياً' if is_signed else '<i class="fa-solid fa-triangle-exclamation"></i> غير موقّع'
    signed_color = "#059669" if is_signed else "#dc2626"
    
    verdict_class = "safe" if verdict["level"] == "safe" else ("caution" if verdict["level"] == "caution" else "")
    
    sig_types = []
    if p.get("signed_v1"): sig_types.append("v1")
    if p.get("signed_v2"): sig_types.append("v2")
    if p.get("signed_v3"): sig_types.append("v3")
    sig_types_str = " + ".join(sig_types) if sig_types else "غير معروف"
    
    # ===== JS SHEETS =====
    score_rows_js = ""
    for r in breakdown:
        lbl_escaped = r['lbl'].replace("'", "\\'")
        score_rows_js += f"      {{ lbl: '{lbl_escaped}', val: '{r['val']}', type: '{r['type']}' }},\n"
    
    perms_sheets_js = ""
    for perm in perms_sorted:
        short = perm.replace("android.permission.", "")
        if perm in PERMISSIONS_DB:
            info = PERMISSIONS_DB[perm]
            key = "perm_" + short.lower().replace(".", "_")
            explain = info.get("explain", "").replace("'", "\\'").replace("\n", " ")
            name_ar = info.get("name_ar", "").replace("'", "\\'")
            level = info["level"]
            level_ar = {"CRITICAL": "حرج", "HIGH": "عالي", "MEDIUM": "متوسط", "LOW": "منخفض"}.get(level, "عادي")
            color = {"CRITICAL": "#dc2626", "HIGH": "#ea580c", "MEDIUM": "#d97706", "LOW": "#059669"}.get(level, "#64748b")
            risk = {"CRITICAL": "danger", "HIGH": "warn", "MEDIUM": "info", "LOW": "info"}.get(level, "info")
            perms_sheets_js += f'''
    "{key}": {{
        icon: '🔑', color: '{color}',
        title: '{name_ar}',
        subtitle: '{short} — {level_ar}',
        risk: '{risk}',
        riskText: '{level_ar}',
        sections: [
            {{ title: 'الوصف', text: '{explain}' }},
            {{ title: 'لماذا يطلبها؟', text: 'قد يطلبها التطبيق لميزة معينة، لكن بعض الصلاحيات قد تُستخدم لأغراض خبيثة.' }},
            {{ title: 'ماذا تفعل؟', list: ['راجع الإعدادات ← التطبيقات', 'أوقف الصلاحيات غير الضرورية', 'إذا لم تكن مرتاحاً — احذف التطبيق'] }}
        ]
    }},'''
    
    trackers_sheets_js = ""
    for t in trackers:
        explain = TRACKER_EXPLAINS.get(t, "مكتبة تتبع.").replace("'", "\\'")
        key = "tracker_" + t.replace(" ", "_").lower()
        title_escaped = t.replace("'", "\\'")
        trackers_sheets_js += f'''
    "{key}": {{
        icon: '📊', color: '#d97706',
        title: '{title_escaped}',
        subtitle: 'مكتبة تتبع',
        risk: 'info',
        riskText: 'مكتبة تتبع',
        sections: [
            {{ title: 'ما هي؟', text: '{explain}' }},
            {{ title: 'ماذا تجمع؟', list: ['معرّف الإعلان', 'نوع الجهاز والنظام', 'الأحداث داخل التطبيق'] }}
        ]
    }},'''
    
    libs_sheets_js = ""
    all_libs = []
    if content and content.get("libraries"):
        for l in content["libraries"].get("known", []):
            all_libs.append(l["name"])
        for l in content["libraries"].get("unknown", []):
            all_libs.append(l)
    else:
        all_libs = libs
    
    for lib in all_libs:
        explain = LIB_EXPLAINS.get(lib, KNOWN_LIBRARIES.get(lib, "مكتبة أصلية (Native) — كود C/C++.")).replace("'", "\\'")
        key = "lib_" + lib.replace(".", "_").replace("-", "_")
        lib_escaped = lib.replace("'", "\\'")
        libs_sheets_js += f'''
    "{key}": {{
        icon: '📚', color: '#2563eb',
        title: '{lib_escaped}',
        subtitle: 'مكتبة أصلية',
        risk: 'info',
        riskText: 'مكتبة أصلية',
        sections: [{{ title: 'ما هي؟', text: '{explain}' }}]
    }},'''
    
    # ===== HTML =====
    html = f"""<!DOCTYPE html>
<html lang="ar" dir="rtl">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>تقرير فحص - {file_name}</title>
<link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css">
<link href="https://fonts.googleapis.com/css2?family=Readex+Pro:wght@300;400;600;700;900&family=JetBrains+Mono:wght@500&display=swap" rel="stylesheet">
<style>
:root {{ --primary:#059669; --primary-light:#ecfdf5; --bg:#f1f5f9; --surface:#ffffff; --text:#0f172a; --text-sub:#64748b; --border:#e2e8f0; --danger:#dc2626; --danger-bg:#fef2f2; --warn:#d97706; --warn-bg:#fffbeb; --info:#2563eb; --info-bg:#eff6ff; --safe:#059669; --safe-bg:#ecfdf5; --radius:18px; }}
* {{ box-sizing:border-box; margin:0; padding:0; font-family:'Readex Pro', sans-serif; -webkit-tap-highlight-color:transparent; }}
body {{ background:var(--bg); color:var(--text); padding:14px; max-width:480px; margin:0 auto; padding-bottom:40px; line-height:1.6; }}
.top-bar {{ display:flex; justify-content:space-between; align-items:center; margin-bottom:16px; }}
.top-bar .title {{ font-size:1.05rem; font-weight:700; display:flex; align-items:center; gap:8px; }}
.top-bar .title i {{ color:var(--primary); }}

.verdict-card {{ border-radius:var(--radius); padding:24px 20px; margin-bottom:14px; color:#fff; position:relative; overflow:hidden; box-shadow:0 12px 28px -8px rgba(220,38,38,0.4); background:linear-gradient(135deg,#7f1d1d 0%,#dc2626 100%); }}
.verdict-card.safe {{ background:linear-gradient(135deg,#064e3b 0%,#059669 100%); box-shadow:0 12px 28px -8px rgba(5,150,105,0.4); }}
.verdict-card.caution {{ background:linear-gradient(135deg,#78350f 0%,#d97706 100%); box-shadow:0 12px 28px -8px rgba(217,119,6,0.4); }}
.verdict-card::after {{ content:''; position:absolute; left:-40px; top:-40px; width:160px; height:160px; background:rgba(255,255,255,0.08); border-radius:50%; }}
.verdict-icon-wrap {{ text-align:center; margin-bottom:10px; }}
.verdict-icon-wrap i {{ font-size:56px; color:#fff; filter:drop-shadow(0 4px 8px rgba(0,0,0,0.25)); }}
.verdict-title {{ font-size:1.6rem; font-weight:900; text-align:center; margin-bottom:6px; }}
.verdict-subtitle {{ text-align:center; opacity:0.9; font-size:0.85rem; margin-bottom:18px; }}
.score-display {{ display:flex; align-items:center; justify-content:center; gap:8px; background:rgba(0,0,0,0.2); border-radius:16px; padding:14px; margin-bottom:12px; }}
.score-num {{ font-size:2.6rem; font-weight:900; line-height:1; }}
.score-max {{ font-size:1rem; opacity:0.7; align-self:flex-end; padding-bottom:6px; }}
.score-bar {{ flex:1; height:8px; background:rgba(255,255,255,0.2); border-radius:4px; overflow:hidden; margin:0 8px; }}
.score-fill {{ height:100%; background:#fff; border-radius:4px; }}
.score-info-btn {{ width:28px; height:28px; border-radius:50%; background:rgba(255,255,255,0.25); border:1.5px solid rgba(255,255,255,0.4); color:#fff; font-size:0.85rem; font-weight:800; cursor:pointer; display:flex; align-items:center; justify-content:center; flex-shrink:0; }}
.verdict-advice {{ background:rgba(255,255,255,0.15); backdrop-filter:blur(6px); border-radius:12px; padding:12px 14px; font-size:0.85rem; line-height:1.6; }}

.trust-card {{ border-right:4px solid var(--primary); border-radius:14px; padding:14px 16px; margin-bottom:12px; }}
.trust-head {{ display:flex; align-items:center; gap:12px; }}

.section-title {{ font-size:0.95rem; font-weight:700; margin:18px 0 10px; display:flex; align-items:center; gap:8px; padding-right:10px; border-right:4px solid var(--primary); }}
.section-title i {{ color:var(--primary); }}
.section-title .count {{ background:var(--primary-light); color:var(--primary); font-size:0.7rem; padding:2px 8px; border-radius:10px; margin-right:auto; }}

.info-card {{ background:var(--surface); border-radius:var(--radius); border:1px solid var(--border); overflow:hidden; margin-bottom:12px; }}
.info-card-head {{ padding:14px 16px; display:flex; justify-content:space-between; align-items:center; cursor:pointer; font-weight:700; font-size:0.9rem; }}
.info-card-head i.chev {{ transition:transform 0.3s; color:var(--text-sub); font-size:0.8rem; }}
.info-card.open .info-card-head i.chev {{ transform:rotate(180deg); }}
.info-card-body {{ display:none; padding:0 16px 16px; border-top:1px dashed var(--border); padding-top:12px; }}
.info-card.open .info-card-body {{ display:block; }}

.data-row {{ display:flex; justify-content:space-between; align-items:center; padding:9px 0; border-bottom:1px dotted var(--border); gap:8px; }}
.data-row:last-child {{ border-bottom:none; }}
.data-row .lbl {{ font-size:0.8rem; color:var(--text-sub); display:flex; align-items:center; gap:6px; flex:1; }}
.data-row .val {{ font-size:0.82rem; font-weight:700; text-align:left; word-break:break-all; }}

.info-btn {{ background:var(--primary-light); color:var(--primary); border:none; width:22px; height:22px; border-radius:50%; font-size:0.7rem; font-weight:700; cursor:pointer; display:inline-flex; align-items:center; justify-content:center; flex-shrink:0; }}

.alert-card {{ background:var(--surface); border-radius:14px; padding:14px 16px; margin-bottom:10px; border-right:4px solid var(--warn); cursor:pointer; transition:transform 0.15s; }}
.alert-card:active {{ transform:scale(0.99); }}
.alert-card.danger {{ border-right-color:var(--danger); background:var(--danger-bg); }}
.alert-card.warn {{ border-right-color:var(--warn); background:var(--warn-bg); }}
.alert-card.info {{ border-right-color:var(--info); background:var(--info-bg); }}
.alert-head {{ display:flex; justify-content:space-between; align-items:flex-start; gap:10px; margin-bottom:6px; }}
.alert-title {{ font-size:0.9rem; font-weight:700; display:flex; align-items:center; gap:8px; flex:1; }}
.alert-badge {{ padding:3px 10px; border-radius:20px; font-size:0.68rem; font-weight:700; white-space:nowrap; color:#fff; }}
.alert-badge.danger {{ background:var(--danger); }}
.alert-badge.warn {{ background:var(--warn); }}
.alert-badge.info {{ background:var(--info); }}
.alert-summary {{ font-size:0.78rem; color:var(--text-sub); line-height:1.5; }}

.perm-card {{ background:var(--surface); border-radius:14px; padding:12px 14px; margin-bottom:8px; border:1px solid var(--border); cursor:pointer; display:flex; align-items:center; gap:12px; transition:transform 0.15s; }}
.perm-card:active {{ transform:scale(0.99); }}
.perm-icon-wrap {{ width:42px; height:42px; border-radius:12px; display:flex; align-items:center; justify-content:center; font-size:1.1rem; color:#fff; flex-shrink:0; }}
.perm-info {{ flex:1; min-width:0; }}
.perm-name {{ font-size:0.85rem; font-weight:700; margin-bottom:2px; }}
.perm-tech {{ font-family:'JetBrains Mono', monospace; font-size:0.65rem; color:var(--text-sub); word-break:break-all; }}
.perm-level-badge {{ padding:3px 8px; border-radius:10px; font-size:0.65rem; font-weight:700; color:#fff; flex-shrink:0; }}

/* Content Analysis */
.content-card {{ background:var(--surface); border-radius:14px; padding:14px 16px; margin-bottom:10px; border:1px solid var(--border); }}
.content-head {{ display:flex; align-items:center; gap:10px; font-weight:700; font-size:0.9rem; margin-bottom:12px; }}
.content-head i {{ color:var(--primary); font-size:1rem; }}
.content-badge {{ margin-right:auto; font-size:0.7rem; background:var(--primary-light); color:var(--primary); padding:3px 10px; border-radius:12px; font-weight:700; }}
.content-body {{ font-size:0.82rem; }}
.url-stats {{ display:flex; gap:8px; margin-bottom:10px; }}
.stat-chip {{ background:var(--safe-bg); color:var(--safe); padding:4px 10px; border-radius:10px; font-size:0.75rem; font-weight:700; }}
.stat-chip.warn {{ background:var(--warn-bg); color:var(--warn); }}
.url-item {{ display:flex; align-items:flex-start; gap:8px; padding:8px; background:var(--warn-bg); border-radius:8px; margin-bottom:6px; font-size:0.75rem; }}
.url-item i {{ color:var(--warn); margin-top:2px; }}
.url-text {{ flex:1; word-break:break-all; direction:ltr; text-align:left; font-family:'JetBrains Mono', monospace; font-size:0.7rem; }}
.url-reason {{ font-size:0.7rem; color:var(--warn); white-space:nowrap; }}
.lib-group {{ margin-bottom:10px; }}
.lib-group strong {{ display:block; margin-bottom:6px; font-size:0.82rem; }}
.empty-mini {{ text-align:center; padding:10px; color:var(--primary); background:var(--primary-light); border-radius:8px; font-size:0.8rem; }}

.chips-wrap {{ display:flex; flex-wrap:wrap; gap:6px; }}
.chip {{ display:inline-flex; align-items:center; gap:6px; padding:7px 12px; border-radius:12px; font-size:0.75rem; font-weight:600; cursor:pointer; border:1px solid transparent; }}
.chip-info {{ background:var(--info-bg); color:var(--info); border-color:#bfdbfe; }}
.chip-ok {{ background:var(--safe-bg); color:var(--safe); border-color:#a7f3d0; }}
.chip-warn {{ background:var(--warn-bg); color:var(--warn); border-color:#fde68a; }}
.chip-danger {{ background:var(--danger-bg); color:var(--danger); border-color:#fecaca; }}
.chip i {{ font-size:0.7rem; }}

.xapk-warning {{ background:var(--warn-bg); border:1px solid #fde68a; border-radius:10px; padding:10px 12px; margin-top:10px; display:flex; gap:10px; align-items:flex-start; color:var(--warn); font-size:0.8rem; }}
.xapk-warning i {{ font-size:1.1rem; }}

.empty-state {{ text-align:center; padding:16px; color:var(--primary); background:var(--primary-light); border-radius:10px; font-size:0.85rem; }}
.empty-state i {{ margin-left:6px; }}

.sheet-overlay {{ position:fixed; inset:0; background:rgba(15,23,42,0.5); backdrop-filter:blur(4px); opacity:0; pointer-events:none; transition:opacity 0.3s; z-index:999; }}
.sheet-overlay.active {{ opacity:1; pointer-events:auto; }}
.bottom-sheet {{ position:fixed; bottom:0; left:0; right:0; background:var(--surface); border-radius:24px 24px 0 0; padding:22px 20px 30px; max-width:480px; margin:0 auto; transform:translateY(100%); transition:transform 0.35s cubic-bezier(0.4,0,0.2,1); z-index:1000; box-shadow:0 -10px 30px rgba(0,0,0,0.15); max-height:85vh; overflow-y:auto; }}
.sheet-overlay.active .bottom-sheet {{ transform:translateY(0); }}
.sheet-drag {{ width:40px; height:4px; background:var(--border); border-radius:2px; margin:0 auto 16px; }}
.sheet-header {{ display:flex; align-items:center; gap:12px; margin-bottom:16px; padding-bottom:14px; border-bottom:1px solid var(--border); }}
.sheet-header .icon {{ width:44px; height:44px; border-radius:12px; display:flex; align-items:center; justify-content:center; font-size:1.2rem; color:#fff; flex-shrink:0; }}
.sheet-header .txt {{ flex:1; }}
.sheet-title {{ font-size:1rem; font-weight:800; line-height:1.3; }}
.sheet-subtitle {{ font-size:0.72rem; color:var(--text-sub); font-family:'JetBrains Mono', monospace; margin-top:2px; }}
.sheet-section {{ margin-bottom:14px; }}
.sheet-section-title {{ font-size:0.75rem; font-weight:700; color:var(--primary); text-transform:uppercase; letter-spacing:0.5px; margin-bottom:6px; }}
.sheet-text {{ font-size:0.86rem; line-height:1.7; }}
.sheet-list {{ list-style:none; padding:0; }}
.sheet-list li {{ padding:6px 0 6px 20px; font-size:0.85rem; line-height:1.6; position:relative; }}
.sheet-list li::before {{ content:'◆'; position:absolute; right:0; color:var(--primary); font-size:0.6rem; top:12px; }}
.risk-indicator {{ display:flex; align-items:center; gap:10px; padding:12px 14px; border-radius:12px; margin-top:10px; }}
.risk-indicator.danger {{ background:var(--danger-bg); border:1px solid #fecaca; }}
.risk-indicator.warn {{ background:var(--warn-bg); border:1px solid #fde68a; }}
.risk-indicator.info {{ background:var(--info-bg); border:1px solid #bfdbfe; }}
.risk-indicator.safe {{ background:var(--safe-bg); border:1px solid #a7f3d0; }}
.risk-indicator .icon {{ font-size:1.4rem; }}
.risk-indicator .txt {{ font-size:0.8rem; font-weight:700; }}
.score-calc-row {{ display:flex; justify-content:space-between; align-items:center; padding:10px 12px; border-radius:10px; margin-bottom:6px; font-size:0.82rem; background:#f8fafc; border:1px solid var(--border); }}
.score-calc-row .lbl {{ color:var(--text-sub); }}
.score-calc-row .val {{ font-weight:700; font-family:'JetBrains Mono', monospace; }}
.score-calc-row .val.neg {{ color:var(--danger); }}
.score-calc-row .val.pos {{ color:var(--safe); }}
.recommendation {{ background:linear-gradient(135deg,#f0fdf4,#ecfdf5); border:1px solid #a7f3d0; border-radius:12px; padding:14px; margin-top:12px; }}
.recommendation.danger {{ background:linear-gradient(135deg,#fef2f2,#fee2e2); border-color:#fecaca; }}
.recommendation.warn {{ background:linear-gradient(135deg,#fffbeb,#fef3c7); border-color:#fde68a; }}
.recommendation-title {{ font-size:0.85rem; font-weight:800; margin-bottom:6px; }}
.recommendation-text {{ font-size:0.82rem; line-height:1.6; }}
.toast {{ position:fixed; bottom:30px; left:50%; transform:translateX(-50%) translateY(100px); background:#0f172a; color:#fff; padding:12px 24px; border-radius:30px; font-size:0.85rem; opacity:0; transition:all 0.3s; z-index:2000; font-weight:600; }}
.toast.show {{ transform:translateX(-50%) translateY(0); opacity:1; }}
</style>
</head>
<body>

<div class="top-bar">
  <div class="title"><i class="fa-solid fa-shield-halved"></i><span>تقرير الفحص</span></div>
  <div style="font-size:0.7rem; color:var(--text-sub);">v7.0</div>
</div>

<div class="verdict-card {verdict_class}">
  <div class="verdict-icon-wrap"><i class="fa-solid {verdict['icon']}"></i></div>
  <div class="verdict-title">{verdict['title']}</div>
  <div class="verdict-subtitle">{app_name} — {size_mb} MB</div>
  <div class="score-display">
    <span class="score-num">{score}</span>
    <span class="score-max">%</span>
    <div class="score-bar"><div class="score-fill" style="width:{score}%"></div></div>
    <button class="score-info-btn" onclick="event.stopPropagation(); showSheet('score_calc')">؟</button>
  </div>
  <div class="verdict-advice"><strong>💡 الحكم:</strong> {verdict['advice']}</div>
</div>

{trust_html}
{xapk_html}

<div class="section-title"><i class="fa-solid fa-circle-info"></i><span>معلومات التطبيق</span></div>
<div class="info-card open">
  <div class="info-card-head" onclick="this.parentElement.classList.toggle('open')">
    <span><i class="fa-solid fa-mobile-screen" style="color:var(--primary);"></i> بيانات الحزمة</span>
    <i class="fa-solid fa-chevron-down chev"></i>
  </div>
  <div class="info-card-body">
    <div class="data-row"><span class="lbl">اسم التطبيق</span><span class="val">{app_name}</span></div>
    <div class="data-row">
      <span class="lbl">معرّف الحزمة <button class="info-btn" onclick="event.stopPropagation(); showSheet('info_package')">؟</button></span>
      <span class="val" style="font-family:monospace; font-size:0.72rem;">{package_name}</span>
    </div>
    <div class="data-row"><span class="lbl">الإصدار</span><span class="val">{version_name} ({version_code})</span></div>
    <div class="data-row"><span class="lbl">الحجم</span><span class="val">{size_mb} MB</span></div>
    <div class="data-row">
      <span class="lbl">minSdk <button class="info-btn" onclick="event.stopPropagation(); showSheet('info_minsdk')">؟</button></span>
      <span class="val">SDK {min_sdk_val}</span>
    </div>
    <div class="data-row">
      <span class="lbl">targetSdk <button class="info-btn" onclick="event.stopPropagation(); showSheet('info_targetsdk')">؟</button></span>
      <span class="val">SDK {target_sdk_val}</span>
    </div>
    <div class="data-row"><span class="lbl">ملفات DEX</span><span class="val">{dex_count}</span></div>
    <div class="data-row"><span class="lbl">إجمالي الملفات</span><span class="val">{total_files}</span></div>
    <div class="data-row">
      <span class="lbl">التوقيع <button class="info-btn" onclick="event.stopPropagation(); showSheet('info_signed')">؟</button></span>
      <span class="val" style="color:{signed_color};">{signed_text} ({sig_types_str})</span>
    </div>
  </div>
</div>

<div class="section-title"><i class="fa-solid fa-triangle-exclamation"></i><span>تنبيهات الأمان</span><span class="count">{alert_count}</span></div>
{alerts_html if alerts_html else '<div class="empty-state"><i class="fa-solid fa-check-circle"></i> لا توجد تنبيهات — التطبيق نظيف</div>'}

<div class="section-title"><i class="fa-solid fa-key"></i><span>الصلاحيات</span><span class="count">{len(perms)}</span></div>
{perms_html if perms_html else '<div class="empty-state"><i class="fa-solid fa-check-circle"></i> لا توجد صلاحيات</div>'}

{content_html}

<div class="section-title"><i class="fa-solid fa-chart-line"></i><span>مكتبات التتبع</span><span class="count">{len(trackers)}</span></div>
{trackers_html}

<div class="section-title"><i class="fa-solid fa-file-signature"></i><span>ملفات التوقيع</span></div>
<div class="chips-wrap">{sig_html}</div>

<div class="section-title"><i class="fa-solid fa-fingerprint"></i><span>البصمات الرقمية</span></div>
<div class="info-card open">
  <div class="info-card-head" onclick="this.parentElement.classList.toggle('open')">
    <span><i class="fa-solid fa-hashtag" style="color:var(--primary);"></i> بصمات الملف</span>
    <i class="fa-solid fa-chevron-down chev"></i>
  </div>
  <div class="info-card-body">
    <div class="data-row" style="flex-direction:column; align-items:stretch;">
      <span class="lbl" style="margin-bottom:6px;">MD5 <button class="info-btn" onclick="event.stopPropagation(); showSheet('info_md5')">؟</button> <i class="fa-regular fa-copy" style="margin-right:auto; cursor:pointer; color:var(--text-sub);" onclick="copyText('{md5}')"></i></span>
      <span style="font-family:'JetBrains Mono', monospace; font-size:0.7rem; color:var(--info); direction:ltr; text-align:left; word-break:break-all;">{md5}</span>
    </div>
    <div class="data-row" style="flex-direction:column; align-items:stretch;">
      <span class="lbl" style="margin-bottom:6px;">SHA256 <button class="info-btn" onclick="event.stopPropagation(); showSheet('info_sha256')">؟</button> <i class="fa-regular fa-copy" style="margin-right:auto; cursor:pointer; color:var(--text-sub);" onclick="copyText('{sha256}')"></i></span>
      <span style="font-family:'JetBrains Mono', monospace; font-size:0.7rem; color:var(--info); direction:ltr; text-align:left; word-break:break-all;">{sha256}</span>
    </div>
  </div>
</div>

<div class="sheet-overlay" id="overlay" onclick="closeSheet()">
  <div class="bottom-sheet" onclick="event.stopPropagation();">
    <div class="sheet-drag"></div>
    <div id="sheetContent"></div>
  </div>
</div>

<div class="toast" id="toast">تم النسخ!</div>

<script>
const SHEETS = {{
{perms_sheets_js}
{trackers_sheets_js}
{libs_sheets_js}
    "info_package": {{ icon: '📦', color: '#059669', title: 'معرّف الحزمة', subtitle: 'Package Name', sections: [{{ title: 'ما هو؟', text: 'اسم فريد يميّز التطبيق عن باقي التطبيقات في نظام أندرويد.' }}, {{ title: 'فائدته؟', list: ['يمنع تعارض التطبيقات', 'يُستخدم لتحديث التطبيق'] }}] }},
    "info_minsdk": {{ icon: '⬇️', color: '#059669', title: 'minSdk', subtitle: 'أقل إصدار مدعوم', sections: [{{ title: 'ما يعني؟', text: 'أقدم إصدار أندرويد يمكن أن يعمل عليه التطبيق. minSdk قديم يعني احتمال وجود ثغرات أمنية.' }}] }},
    "info_targetsdk": {{ icon: '⬆️', color: '#059669', title: 'targetSdk', subtitle: 'الإصدار المستهدف', sections: [{{ title: 'ما يعني؟', text: 'الإصدار الذي صُمم التطبيق للعمل عليه بشكل مثالي.' }}] }},
    "info_signed": {{ icon: '✅', color: '#059669', title: 'التوقيع الرقمي', subtitle: 'APK Signature', sections: [{{ title: 'ما هو؟', text: 'توقيع رقمي يثبت أن التطبيق لم يُعدّل بعد توقيعه من المطوّر.' }}, {{ title: 'الأنواع:', list: ['v1 — التوقيع التقليدي', 'v2 — توقيع محسّن', 'v3 — الأحدث'] }}] }},
    "info_md5": {{ icon: '#️⃣', color: '#2563eb', title: 'MD5', subtitle: 'بصمة الملف', sections: [{{ title: 'ما هي؟', text: 'سلسلة فريدة تُشتق من محتوى الملف. أي تغيير يغير البصمة.' }}] }},
    "info_sha256": {{ icon: '🔑', color: '#2563eb', title: 'SHA256', subtitle: 'بصمة قوية', sections: [{{ title: 'ما هي؟', text: 'نسخة أقوى من MD5. تُستخدم للتحقق من سلامة الملفات.' }}] }},
    "generic_perm": {{ icon: '🔑', color: '#64748b', title: 'صلاحية نظام', subtitle: 'Android Permission', sections: [{{ title: 'ما هي؟', text: 'صلاحية نظام عادية. قد تكون مطلوبة لعمل التطبيق بشكل صحيح.' }}] }},
    "accessibility": {{ icon: '🚨', color: '#dc2626', title: 'خدمة الوصول (Accessibility)', subtitle: 'BIND_ACCESSIBILITY_SERVICE', risk: 'danger', riskText: 'أخطر صلاحية على الإطلاق', sections: [{{ title: 'ما هذه الخدمة؟', text: 'ميزة في أندرويد لمساعدة ذوي الاحتياجات الخاصة. تسمح بقراءة كل ما على الشاشة والتحكم به.' }}, {{ title: 'لماذا خطيرة؟', list: ['قراءة كل ما يُكتب — بما فيها كلمات السر', 'الضغط على الأزرار نيابة عنك', 'التقاط نصوص من أي تطبيق', 'تشتغل في الخلفية'] }}, {{ title: 'ماذا تفعل؟', list: ['افتح: الإعدادات ← إمكانية الوصول', 'لا تمنحها إلا لتطبيقات تثق بها'] }}], recommendation: {{ type: 'danger', title: 'توصية', text: 'لا تمنح خدمة الوصول إلا إذا كنت تثق بالمطوّر تماماً.' }} }},
    "notif_listener": {{ icon: '🚨', color: '#dc2626', title: 'قراءة الإشعارات', subtitle: 'NotificationListenerService', risk: 'danger', riskText: 'خطر شديد', sections: [{{ title: 'ما هذه الخدمة؟', text: 'تسمح للتطبيق بقراءة كل الإشعارات التي تصلك.' }}, {{ title: 'لماذا خطيرة؟', list: ['قراءة رموز OTP من البنوك', 'معرفة كل رسائلك وإشعاراتك', 'بناء ملف كامل عنك'] }}], recommendation: {{ type: 'danger', title: 'توصية', text: 'لا تمنح هذه الصلاحية إلا لتطبيقات تثق بها 100%.' }} }},
    "sms_access": {{ icon: '🚨', color: '#dc2626', title: 'التعامل مع الرسائل (SMS)', subtitle: 'SMS / Telephony', risk: 'danger', riskText: 'خطر شديد', sections: [{{ title: 'ما هذا؟', text: 'التطبيق يقرأ أو يرسل رسائل SMS من جهازك.' }}, {{ title: 'لماذا خطير؟', list: ['سرقة رموز التحقق OTP', 'الاشتراك بخدمات مدفوعة', 'إرسال رسائل احتيالية'] }}, {{ title: 'ماذا تفعل؟', list: ['إذا لم يكن تطبيق رسائل — احذفه', 'لا تمنحه هذه الصلاحية أبداً'] }}], recommendation: {{ type: 'danger', title: 'توصية', text: 'لا تستخدم تطبيقات تقرأ SMS إلا إذا كنت تثق بها تماماً.' }} }},
    "install_pkg": {{ icon: '🔴', color: '#dc2626', title: 'تثبيت تطبيقات', subtitle: 'REQUEST_INSTALL_PACKAGES', risk: 'danger', riskText: 'صلاحية حرجة', sections: [{{ title: 'ما هذه الصلاحية؟', text: 'تسمح للتطبيق بتنزيل وتثبيت تطبيقات أخرى (APK) على جهازك.' }}, {{ title: 'لماذا خطيرة؟', list: ['تنزيل فيروسات وتثبيتها تلقائياً', 'تثبيت تطبيقات تجسس', 'مسؤولة عن معظم حالات الاختراق'] }}, {{ title: 'ماذا تفعل؟', list: ['الإعدادات ← التطبيقات ← أوقف "تثبيت تطبيقات غير معروفة"'] }}], recommendation: {{ type: 'danger', title: 'توصية', text: 'أوقف هذه الصلاحية فوراً.' }} }},
    "shell_cmds": {{ icon: '🚨', color: '#dc2626', title: 'تنفيذ أوامر نظام (Shell)', subtitle: 'Runtime.exec', risk: 'danger', riskText: 'خطر', sections: [{{ title: 'ما هذا؟', text: 'التطبيق ينفذ أوامر نظام (Unix/Linux) عبر Runtime.exec.' }}, {{ title: 'لماذا خطير؟', list: ['قد يتحكم بالجهاز', 'قد يحذف ملفات', 'قد يثبت تطبيقات'] }}, {{ title: 'ماذا تفعل؟', list: ['لا تثق بتطبيق ينفذ أوامر نظام إلا إذا كان مطوّر معروف'] }}], recommendation: {{ type: 'danger', title: 'توصية', text: 'احذر من التطبيقات التي تنفذ أوامر نظام.' }} }},
    "dynamic_code": {{ icon: '⚠️', color: '#d97706', title: 'تحميل كود ديناميكي', subtitle: 'DexClassLoader / loadClass', risk: 'warn', riskText: 'تحذير', sections: [{{ title: 'ما هو؟', text: 'بدل احتواء التطبيق على كل الكود، يحمّل أجزاءً من الإنترنت وقت التشغيل.' }}, {{ title: 'لماذا؟', list: ['تحديث الميزات بدون تحديث التطبيق', 'تقليل حجم التطبيق', 'أحياناً: إخفاء الكود'] }}, {{ title: 'هل خطر؟', text: 'ليس خطراً بحد ذاته، لكن قد يشغّل كوداً لم يُفحص.' }}], recommendation: {{ type: 'warn', title: 'توصية', text: 'راقب استهلاك البيانات لأول أسبوع.' }} }},
    "clipboard": {{ icon: '⚠️', color: '#d97706', title: 'قراءة الحافظة', subtitle: 'Clipboard Access', risk: 'warn', riskText: 'تحذير', sections: [{{ title: 'ما هذا؟', text: 'التطبيق يقرأ الحافظة (كل ما تنسخه).' }}, {{ title: 'لماذا خطر؟', text: 'قد يقرأ كلمات السر أو أرقام البطاقات التي تنسخها.' }}], recommendation: {{ type: 'warn', title: 'توصية', text: 'لا تنسخ معلومات حساسة أثناء استخدام التطبيق.' }} }},
    "old_sdk": {{ icon: '⚠️', color: '#d97706', title: 'minSdk قديم', subtitle: 'Android 4.2 أو أقدم', risk: 'warn', riskText: 'تحذير', sections: [{{ title: 'ما يعني؟', text: 'التطبيق مصمم ليعمل على أندرويد قديم. قد يستخدم مكتبات قديمة بدون تصحيحات أمنية.' }}, {{ title: 'ماذا تفعل؟', list: ['ابحث عن نسخة أحدث', 'إذا ما توفرت — استخدمه بحذر'] }}], recommendation: {{ type: 'warn', title: 'توصية', text: 'ابحث عن نسخة محدّثة.' }} }},
    "high_perms": {{ icon: '🟡', color: '#d97706', title: 'صلاحيات عالية الخطورة', subtitle: 'High Risk Permissions', risk: 'warn', riskText: 'تحذير', sections: [{{ title: 'ما الصلاحيات؟', list: ['قراءة الملفات', 'كتابة الملفات', 'معلومات الجهاز'] }}, {{ title: 'لماذا خطيرة؟', text: 'طبيعية لتطبيقات كثيرة، لكنها قد تُستخدم لسرقة الصور أو الملفات.' }}], recommendation: {{ type: 'warn', title: 'توصية', text: 'راجع ملفاتك بانتظام.' }} }},
    "webview": {{ icon: '⚠️', color: '#d97706', title: 'يستخدم WebView', subtitle: 'WebView / loadUrl', risk: 'warn', riskText: 'تحذير', sections: [{{ title: 'ما هو؟', text: 'التطبيق ينشئ متصفحاً داخلياً لتحميل صفحات الويب.' }}, {{ title: 'لماذا؟', text: 'لمشاهدة محتوى ويب داخل التطبيق (فيديو، مقالات).' }}, {{ title: 'لماذا تحذير؟', text: 'إذا استخدم HTTP غير مشفر — قد تُسرق البيانات.' }}], recommendation: {{ type: 'warn', title: 'توصية', text: 'تأكد من استخدام التطبيق لروابط HTTPS.' }} }},
    "root_check": {{ icon: 'ℹ️', color: '#2563eb', title: 'فحص Root والمحاكي', subtitle: 'isRooted / isEmulator', risk: 'info', riskText: 'معلوماتي', sections: [{{ title: 'ما هذا؟', text: 'التطبيق يتحقق مما إذا كان جهازك مروّتاً أو يعمل على محاكي.' }}, {{ title: 'هل خطر؟', text: 'لا — سلوك شائع جداً.' }}], recommendation: {{ type: 'info', title: 'معلومة', text: 'سلوك طبيعي.' }} }},
    "trackers_info": {{ icon: 'ℹ️', color: '#2563eb', title: 'مكتبات التتبع', subtitle: 'Trackers', risk: 'info', riskText: 'معلوماتي', sections: [{{ title: 'ما هي؟', text: 'مكتبات تجمع بيانات استخدامك وترسلها للشركات.' }}, {{ title: 'هل خطر؟', text: 'ليست خطراً مباشراً، لكنها تتبع استخدامك.' }}], recommendation: {{ type: 'info', title: 'معلومة', text: 'عطّل "معرّف الإعلان" من الإعدادات.' }} }},
    "suspicious_urls": {{ icon: '🌐', color: '#d97706', title: 'روابط مشبوهة', subtitle: 'Suspicious URLs', risk: 'warn', riskText: 'تحذير', sections: [{{ title: 'ما هذا؟', text: 'التطبيق يحتوي على روابط قد تشير لنشاط خبيث.' }}, {{ title: 'لماذا؟', list: ['نطاقات مشبوهة (.ru, .tk, .xyz)', 'كلمات مفتاحية (hack, crack, free)', 'خدمات رفع ملفات (pastebin, mega)'] }}, {{ title: 'ماذا تفعل؟', list: ['لا تفتح هذه الروابط', 'إذا التطبيق يعتمد عليها — احذفه'] }}], recommendation: {{ type: 'warn', title: 'توصية', text: 'احذر من التطبيقات التي تتصل بمواقع مشبوهة.' }} }},
    "unknown_libs": {{ icon: 'ℹ️', color: '#2563eb', title: 'مكتبات أصلية مجهولة', subtitle: 'Unknown Native Libraries', risk: 'info', riskText: 'معلوماتي', sections: [{{ title: 'ما هذا؟', text: 'التطبيق يحتوي على مكتبات أصلية (C/C++) غير موجودة في قاعدة البيانات.' }}, {{ title: 'هل خطر؟', text: 'ليس خطراً بحد ذاته — قد تكون مكتبة خاصة بالمطوّر.' }}, {{ title: 'لماذا نذكرها؟', text: 'لأن المكتبات المجهولة قد تحتوي على كود غير قابل للفحص.' }}], recommendation: {{ type: 'info', title: 'معلومة', text: 'راقب سلوك التطبيق.' }} }},
    "xapk_extra": {{ icon: '⚠️', color: '#d97706', title: 'صلاحيات إضافية في XAPK', subtitle: 'Extra XAPK Permissions', risk: 'warn', riskText: 'تحذير', sections: [{{ title: 'ما هذا؟', text: 'الـ XAPK يحتوي على ملفات APK إضافية (config) تطلب صلاحيات لا يطلبها الملف الرئيسي.' }}, {{ title: 'لماذا خطير؟', text: 'قد تكون صلاحيات مخفية عن المستخدم العادي.' }}, {{ title: 'ماذا تفعل؟', list: ['راجع قائمة الصلاحيات كاملة', 'إذا كانت مريبة — لا تثبّت'] }}], recommendation: {{ type: 'warn', title: 'توصية', text: 'افحص الصلاحيات الإضافية بعناية.' }} }},
    "score_calc": {{
        icon: '📊', color: '#059669',
        title: 'كيف تم حساب الدرجة؟',
        subtitle: 'Score Breakdown',
        sections: [{{ title: 'طريقة الحساب', text: 'نبدأ من 100، ثم نضيف/نخصم حسب المعايير. التطبيقات الموثوقة تحصل على نقاط إضافية.' }}],
        scoreRows: [
            {{ lbl: '⚪ البداية', val: '100', type: 'pos' }},
{score_rows_js}
        ],
        total: {{ lbl: '📌 النتيجة النهائية', val: '{score}' }},
        recommendation: {{ type: 'info', title: 'ملاحظة', text: 'الدرجة مؤشر وليست حكماً نهائياً. راجع التنبيهات لفهم المخاطر.' }}
    }}
}};

function showSheet(key) {{
  const data = SHEETS[key];
  if (!data) return;
  
  const riskColors = {{
    danger: {{ icon: '🚨', text: '#dc2626' }},
    warn: {{ icon: '⚠️', text: '#d97706' }},
    info: {{ icon: 'ℹ️', text: '#2563eb' }},
    safe: {{ icon: '✅', text: '#059669' }}
  }};
  
  let riskHtml = '';
  if (data.risk) {{
    const r = riskColors[data.risk];
    riskHtml = '<div class="risk-indicator ' + data.risk + '"><span class="icon">' + r.icon + '</span><span class="txt" style="color:' + r.text + ';">' + (data.riskText || '') + '</span></div>';
  }}
  
  let sectionsHtml = '';
  if (data.sections) {{
    for (const s of data.sections) {{
      sectionsHtml += '<div class="sheet-section"><div class="sheet-section-title">' + s.title + '</div>';
      if (s.text) sectionsHtml += '<div class="sheet-text">' + s.text + '</div>';
      if (s.list) {{
        sectionsHtml += '<ul class="sheet-list">';
        for (const item of s.list) sectionsHtml += '<li>' + item + '</li>';
        sectionsHtml += '</ul>';
      }}
      sectionsHtml += '</div>';
    }}
  }}
  
  let scoreHtml = '';
  if (data.scoreRows) {{
    scoreHtml = '<div class="sheet-section"><div class="sheet-section-title">تفصيل الحساب</div>';
    for (const row of data.scoreRows) {{
      scoreHtml += '<div class="score-calc-row"><span class="lbl">' + row.lbl + '</span><span class="val ' + row.type + '">' + row.val + '</span></div>';
    }}
    scoreHtml += '</div>';
    if (data.total) {{
      scoreHtml += '<div class="score-calc-row" style="background:linear-gradient(135deg,#f0fdf4,#ecfdf5);border-color:#a7f3d0;margin-top:10px;"><span class="lbl" style="color:#059669;font-weight:700;">' + data.total.lbl + '</span><span class="val" style="color:#059669;font-size:1rem;">' + data.total.val + '</span></div>';
    }}
  }}
  
  let recHtml = '';
  if (data.recommendation) {{
    const rec = data.recommendation;
    recHtml = '<div class="recommendation ' + (rec.type || '') + '"><div class="recommendation-title"><span>💡</span> ' + rec.title + '</div><div class="recommendation-text">' + rec.text + '</div></div>';
  }}
  
  const html = '<div class="sheet-header">' +
    '<div class="icon" style="background:' + (data.color || '#059669') + ';">' + (data.icon || 'ℹ️') + '</div>' +
    '<div class="txt">' +
      '<div class="sheet-title">' + data.title + '</div>' +
      (data.subtitle ? '<div class="sheet-subtitle">' + data.subtitle + '</div>' : '') +
    '</div>' +
  '</div>' + riskHtml + sectionsHtml + scoreHtml + recHtml;
  
  document.getElementById('sheetContent').innerHTML = html;
  document.getElementById('overlay').classList.add('active');
}}

function closeSheet() {{
  document.getElementById('overlay').classList.remove('active');
}}

function copyText(text) {{
  if (navigator.clipboard) {{
    navigator.clipboard.writeText(text).then(() => showToast('تم النسخ بنجاح!'));
  }} else {{
    const ta = document.createElement('textarea');
    ta.value = text;
    document.body.appendChild(ta);
    ta.select();
    document.execCommand('copy');
    document.body.removeChild(ta);
    showToast('تم النسخ بنجاح!');
  }}
}}

function showToast(msg) {{
  const t = document.getElementById('toast');
  t.innerText = msg;
  t.classList.add('show');
  setTimeout(() => t.classList.remove('show'), 2000);
}}
</script>
</body>
</html>"""
    
    with open(filename, "w", encoding="utf-8") as f:
        f.write(html)
    return filename


# ============ Main Analyze Function ============
def analyze_apk(apk_path):
    if not os.path.exists(apk_path):
        print(f"{C.R}[X] File not found: {apk_path}{C.END}")
        return None
    
    file_size = os.path.getsize(apk_path)
    file_name = os.path.basename(apk_path)
    
    title(f"[*] Scanning: {file_name}", C.G)
    
    print(f"\n{C.BOLD}[+] File Info:{C.END}")
    print(f"  Path: {apk_path}")
    print(f"  Size: {file_size / (1024*1024):.2f} MB")
    
    # ===== XAPK check =====
    xapk_info = None
    real_apk_path = apk_path
    
    if file_name.lower().endswith(".xapk") or is_xapk(apk_path):
        print(f"\n{C.Y}[~] XAPK detected — analyzing full bundle...{C.END}")
        xapk_info = analyze_xapk_full(apk_path)
        
        if xapk_info.get("error"):
            print(f"  {C.R}[X] XAPK Error: {xapk_info['error']}{C.END}")
        else:
            print(f"  APKs: {len(xapk_info['apks'])}, OBB: {len(xapk_info['obb_files'])}")
            if xapk_info.get("base_apk"):
                print(f"  Base: {xapk_info['base_apk']['name']}")
                print(f"  Configs: {len(xapk_info.get('config_apks', []))}")
            if xapk_info.get("extra_permissions"):
                print(f"  {C.Y}[!] {len(xapk_info['extra_permissions'])} extra permissions in config APKs{C.END}")
            real_apk_path = xapk_info["base_apk"]["path"]
    
    # ===== Hashes =====
    print(f"\n{C.Y}[~] Computing hashes...{C.END}")
    sha256 = sha256_file(apk_path)
    md5 = md5_file(apk_path)
    print(f"  SHA256: {sha256}")
    print(f"  MD5:    {md5}")
    
    # ===== Parse APK =====
    print(f"\n{C.Y}[~] Parsing AndroidManifest...{C.END}")
    apk_data = analyze_with_pyaxml(real_apk_path)
    
    # ===== Extract Strings =====
    print(f"{C.Y}[~] Extracting DEX strings...{C.END}")
    dex_strings = extract_dex_strings(real_apk_path)
    print(f"  Found {len(dex_strings)} strings")
    
    # ===== Trackers =====
    print(f"{C.Y}[~] Detecting trackers...{C.END}")
    trackers = detect_trackers_from_strings(dex_strings)
    
    # ===== Suspicious Patterns =====
    print(f"{C.Y}[~] Analyzing suspicious patterns...{C.END}")
    suspicious = detect_suspicious_code(dex_strings)
    
    # ===== Native Libraries =====
    print(f"{C.Y}[~] Listing native libraries...{C.END}")
    libs = extract_libraries(real_apk_path)
    
    # ===== Deep Content Analysis =====
    print(f"{C.Y}[~] Deep content analysis (URLs, Libs, Shell)...{C.END}")
    content_analysis = deep_content_analysis(real_apk_path, dex_strings, libs)
    print(f"  URLs: {content_analysis['urls']['total']} ({content_analysis['urls']['suspicious_count']} مشبوه)")
    print(f"  Libraries: {content_analysis['libraries']['known_count']} معروفة, {content_analysis['libraries']['unknown_count']} مجهولة")
    if content_analysis['shell_analysis']['found']:
        print(f"  Shell: {content_analysis['shell_analysis']['count']} أمر")
    
    # ===== Signature =====
    print(f"{C.Y}[~] Reading signature files...{C.END}")
    sig_info = get_signature_info(real_apk_path)
    
    # ===== DEX count =====
    print(f"{C.Y}[~] Counting DEX files...{C.END}")
    dex_count = count_dex_files(real_apk_path)
    total_files = count_total_files(real_apk_path)
    print(f"  DEX: {dex_count}, Total: {total_files}")
    
    # ===== Package ID =====
    app_info = None
    if apk_data and "error" not in apk_data:
        package_name = apk_data.get("package", "")
        print(f"\n{C.Y}[~] Identifying package...{C.END}")
        app_info = identify_package(package_name)
        if app_info:
            print(f"  {C.G}[OK] Known: {app_info['name']} ({app_info['category']}, trust={app_info['trust']}){C.END}")
        else:
            print(f"  {C.Y}[?] Unknown package — strict mode{C.END}")
    
    # ===== Display =====
    critical, high = [], []
    
    if apk_data and "error" not in apk_data:
        print(f"\n{C.BOLD}[+] App Info:{C.END}")
        print(f"  Name:      {apk_data.get('app_name', 'N/A')}")
        print(f"  Package:   {apk_data.get('package', 'N/A')}")
        print(f"  Version:   {apk_data.get('version_name', 'N/A')} ({apk_data.get('version_code', 'N/A')})")
        print(f"  minSdk:    {apk_data.get('min_sdk', 'N/A')}")
        print(f"  targetSdk: {apk_data.get('target_sdk', 'N/A')}")
        
        print(f"\n{C.BOLD}[+] Digital Signature:{C.END}")
        if apk_data.get("signed"):
            versions = []
            if apk_data.get("signed_v1"): versions.append("v1")
            if apk_data.get("signed_v2"): versions.append("v2")
            if apk_data.get("signed_v3"): versions.append("v3")
            print(f"  {C.G}[OK] Signed: {', '.join(versions)}{C.END}")
        else:
            print(f"  {C.R}[X] NOT SIGNED!{C.END}")
        
        permissions = apk_data.get("permissions", [])
        print(f"\n{C.BOLD}[+] Permissions ({len(permissions)}):{C.END}")
        
        for perm in permissions:
            if perm in PERMISSIONS_DB:
                level = PERMISSIONS_DB[perm]["level"]
                if level == "CRITICAL": critical.append(perm)
                elif level == "HIGH": high.append(perm)
        
        if critical:
            print(f"\n  {C.R}{C.BOLD}[!!] CRITICAL ({len(critical)}):{C.END}")
            for p in critical:
                short = p.replace("android.permission.", "")
                print(f"    {C.R}*{C.END} {short}")
        
        if high:
            print(f"\n  {C.Y}{C.BOLD}[!] HIGH ({len(high)}):{C.END}")
            for p in high:
                short = p.replace("android.permission.", "")
                print(f"    {C.Y}*{C.END} {short}")
        
        print(f"\n{C.BOLD}[+] Trackers ({len(trackers)}):{C.END}")
        for t in trackers:
            print(f"  {C.Y}*{C.END} {t}")
        if not trackers:
            print(f"  {C.G}[OK] None{C.END}")
        
        print(f"\n{C.BOLD}[+] Suspicious Patterns ({len(suspicious)}):{C.END}")
        for name in suspicious:
            cat = suspicious[name].get("category", "info")
            icon = "🚨" if cat == "danger" else "⚠️" if cat == "warn" else "ℹ️"
            print(f"  {icon} {name}")
        if not suspicious:
            print(f"  {C.G}[OK] None{C.END}")
        
        print(f"\n{C.BOLD}[+] Content Analysis:{C.END}")
        urls_info = content_analysis["urls"]
        print(f"  URLs: {urls_info['total']} total, {urls_info['suspicious_count']} suspicious")
        if urls_info["suspicious"]:
            for u in urls_info["suspicious"][:5]:
                print(f"    {C.R}⚠{C.END} {u['url'][:60]} — {u['reason']}")
        
        libs_info = content_analysis["libraries"]
        print(f"  Known libs: {libs_info['known_count']}, Unknown: {libs_info['unknown_count']}")
        
        if content_analysis["shell_analysis"]["found"]:
            print(f"  Shell commands: {', '.join(content_analysis['shell_analysis']['found'])}")
    else:
        print(f"{C.R}[X] Failed to parse APK{C.END}")
    
    # ===== Final Assessment =====
    title("[*] Final Assessment", C.G)
    
    score, breakdown = calculate_score(apk_data, trackers, suspicious, libs, app_info, content_analysis, xapk_info)
    verdict = get_verdict(score, app_info)
    
    print(f"\n{C.BOLD}[+] Score: {score}/100{C.END}")
    print(f"{C.BOLD}[+] Verdict: {verdict['title']}{C.END}")
    
    if score >= 80:
        print(f"{C.G}{C.BOLD}[OK] SAFE{C.END}")
    elif score >= 60:
        print(f"{C.Y}{C.BOLD}[~] CAUTION{C.END}")
    elif score >= 40:
        print(f"{C.Y}{C.BOLD}[!] SUSPICIOUS{C.END}")
    else:
        print(f"{C.R}{C.BOLD}[!!] HIGH RISK{C.END}")
    
    print(f"\n{C.BOLD}[+] Score Breakdown:{C.END}")
    for row in breakdown:
        print(f"  {row['lbl']}: {row['val']}")
    
    # ===== Report =====
    report = {
        "file": file_name,
        "path": apk_path,
        "size_mb": round(file_size / (1024*1024), 2),
        "sha256": sha256,
        "md5": md5,
        "analyzed_at": datetime.now().isoformat(),
        "score": score,
        "score_breakdown": breakdown,
        "verdict": verdict,
        "known_app": app_info,
        "xapk_info": xapk_info,
        "content_analysis": content_analysis,
        "apk_data": apk_data,
        "all_permissions": apk_data.get("permissions", []) if apk_data and "error" not in apk_data else [],
        "critical_permissions": critical,
        "high_permissions": high,
        "trackers": trackers,
        "suspicious_code": suspicious,
        "native_libs": libs,
        "signature_info": sig_info,
        "dex_count": dex_count,
        "total_files": total_files,
        "dex_strings_count": len(dex_strings),
    }
    
    base_name = file_name.replace('.apk', '').replace('.xapk', '')
    timestamp = datetime.now().strftime('%Y%m%d_%H%M')
    
    json_file = f"apk_report_{base_name}_{timestamp}.json"
    with open(json_file, "w", encoding="utf-8") as f:
        json.dump(report, f, ensure_ascii=False, indent=2, default=str)
    
    html_file = f"apk_report_{base_name}_{timestamp}.html"
    generate_html_report(report, html_file)
    
    print(f"\n{C.G}[OK] JSON report: {json_file}{C.END}")
    print(f"{C.G}[OK] HTML report: {html_file}{C.END}")
    print(f"{C.C}[i] Open HTML in browser for full Arabic report{C.END}")
    
    # Cleanup
    if xapk_info:
        cleanup_xapk_temp(xapk_info)
    
    return report


# ============ Main ============
def main():
    print(f"\n{C.G}{C.BOLD}" + "=" * 68)
    print(f"  APK Scanner v7.0 - Advanced Edition")
    print("=" * 68 + f"{C.END}\n")
    
    print(f"{C.Y}[~] Checking tools...{C.END}")
    
    has_aapt = subprocess.run(["which", "aapt"], capture_output=True).returncode == 0
    has_pyaxml = False
    try:
        import pyaxmlparser
        has_pyaxml = True
    except ImportError:
        pass
    
    print(f"  aapt:         {'[OK]' if has_aapt else '[--]'}")
    print(f"  pyaxmlparser: {'[OK]' if has_pyaxml else '[--]'}")
    
    if not has_pyaxml:
        print(f"\n{C.R}[X] pyaxmlparser is required!{C.END}")
        print(f"    pip install pyaxmlparser")
        return
    
    while True:
        print(f"\n{C.C}[?] APK/XAPK file path:{C.END}")
        print(f"    Example: /sdcard/Download/app.apk")
        apk_path = input(f"{C.C}> {C.END}").strip().strip('"').strip("'")
        
        if not apk_path:
            print(f"{C.R}[X] No path entered{C.END}")
            continue
        
        apk_path = os.path.expanduser(apk_path)
        
        if not os.path.exists(apk_path):
            print(f"{C.R}[X] File not found{C.END}")
            retry = input(f"{C.Y}Try again? (y/n): {C.END}").strip().lower()
            if retry != "y":
                break
            continue
        
        try:
            analyze_apk(apk_path)
        except Exception as e:
            print(f"{C.R}[X] Error: {e}{C.END}")
            import traceback
            traceback.print_exc()
        
        again = input(f"\n{C.C}Scan another file? (y/n): {C.END}").strip().lower()
        if again != "y":
            break
    
    print(f"\n{C.G}Goodbye!{C.END}\n")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print(f"\n{C.Y}Interrupted{C.END}\n")
    except Exception as e:
        print(f"\n{C.R}Error: {e}{C.END}\n")