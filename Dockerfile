FROM python:3.11-slim

WORKDIR /app

# تثبيت أدوات النظام (aapt لتحليل APK)
RUN apt-get update && apt-get install -y --no-install-recommends \
    aapt \
    libxml2 \
    libxslt1.1 \
    && rm -rf /var/lib/apt/lists/*

# تثبيت مكتبات Python
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# نسخ الملفات
COPY . .

# منفذ Hugging Face
EXPOSE 7860

# تشغيل السيرفر
CMD ["gunicorn", "-b", "0.0.0.0:7860", "--timeout", "1800", "--workers", "2", "--threads", "4", "--access-logfile", "-", "app:app"]