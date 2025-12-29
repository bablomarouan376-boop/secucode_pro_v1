import os
import re
import requests
import socket
import ssl
import time
from flask import Flask, request, jsonify, render_template
from urllib.parse import urlparse
from validators import url

app = Flask(__name__)

# إعدادات الاتصال الاحترافية لتبدو كمتصفح حقيقي
HEADERS = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36",
    "Accept-Language": "en-US,en;q=0.9,ar;q=0.8",
}

def check_ssl_status(hostname):
    """فحص جودة وصلاحية شهادة SSL عبر السوكت"""
    try:
        context = ssl.create_default_context()
        with socket.create_connection((hostname, 443), timeout=3) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                return True, "شهادة صالحة وموثوقة"
    except Exception:
        return False, "شهادة غير صالحة أو مفقودة"

def perform_deep_analysis(target_url):
    start_time = time.time()
    violated_rules = []
    redirect_path = [target_url]
    points = 0
    
    # --- 1. تتبع المسار وفحص الاتصال (Dynamic Analysis) ---
    try:
        response = requests.get(target_url, headers=HEADERS, timeout=8, allow_redirects=True)
        final_url = response.url
        content = response.text
        
        # تسجيل مسار التحويلات (Redirect History)
        for resp in response.history:
            if resp.url not in redirect_path:
                redirect_path.append(resp.url)
        if final_url not in redirect_path:
            redirect_path.append(final_url)

        # فحص البروتوكول والـ SSL
        if not final_url.startswith('https'):
            points += 45
            violated_rules.append({"name": "اتصال غير مشفر (HTTP)", "risk_description": "الموقع يرسل البيانات بدون تشفير، مما يسهل اختراق الجلسة.", "points_added": 45})
        else:
            is_valid, msg = check_ssl_status(urlparse(final_url).netloc)
            if not is_valid:
                points += 35
                violated_rules.append({"name": "مشكلة في شهادة الأمان", "risk_description": "شهادة الـ SSL منتهية أو غير موثقة من جهة رسمية.", "points_added": 35})

        # فحص عدد التحويلات
        if len(response.history) > 2:
            points += 20
            violated_rules.append({"name": "سلسلة تحويلات مريبة", "risk_description": "الرابط يحاول إخفاء وجهته النهائية عبر القفز بين عدة مواقع.", "points_added": 20})

    except Exception:
        points += 30
        violated_rules.append({"name": "فشل فحص الاستجابة", "risk_description": "الموقع يحظر أدوات الفحص أو الخادم غير موجود.", "points_added": 30})
        final_url = target_url
        content = ""

    # --- 2. فحص الهيكل والمحتوى (Static Analysis) ---
    parsed = urlparse(final_url)
    
    # قواعد Regex متقدمة
    static_rules = [
        (r'@', 50, "تزوير العناوين (@)", "يستخدم لإخفاء النطاق الحقيقي خلف اسم مستخدم وهمي."),
        (r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', 60, "عنوان IP مباشر", "المواقع الموثوقة تستخدم أسماء وليس أرقام IP مباشرة."),
        (r'(login|verify|update|secure|bank|paypal|account|gift)', 25, "كلمات هندسة اجتماعية", "الرابط يحتوي على كلمات تهدف لخداعك نفسياً."),
        (r'\.zip$|\.exe$|\.rar$|\.apk$|\.bat$', 85, "تحميل برمجية تنفيذية", "الرابط سيقوم بتحميل ملف قد يضر بجهازك فوراً.")
    ]

    for pattern, pts, name, desc in static_rules:
        if re.search(pattern, final_url, re.I):
            points += pts
            violated_rules.append({"name": name, "risk_description": desc, "points_added": pts})

    if content and re.search(r'<input[^>]*type="password"', content, re.I):
        points += 50
        violated_rules.append({"name": "طلب بيانات حساسة", "risk_description": "الصفحة تحتوي على حقل إدخال كلمة مرور بشكل غير آمن.", "points_added": 50})

    # --- 3. التصنيف النهائي ---
    risk = "Critical" if points >= 80 else "High" if points >= 45 else "Medium" if points >= 20 else "Low"

    return {
        "risk_score": risk,
        "suspicious_points": points,
        "violated_rules": violated_rules,
        "link_input": target_url,
        "link_final": final_url,
        "redirect_path": redirect_path,
        "detected_warnings": len(violated_rules),
        "execution_time": round(time.time() - start_time, 2)
    }

@app.route('/')
def home():
    return render_template('index.html')

@app.route('/analyze', methods=['POST'])
def analyze():
    data = request.json
    raw_url = data.get('link', '').strip()
    if not raw_url:
        return jsonify({"message": "يرجى إدخال رابط"}), 400
    if not raw_url.startswith(('http://', 'https://')):
        raw_url = 'https://' + raw_url
    
    if not url(raw_url):
        return jsonify({"message": "تنسيق الرابط غير صحيح"}), 400
        
    return jsonify(perform_deep_analysis(raw_url))

if __name__ == '__main__':
    app.run(debug=True)
