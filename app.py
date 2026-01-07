import os
import re
import requests
import socket
import ssl
import time
from flask import Flask, request, jsonify, render_template, send_from_directory
from urllib.parse import urlparse
from validators import url as validate_url

app = Flask(__name__, static_folder='static', template_folder='templates')

HEADERS = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36",
}

def check_ssl_status(hostname):
    try:
        context = ssl.create_default_context()
        with socket.create_connection((hostname, 443), timeout=3) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                return True
    except:
        return False

def perform_deep_analysis(target_url):
    start_time = time.time()
    violated_rules = []
    redirect_path = [target_url]
    points = 0
    
    try:
        # فحص الرابط ومحتوى الصفحة
        response = requests.get(target_url, headers=HEADERS, timeout=10, allow_redirects=True)
        final_url = response.url
        content = response.text  # هنا سنقوم بفحص الكود البرمجي للموقع
        
        for resp in response.history:
            if resp.url not in redirect_path:
                redirect_path.append(resp.url)
        if final_url not in redirect_path:
            redirect_path.append(final_url)

        # 1. فحص تشفير الموقع
        if not final_url.startswith('https'):
            points += 45
            violated_rules.append({"name": "اتصال غير مشفر", "risk_description": "الموقع لا يستخدم HTTPS.", "points_added": 45})
        else:
            if not check_ssl_status(urlparse(final_url).netloc):
                points += 35
                violated_rules.append({"name": "شهادة SSL غير موثوقة", "risk_description": "شهادة الأمان قد تكون مزيفة.", "points_added": 35})

        # 2. فحص محتوى الصفحة (التحديث الجديد لكشف سكريبتات الكاميرا)
        
        # كشف طلب الوصول للكاميرا أو الميكروفون
        if re.search(r'getUserMedia|enumerateDevices|mediaDevices', content):
            points += 70
            violated_rules.append({
                "name": "محاولة اختراق الخصوصية", 
                "risk_description": "تم رصد كود برمجي يحاول الوصول للكاميرا أو الميكروفون الخاص بك فور الدخول.", 
                "points_added": 70
            })

        # كشف محاولة سحب الصور أو البيانات تلقائياً
        if re.search(r'canvas\.toDataURL|upload|post.*\.png|post.*\.jpg', content, re.I):
            points += 50
            violated_rules.append({
                "name": "اشتباه في سحب بيانات بصري", 
                "risk_description": "الموقع يحتوي على تعليمات برمجية لإرسال صور أو لقطات من جهازك للسيرفر.", 
                "points_added": 50
            })

        # كشف طلبات إدخال كلمات المرور في مواقع غير معروفة
        if re.search(r'type="password"', content, re.I):
            points += 40
            violated_rules.append({"name": "طلب بيانات حساسة", "risk_description": "تم رصد نموذج لإدخال كلمة مرور.", "points_added": 40})

    except Exception:
        points += 20
        violated_rules.append({"name": "فشل الوصول للمحتوى", "risk_description": "الموقع يحظر أدوات التحليل، مما يثير الريبة.", "points_added": 20})
        final_url = target_url

    # 3. فحص الرابط نفسه (Regex)
    static_rules = [
        (r'@', 50, "رمز تضليل @"),
        (r'\d{1,3}\.\d{1,3}\.\d{1,3}', 60, "عنوان IP مباشر"),
        (r'(login|verify|bank|gift|update)', 30, "كلمات هندسة اجتماعية")
    ]
    for pattern, pts, name in static_rules:
        if re.search(pattern, final_url, re.I):
            points += pts
            violated_rules.append({"name": name, "risk_description": "نمط الرابط مريب وغالباً ما يُستخدم في التصيد.", "points_added": pts})

    risk = "Critical" if points >= 80 else "High" if points >= 45 else "Medium" if points >= 20 else "Low"

    return {
        "risk_score": risk,
        "suspicious_points": points,
        "violated_rules": violated_rules,
        "link_final": final_url,
        "redirect_path": redirect_path,
        "execution_time": round(time.time() - start_time, 2)
    }

@app.route('/')
def home():
    return render_template('index.html')

@app.route('/analyze', methods=['POST'])
def analyze():
    data = request.json
    url = data.get('link', '').strip()
    if not url: return jsonify({"message": "أدخل الرابط"}), 400
    if not url.startswith('http'): url = 'https://' + url
    if not validate_url(url): return jsonify({"message": "رابط خاطئ"}), 400
    return jsonify(perform_deep_analysis(url))

@app.route('/robots.txt')
def robots(): return send_from_directory(app.static_folder, 'robots.txt')

@app.route('/sitemap.xml')
def sitemap(): return send_from_directory(app.static_folder, 'sitemap.xml')

if __name__ == '__main__':
    app.run(debug=True)

