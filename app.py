import os
import re
import requests
import time
import base64
from flask import Flask, request, jsonify, render_template, send_from_directory
from urllib.parse import urlparse, urljoin
from validators import url as validate_url
from datetime import datetime

app = Flask(__name__, static_folder='static', template_folder='templates')

# إعدادات متصفح احترافية لتجنب الحظر أثناء الفحص
HEADERS = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
    "Accept-Language": "en-US,en;q=0.9",
    "Referer": "https://www.google.com/"
}

def get_domain_age(domain):
    """فحص عمر النطاق عبر بروتوكول RDAP"""
    try:
        # استثناء النطاقات الفرعية الطويلة جداً
        clean_domain = ".".join(domain.split(".")[-2:])
        res = requests.get(f"https://rdap.org/domain/{clean_domain}", timeout=5)
        if res.status_code == 200:
            data = res.json()
            events = data.get('events', [])
            for event in events:
                if event.get('eventAction') == 'registration':
                    reg_date_str = event.get('eventDate')
                    reg_date = datetime.strptime(reg_date_str[:10], "%Y-%m-%d")
                    return (datetime.now() - reg_date).days
    except:
        pass
    return None

def fetch_and_scan_js(html, base_url):
    """جلب وتحليل ملفات الـ JavaScript الخارجية"""
    scripts = re.findall(r'<script src=["\'](.*?)["\']', html, re.I)
    js_payload = ""
    for s in scripts[:3]: # فحص أول 3 ملفات فقط للسرعة
        try:
            full_url = urljoin(base_url, s)
            r = requests.get(full_url, headers=HEADERS, timeout=3)
            js_payload += "\n" + r.text
        except:
            continue
    return js_payload

def perform_ultimate_analysis(target_url):
    """المحرك النهائي لتحليل التهديدات - الإصدار الاحترافي"""
    start_time = time.time()
    violated_rules = []
    risk_points = 0
    redirect_path = [target_url]
    
    try:
        session = requests.Session()
        response = session.get(target_url, headers=HEADERS, timeout=10, allow_redirects=True)
        final_url = response.url
        main_html = response.text
        domain = urlparse(final_url).netloc.lower()
        
        # تجميع المحتوى للفحص التقني
        full_content = main_html + fetch_and_scan_js(main_html, final_url)

        # 1. كشف انتحال العلامات التجارية (منطق محسّن 100%)
        brands = {
            'google': ['google.com', 'google.com.eg', 'gstatic.com'],
            'facebook': ['facebook.com', 'fb.com', 'messenger.com'],
            'paypal': ['paypal.com'],
            'microsoft': ['microsoft.com', 'live.com', 'outlook.com'],
            'apple': ['apple.com', 'icloud.com'],
            'amazon': ['amazon.com', 'aws.amazon.com'],
            'netflix': ['netflix.com'],
            'binance': ['binance.com']
        }

        for brand, official_domains in brands.items():
            if brand in domain:
                is_official = any(domain.endswith(off) for off in official_domains)
                if not is_official:
                    risk_points += 70
                    violated_rules.append({
                        "name": "اشتباه انتحال علامة تجارية", 
                        "risk_description": f"الموقع يستخدم اسم '{brand}' لكنه لا يتبع النطاقات الرسمية الموثقة."
                    })

        # 2. تحليل عمر النطاق
        age = get_domain_age(domain)
        if age is not None:
            if age < 30:
                risk_points += 40
                violated_rules.append({"name": "نطاق حديث جداً", "risk_description": f"عمر الموقع {age} يوم فقط. المواقع الجديدة غالباً ما تكون مريبة."})

        # 3. كشف استدعاءات الخصوصية (Patterns دقيقة)
        privacy_patterns = {
            'الكاميرا/الميكروفون': r'getUserMedia|mediaDevices\.getUserMedia',
            'الموقع الجغرافي': r'navigator\.geolocation\.getCurrentPosition',
            'طلب كلمات مرور': r'type=["\']password["\']'
        }

        for label, pattern in privacy_patterns.items():
            if re.search(pattern, full_content, re.I):
                # لا نحسب النقاط إذا كان الموقع رسمياً ومعروفاً (مثل جوجل)
                if risk_points > 0 or age is not None and age < 365:
                    risk_points += 30
                    violated_rules.append({"name": f"طلب أذونات: {label}", "risk_description": "تم رصد كود برمجي يطلب الوصول لبيانات حساسة."})

        # 4. فحص الأمان الأساسي
        if not final_url.startswith('https'):
            risk_points += 30
            violated_rules.append({"name": "اتصال غير مشفر", "risk_description": "الموقع يستخدم بروتوكول HTTP الضعيف."})

        # تتبع التحويلات
        for r in response.history:
            if r.url not in redirect_path: redirect_path.append(r.url)
        if final_url not in redirect_path: redirect_path.append(final_url)

    except Exception:
        # في حالة فشل الوصول للموقع (قد يكون محجوباً أو خبيثاً يحظر الفحص)
        risk_points = 25
        violated_rules.append({"name": "تحذير أمني", "risk_description": "الموقع يرفض الفحص الآلي أو تعذر الاتصال به، يرجى الحذر."})
        final_url = target_url

    # تصنيف النتيجة النهائية
    final_score = min(risk_points, 100)
    if final_score >= 70:
        risk_label = "Critical"
    elif final_score >= 40:
        risk_label = "High"
    elif final_score >= 20:
        risk_label = "Medium"
    else:
        risk_label = "Safe"

    return {
        "risk_score": risk_label,
        "suspicious_points": final_score,
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
    url = request.json.get('link', '').strip()
    if not url: return jsonify({"message": "يرجى إدخال الرابط"}), 400
    if not url.startswith('http'): url = 'https://' + url
    if not validate_url(url): return jsonify({"message": "الرابط غير صالح"}), 400
    return jsonify(perform_ultimate_analysis(url))

@app.route('/robots.txt')
def robots(): return send_from_directory(app.static_folder, 'robots.txt')

@app.route('/sitemap.xml')
def sitemap(): return send_from_directory(app.static_folder, 'sitemap.xml')

if __name__ == '__main__':
    app.run(debug=True)
