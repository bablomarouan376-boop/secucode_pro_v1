import os
import re
import requests
import time
import base64
from flask import Flask, request, jsonify, render_template, send_from_directory
from urllib.parse import urlparse, urljoin
from validators import url as validate_url
from datetime import datetime

# إعداد التطبيق - SecuCode Pro v2.5
app = Flask(__name__, static_folder='static', template_folder='templates')

# إعدادات متصفح احترافية (Stealth Mode)
HEADERS = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
    "Accept-Language": "ar,en-US;q=0.9,en;q=0.8",
    "Referer": "https://www.google.com/"
}

def get_domain_age(domain):
    """فحص عمر النطاق عبر بروتوكول RDAP"""
    try:
        if not domain or '.' not in domain: return None
        res = requests.get(f"https://rdap.org/domain/{domain}", timeout=5)
        if res.status_code == 200:
            events = res.json().get('events', [])
            for event in events:
                if event.get('eventAction') == 'registration':
                    reg_date = datetime.strptime(event.get('eventDate')[:10], "%Y-%m-%d")
                    return (datetime.now() - reg_date).days
    except: pass
    return None

def base64_auto_decoder(content):
    """Base64 Auto-Decoder: فك تشفير النصوص المخفية"""
    decoded_text = ""
    # البحث عن سلاسل نصية طويلة قد تكون Base64
    potential_matches = re.findall(r'["\']([A-Za-z0-9+/]{40,})={0,2}["\']', content)
    for match in potential_matches:
        try:
            decoded = base64.b64decode(match).decode('utf-8', errors='ignore')
            if any(key in decoded for key in ['http', 'eval', 'exec', 'document', 'window']):
                decoded_text += " " + decoded
        except: continue
    return decoded_text

def recursive_js_fetch(html, base_url):
    """Recursive JS Fetching: جلب وفحص السكربتات الخارجية والداخلية"""
    scripts = re.findall(r'<script src=["\'](.*?)["\']', html, re.I)
    js_content = ""
    # جلب محتوى السكربتات الداخلية المكتوبة مباشرة في HTML
    inline_scripts = re.findall(r'<script>(.*?)</script>', html, re.S | re.I)
    js_content += "\n".join(inline_scripts)
    
    # جلب السكربتات الخارجية (أول 5 ملفات لتجنب البطء)
    for s in scripts[:5]:
        try:
            full_url = urljoin(base_url, s)
            r = requests.get(full_url, headers=HEADERS, timeout=5)
            if r.status_code == 200:
                js_content += "\n" + r.text
        except: continue
    return js_content

def perform_ultimate_analysis(target_url):
    """المحرك الرئيسي: Deep Pattern Matching & Redirection Tracking"""
    start_time = time.time()
    violated_rules = []
    redirect_path = [target_url]
    risk_points = 0
    
    try:
        session = requests.Session()
        # Advanced Redirection Tracker: تتبع القفزات
        response = session.get(target_url, headers=HEADERS, timeout=12, allow_redirects=True)
        
        for r in response.history:
            if r.url not in redirect_path: redirect_path.append(r.url)
        if response.url not in redirect_path: redirect_path.append(response.url)

        final_url = response.url
        main_html = response.text
        
        # تجميع المحتوى للفحص العميق
        extended_js = recursive_js_fetch(main_html, final_url)
        full_logic = main_html + extended_js
        full_logic += base64_auto_decoder(full_logic)

        # 1. تحليل عمر النطاق
        domain = urlparse(final_url).netloc
        age = get_domain_age(domain)
        if age and age < 60:
            risk_points += 60
            violated_rules.append({"name": "نطاق حديث (خطر احتيال)", "risk_description": f"الموقع مسجل منذ {age} يوم فقط. المواقع الحديثة جداً غالباً ما تكون منصات تصيد مؤقتة."})

        # 2. Deep Pattern Matching: كشف محاولات التجسس وسحب البيانات
        threat_map = {
            'الوصول للكاميرا/المايك': r'getUserMedia|mediaDevices|camera|microphone|video|audio',
            'تتبع الموقع الجغرافي': r'getCurrentPosition|watchPosition|geolocation',
            'سحب الكوكيز/الجلسات': r'document\.cookie|sessionStorage|localStorage|atob\(',
            'تصيد بيانات مالية': r'credit_card|cvv|exp_date|password|ssn|social_security'
        }

        for label, pattern in threat_map.items():
            if re.search(pattern, full_logic, re.I):
                risk_points += 50
                violated_rules.append({"name": f"محاولة {label}", "risk_description": "تم رصد كود برمجي يحاول الوصول لخصوصيتك أو سحب بيانات حساسة بدون إذن."})

        # 3. فحص التشفير
        if not final_url.startswith('https'):
            risk_points += 40
            violated_rules.append({"name": "اتصال غير مشفر", "risk_description": "الموقع لا يدعم SSL، بياناتك المرسلة عبره يمكن اعتراضها بسهولة."})

    except Exception as e:
        risk_points += 35
        violated_rules.append({"name": "فشل الاتصال / حماية ضد الفحص", "risk_description": "الموقع يرفض الفحص الآلي، وهذا سلوك شائع في المواقع الضارة."})
        final_url = target_url

    # تصنيف الخطر النهائي
    score = min(risk_points, 100)
    label = "Critical" if score >= 85 else "High" if score >= 60 else "Medium" if score >= 30 else "Low"

    return {
        "risk_score": label,
        "suspicious_points": score,
        "violated_rules": violated_rules,
        "redirect_path": redirect_path,
        "final_url": final_url,
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

if __name__ == '__main__':
    app.run(debug=True)

