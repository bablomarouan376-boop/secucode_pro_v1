import os
import requests
import base64
import urllib3
from flask import Flask, request, jsonify, render_template
from urllib.parse import urlparse

# كتم تحذيرات SSL للمواقع غير الآمنة أثناء الفحص التقني
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

app = Flask(__name__)

# --- إعدادات النظام (طارق مصطفى) ---
VT_API_KEY = "07c7587e1d272b5f0187493944bb59ba9a29a56a16c2df681ab56b3f3c887564"
TELEGRAM_TOKEN = "8072400877:AAEhIU4s8csph7d6NBM5MlZDlfWIAV7ca2o"
CHAT_ID = "7421725464"

def check_spyware_behavior(url):
    """تحليل سلوك الكود المصدري لكشف محاولات الوصول للكاميرا أو الموقع"""
    try:
        headers = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) SecuCode-Audit/2026"}
        response = requests.get(url, timeout=10, headers=headers, verify=False)
        html = response.text.lower()
        
        # أنماط برمجية تستخدم في صفحات الاختراق (الكاميرا، الميكروفون، الموقع، تسجيل الشاشة)
        spy_patterns = [
            'getusermedia', 'navigator.mediadevices', 'video', 
            'canvas.todataurl', 'geolocation.getcurrentposition', 
            'track.stop', 'recorder.start'
        ]
        found = [p for p in spy_patterns if p in html]
        return len(found) > 0
    except Exception as e:
        print(f"Analysis Error: {e}")
        return False

def get_vt_analysis(url):
    """استعلام عن سجل الرابط في قاعدة بيانات VirusTotal العالمية"""
    try:
        # تشفير الرابط حسب معايير VT API v3
        url_id = base64.urlsafe_b64encode(url.encode()).decode().strip("=")
        headers = {"x-apikey": VT_API_KEY}
        res = requests.get(f"https://www.virustotal.com/api/v3/urls/{url_id}", headers=headers, timeout=12)
        
        if res.status_code == 200:
            return res.json()['data']['attributes']['last_analysis_stats']
        return None
    except Exception as e:
        print(f"VT Intelligence Error: {e}")
        return None

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/analyze', methods=['POST'])
def analyze():
    data = request.json
    raw_url = data.get('link', '').strip()
    
    if not raw_url:
        return jsonify({"error": "No URL provided"}), 400
    
    # تصحيح البروتوكول تلقائياً
    url = raw_url if raw_url.startswith(('http://', 'https://')) else 'https://' + raw_url
    domain = urlparse(url).netloc.lower()
    
    # 1. تحليل السلوك البرمجي
    is_spyware = check_spyware_behavior(url)
    
    # 2. فحص الاستخبارات العالمية (VirusTotal)
    vt_stats = get_vt_analysis(url)
    m_count = vt_stats.get('malicious', 0) if vt_stats else 0
    
    # 3. معالجة النتيجة النهائية (Risk Logic)
    if is_spyware:
        score, v_key = 99.9, "CRITICAL_SPYWARE"
    elif m_count > 0:
        score, v_key = min(m_count * 25, 100), "MALICIOUS_THREAT"
    else:
        score, v_key = 0, "CLEAN_DOMAIN"

    is_blacklisted = (is_spyware or m_count > 0)

    # 4. إرسال إشعار التليجرام الاحترافي
    try:
        status_icon = "⚠️" if is_blacklisted else "✅"
        tg_msg = (
            f"{status_icon} *SecuCode Pro Audit*\n"
            f"━━━━━━━━━━━━━━━\n"
            f"🌐 *Domain:* `{domain}`\n"
            f"📸 *Spyware Patterns:* {'Detected' if is_spyware else 'Clean'}\n"
            f"🚨 *Security Engines:* {m_count} flagged\n"
            f"📊 *Total Risk:* {score}%\n"
            f"━━━━━━━━━━━━━━━\n"
            f"👤 *Analyst:* Tarek Mostafa"
        )
        requests.post(f"https://api.telegram.org/bot{TELEGRAM_TOKEN}/sendMessage", 
                      json={"chat_id": CHAT_ID, "text": tg_msg, "parse_mode": "Markdown"})
    except: 
        pass

    # الاستجابة النهائية المتوافقة مع الـ Frontend
    return jsonify({
        "is_official": False, # يتم التحقق منها في الفرونت إند أولاً
        "is_blacklisted": is_blacklisted,
        "risk_score": score,
        "violation_key": v_key,
        "spy_detected": is_spyware,
        "engines_found": m_count
    })

if __name__ == '__main__':
    # تشغيل السيرفر في وضع التطوير
    app.run(host='0.0.0.0', port=5000, debug=True)
