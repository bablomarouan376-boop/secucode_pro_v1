import os
import requests
import base64
import urllib3
import json
from flask import Flask, request, jsonify, render_template
from urllib.parse import urlparse
import firebase_admin
from firebase_admin import credentials, db

# كتم تحذيرات SSL
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

app = Flask(__name__)

# --- إعدادات SecuCode Pro 2026 (طارق مصطفى) ---
VT_API_KEY = "07c7587e1d272b5f0187493944bb59ba9a29a56a16c2df681ab56b3f3c887564"
TELEGRAM_TOKEN = "8072400877:AAEhIU4s8csph7d6NBM5MlZDlfWIAV7ca2o"
CHAT_ID = "7421725464"

# إعداد Firebase
try:
    if not firebase_admin._apps:
        firebase_admin.initialize_app(options={
            'databaseURL': 'https://flutter-ai-playground-2de28-default-rtdb.europe-west1.firebasedatabase.app'
        })
except Exception as e:
    print(f"Firebase Alert: {e}")

def check_spyware_behavior(url):
    """تحليل سلوكي لكشف طلبات الكاميرا والموقع"""
    try:
        headers = {"User-Agent": "SecuCode-Forensic/2.0"}
        response = requests.get(url, timeout=7, headers=headers, verify=False)
        content = response.text.lower()
        patterns = ['getusermedia', 'navigator.mediadevices', 'video', 'geolocation', 'webcam']
        return any(p in content for p in patterns)
    except: return False

def get_vt_analysis(url):
    """جلب بيانات الاستخبارات من VirusTotal"""
    try:
        url_id = base64.urlsafe_b64encode(url.encode()).decode().strip("=")
        headers = {"x-apikey": VT_API_KEY}
        res = requests.get(f"https://www.virustotal.com/api/v3/urls/{url_id}", headers=headers, timeout=10)
        return res.json()['data']['attributes']['last_analysis_stats'] if res.status_code == 200 else None
    except: return None

def send_telegram_alert(domain, is_spyware, m_count, score):
    """إرسال تقرير فوري لبوت طارق"""
    try:
        icon = "🔴" if (is_spyware or m_count > 0) else "🟢"
        msg = (
            f"{icon} *SecuCode Pro: Forensic Report*\n"
            f"━━━━━━━━━━━━━━━━━━\n"
            f"🌐 *Domain:* `{domain}`\n"
            f"📸 *Spyware:* {'Detected' if is_spyware else 'Clean'}\n"
            f"🚨 *Engines:* {m_count} flagged\n"
            f"📊 *Risk Level:* {score}%\n"
            f"👤 *Analyst:* Tarek Mostafa Core"
        )
        requests.post(f"https://api.telegram.org/bot{TELEGRAM_TOKEN}/sendMessage", 
                      json={"chat_id": CH_ID, "text": msg, "parse_mode": "Markdown"})
    except: pass

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/analyze', methods=['POST'])
def analyze():
    data = request.json
    raw_url = data.get('link', '').strip()
    if not raw_url: return jsonify({"error": "Empty URL"}), 400
    
    url = raw_url if raw_url.startswith('http') else 'https://' + raw_url
    domain = urlparse(url).netloc.lower() or url
    
    spy_detected = check_spyware_behavior(url)
    vt_stats = get_vt_analysis(url)
    m_count = vt_stats.get('malicious', 0) if vt_stats else 0
    
    # حساب معامل الخطورة
    risk_score = 99.9 if spy_detected else (min(m_count * 20, 100) if m_count > 0 else 0)
    is_blacklisted = (spy_detected or m_count > 0)

    # تحديث العدادات في Firebase
    try:
        db.reference('stats/clicks').transaction(lambda c: (c or 0) + 1)
        if is_blacklisted: db.reference('stats/threats').transaction(lambda t: (t or 0) + 1)
    except: pass

    send_telegram_alert(domain, spy_detected, m_count, risk_score)

    return jsonify({
        "is_official": (risk_score == 0 and ("google" in domain or "microsoft" in domain)),
        "is_blacklisted": is_blacklisted,
        "risk_score": risk_score,
        "spy_detected": spy_detected,
        "engines_found": m_count,
        "screenshot": f"https://s0.wp.com/mshots/v1/{url}?w=800&h=600"
    })

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)
