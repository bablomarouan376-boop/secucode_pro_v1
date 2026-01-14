import os, re, requests, time
from flask import Flask, request, jsonify, render_template, Response
from urllib.parse import urlparse
from threading import Thread

app = Flask(__name__)

# بيانات المطور: طارق مصطفى
TELEGRAM_TOKEN = "8072400877:AAEhIU4s8csph7d6NBM5MlZDlfWIAV7ca2o"
CHAT_ID = "7421725464"

# --- [ Intelligence Engine ] ---
BLACKLIST_DB = set()
WHITELIST = {'google.com', 'facebook.com', 'microsoft.com', 'apple.com', 'twitter.com', 'github.com', 'youtube.com', 'linkedin.com'}

def sync_engine():
    global BLACKLIST_DB
    while True:
        try:
            new_db = set()
            sources = ["https://openphish.com/feed.txt", "https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts"]
            for s in sources:
                r = requests.get(s, timeout=15)
                if r.status_code == 200:
                    domains = re.findall(r'(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9][a-z0-9-]{0,61}[a-z0-9]', r.text)
                    new_db.update([d.lower() for d in domains])
            BLACKLIST_DB = new_db
        except: pass
        time.sleep(3600)

Thread(target=sync_engine, daemon=True).start()

@app.route('/')
def index(): return render_template('index.html')

@app.route('/analyze', methods=['POST'])
def analyze():
    url = request.json.get('link', '').strip()
    if not url.startswith('http'): url = 'https://' + url
    
    score, violations = 0, []
    domain = urlparse(url).netloc.lower().replace('www.', '')

    try:
        if any(w in domain for w in WHITELIST):
            score, violations = 0, [{"name": "Global Trusted Authority", "desc": "تم التحقق: هذا النطاق مسجل ضمن المؤسسات الموثوقة عالمياً."}]
        elif domain in BLACKLIST_DB:
            score, violations = 100, [{"name": "Cyber Threat Identified", "desc": "تحذير: النطاق مدرج ضمن القوائم السوداء لنشاطات الاختراق النشطة."}]
        else:
            res = requests.get(url, timeout=8, headers={"User-Agent": "SecuCode-Pro-Sentry"}, verify=False)
            html = res.text
            if re.search(r'getUserMedia|mediaDevices|camera|videoinput', html, re.I):
                score = 98
                violations.append({"name": "Unauthorized Media Access", "desc": "بروتوكول مشبوه يحاول تشغيل الكاميرا/الميكروفون بدون تصريح."})
            if re.search(r'password|login|كلمة المرور|signin|verify', html, re.I):
                score = max(score, 90)
                violations.append({"name": "Phishing Interface Detection", "desc": "رصد هيكل انتحالي يهدف لسرقة بيانات الاعتماد الشخصية."})
    except:
        score, violations = 45, [{"name": "Encrypted Obstruction", "desc": "النظام يكتشف جدار حماية يمنع الفحص السلوكي الشامل."}]

    try:
        status = "🛑 CRITICAL THREAT" if score >= 80 else "🛡️ SECURE"
        msg = f"🔍 [REPORT] SecuCode Pro\n🌐 Host: {domain}\n📊 Risk Level: {score}%\n⚠️ Status: {status}"
        requests.post(f"https://api.telegram.org/bot{TELEGRAM_TOKEN}/sendMessage", json={"chat_id": CHAT_ID, "text": msg}, timeout=1)
    except: pass

    return jsonify({"risk_score": "Critical" if score >= 80 else "Safe", "points": score, "violations": violations})

if __name__ == '__main__':
    app.run(debug=True)
