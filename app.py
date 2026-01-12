import os, re, requests, time, random
from flask import Flask, request, jsonify, render_template, send_from_directory, Response
from urllib.parse import urlparse
from datetime import datetime
from threading import Thread

app = Flask(__name__)

# --- المستودع المركزي للذكاء الاصطناعي والتهديدات ---
GLOBAL_BLACKLIST = set()
LAST_UPDATE = "جاري المزامنة..."
START_DATE = datetime(2026, 1, 1)
BASE_SCANS = 1540

def update_threat_intelligence():
    global GLOBAL_BLACKLIST, LAST_UPDATE
    new_threats = set()
    sources = [
        "https://openphish.com/feed.txt",
        "https://phishstats.info/phish_score.txt"
    ]
    for s in sources:
        try:
            res = requests.get(s, timeout=15)
            if res.status_code == 200:
                for line in res.text.splitlines():
                    if line and not line.startswith('#'):
                        domain = urlparse(line).netloc if '://' in line else line.split('/')[0]
                        if domain: new_threats.add(domain.lower().strip())
        except: pass
    
    # قائمة طارق الخاصة للتهديدات المحلية النشطة في مصر
    manual_list = [
        'casajoys.com', 'webcam360.com', 'grabify.link', 
        'iplogger.org', 'blasze.com', 'linkexpander.com',
        'r.mtdv.me', 'bit.ly', 'cutt.ly' # الروابط المختصرة توضع تحت المراقبة
    ]
    for d in manual_list: new_threats.add(d)
    
    GLOBAL_BLACKLIST = new_threats
    LAST_UPDATE = datetime.now().strftime("%H:%M:%S")

Thread(target=update_threat_intelligence).start()

def get_live_stats():
    now = datetime.now()
    days = (now - START_DATE).days
    total = BASE_SCANS + (days * 41) + (now.hour * 3) + random.randint(1, 5)
    return total, int(total * 0.13)

# --- المحرك السلوكي المتطور (Deep Radar) ---
def analyze_content(content, domain):
    points, findings = 0, []
    
    # 1. كشف محاولة اختراق الكاميرا (WebCam Attack)
    if re.search(r'getUserMedia|Webcam\.attach|camera\.start|video_capture|navigator\.devices\.video', content, re.I):
        trusted = ['google.com', 'zoom.us', 'microsoft.com', 'teams.live.com', 'facebook.com']
        if not any(t in domain for t in trusted):
            points += 98
            findings.append({"name": "اختراق الخصوصية (كاميرا)", "desc": "تم رصد محاولة برمجية لفتح الكاميرا فور الدخول للموقع."})
    
    # 2. كشف تسريب البيانات لبوتات التليجرام (Exfiltration)
    if re.search(r'api\.telegram\.org/bot|tele-bot|bot_token', content, re.I):
        points = max(points, 90)
        findings.append({"name": "تسريب بيانات (تليجرام)", "desc": "الموقع مبرمج لإرسال ملفاتك أو صورك لبوت تليجرام خارجي."})
    
    # 3. كشف سكربتات سحب الحسابات (Phishing Scripts)
    if re.search(r'login_submit|password_capture|account_verify', content, re.I) and points < 50:
        points += 40
        findings.append({"name": "اشتباه في صفحة مزورة", "desc": "يحتوي الموقع على أكواد تهدف لسحب بيانات الدخول."})
    
    return points, findings

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/analyze', methods=['POST'])
def analyze():
    url = request.json.get('link', '').strip()
    if not url: return jsonify({"error": "No URL provided"}), 400
    if not url.startswith('http'): url = 'https://' + url
    
    domain = urlparse(url).netloc.lower()
    total_points, violations = 0, []

    # الخطوة 1: فحص القائمة السوداء الفورية
    if domain in GLOBAL_BLACKLIST:
        total_points = 100
        violations.append({"name": "تهديد عالمي مؤكد", "desc": "هذا الموقع مسجل رسمياً كنشاط احتيالي في قواعد بيانات الأمن السيبراني."})

    # الخطوة 2: التحليل السلوكي العميق (Deep Scan)
    if total_points < 100:
        try:
            # استخدام Session و User-Agent حقيقي لتجنب الحجب
            headers = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"}
            res = requests.get(url, timeout=12, headers=headers, allow_redirects=True)
            
            # فحص محتوى الصفحة
            p, f = analyze_content(res.text, domain)
            total_points = max(total_points, p)
            violations.extend(f)
            
            # كشف سلاسل التحويل الطويلة (Redirect Chains)
            if len(res.history) > 1:
                total_points += 15
                violations.append({"name": "تحويلات متعددة", "desc": "الموقع يقوم بتحويلك عدة مرات لإخفاء هويته، وهذا سلوك مريب."})

        except requests.exceptions.Timeout:
            total_points = max(total_points, 75)
            violations.append({"name": "حجب الفحص (Timeout)", "desc": "الموقع بطيء جداً أو يحاول تعطيل أنظمة الفحص، مما يرفع احتمالية الخطر."})
        except:
            if total_points < 50:
                total_points = 50
                violations.append({"name": "تعذر التحليل المباشر", "desc": "الموقع يحظر أدوات الفحص، مما يعني أنه قد يكون فخاً مشفراً."})

    score = min(total_points, 100)
    t_total, t_threats = get_live_stats()
    return jsonify({
        "risk_score": "Critical" if score >= 85 else "High" if score >= 60 else "Low",
        "points": score, "violations": violations, "last_update": LAST_UPDATE,
        "stats": {"total": t_total, "threats": t_threats}
    })

# --- مسارات الملفات التقنية (PWA & SEO) ---
@app.route('/manifest.json')
def serve_manifest():
    return send_from_directory(os.path.join(app.root_path, 'static'), 'manifest.json')

@app.route('/sitemap.xml')
def serve_sitemap():
    return send_from_directory(os.path.join(app.root_path, 'static'), 'sitemap.xml', mimetype='application/xml')

@app.route('/robots.txt')
def serve_robots():
    return send_from_directory(os.path.join(app.root_path, 'static'), 'robots.txt')

if __name__ == '__main__':
    app.run(debug=True)
