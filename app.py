import os
import requests
import base64
import socket
import time
import json
import logging
from flask import Flask, request, jsonify, render_template, send_file
from urllib.parse import urlparse
import firebase_admin
from firebase_admin import credentials, db
from xhtml2pdf import pisa
from io import BytesIO

app = Flask(__name__)

logging.basicConfig(level=logging.INFO)

# البيانات الحساسة
VT_API_KEY = "07c7587e1d272b5f0187493944bb59ba9a29a56a16c2df681ab56b3f3c887564"
TELEGRAM_TOKEN = "8072400877:AAEhIU4s8csph7d6NBM5MlZDlfWIAV7ca2o"
CHAT_ID = "7421725464"

FIREBASE_CONFIG = {
  "type": "service_account",
  "project_id": "secucode-pro",
  "private_key_id": "131da2ca8578982b77e48fa71f8c4b65880b0784",
  "private_key": "-----BEGIN PRIVATE KEY-----\nMIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQCZwhV2C+HnRrp8\nTemJc7bdbGw2JUb47hZ1ShXk2ReFbQ256bhud1AIO+rxHJ0fzq8Ba+ZTaAsodLxU\nn74+dxpyrMUolvBONnWgFeQtgqFsHouAAy0j/iJs6yNny6o4f/TVp4UKixqY+jT0\nTSBo8ixU7Dxh6VWdom62BsKUAGN8ALFM5N6+4z3fbCj9fB4mmvibIQLLAVwxZ703\ndSP1ZFOJgd98LEHYOBYBKAOQ/fEyq20e8PEokuVnoLqvLxJDGCwGvv5aEadq2t3O\nhJ9oJAefIDD2YsAPgeMu8MAtlHlTuoqu82FGehQ2v6mtC4121W2NFLORPC1fttWE\nFr5U5La3AgMBAAECggEAAUqVcGNeFirBiZCBK7wwJ6P3mLGZpkmD9N5R6FByJyy+\nr91nA2d4fZpiP3ZA9jTda0K8Hr9B2uEm8CjcqcJGXmtDC/UTsQIhAm5H9DE2gAyr\nej0lkOh6l9ScwTHA0Z8MnTy0xOBpeRdjZ32pjiSSixW0QB8kj4u0NJ+yvW+3NDru\ntErFEF03IaMgfnK279reWuNKC72lZfVlkFk9qoi6b34j1mdhAXlkIqPm1plkd8py\nZDPxGf7/xdB32peadLpuWHvd/JyE9hLGa+CT9g12kKOcxh/KmJVD5MBkIriQAFoh\nT7pvJm9SDju4uDtc6O26IME3/YIwjB+YfgrXMySMiQKBgQDOSdjq2/TJTYXoen2X\ncvlssZGGVenb30rcQHIPtC9xHhczPJ6cAPhRltmeV37HO8g82unNnbsAePCsVZx+\nX6p2y9VDzTDimAJEXd/JVjwBnFs8/8GwUwLoFvsbnAvA8pSFHYmKURDJolPjJ0Gw\nqr40NrApbRG47JYQHyhHTfOPwwKBgQC+z5Xa2yT1rSzOsNoOwfJmTo0oThNaTExE\n6/8/1F7NpeZLKbew5sai20CmmvWKljVKgiyUdJLZShlbnqv3QUvEL+PH9pWNftpd\nphAlbEG9UPjF6nR8IrOwtAXK3tMyrGlYl7EI0dgwY8pzoYgUraRik2AqfaG2BRe/\n8oUXZMKh/QKBgGmwaiOCB/su7cF7KGd0r5fhrgZedA+Dao5HsmibT4cr/ITytOyG\njrL2j45Rk5Gt7lxHaGxBOLL4Q4532lLg3qw4qI4xTa96ZAb09Zfox5unqRMqkeit\nzxpr08GEhH0Zi8BbrsEf4XL86O/DiCNkh0inEEBZMjBFfmjKHc/Sf0wTAoGALYVy\nl9LeP2pAHVNdwlWM0dF9pZby0QEQ1QSEUaMFtwQUK+xY8XAtBV9PTi/70kNBlXP2\n1Lf27LXb1NrG5ecC/1v5eJQgW7BewibDBVqNWG//2Z+0iITy334jP6HnOtidDVCr\IJKHhAvambl4sI44gHfuYlS0hqsyXk2qaMlWEbUCgYEAmSFfrOq4+I32/Aqr8f2v\nWnU65jupo1jeBmzSDP+IZYCH4Ydf9msfzQS9eX4UoGnQ8qD07ICiVnXuP7hqY8JR\n8sjwYcTcZ6JHiuLp4HP+PhwrhsM/govb8BCcBrDRpggTx7bXPhqFYKgPN5jb6n7Q\nQgLue5qdPf3qb3a3n6CioWQ=\n-----END PRIVATE KEY-----\n",
  "client_email": "firebase-adminsdk-fbsvc@secucode-pro.iam.gserviceaccount.com",
  "client_id": "100797441781867873022",
  "auth_uri": "https://accounts.google.com/o/oauth2/auth",
  "token_uri": "https://oauth2.googleapis.com/token",
  "auth_provider_x509_cert_url": "https://www.googleapis.com/oauth2/v1/certs",
  "client_x509_cert_url": "https://www.googleapis.com/robot/v1/metadata/x509/firebase-adminsdk-fbsvc%40secucode-pro.iam.gserviceaccount.com",
  "universe_domain": "googleapis.com"
}

try:
    if not firebase_admin._apps:
        cred = credentials.Certificate(FIREBASE_CONFIG)
        firebase_admin.initialize_app(cred, {'databaseURL': 'https://flutter-ai-playground-2de28-default-rtdb.europe-west1.firebasedatabase.app'})
except: pass

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/analyze', methods=['POST'])
def analyze():
    try:
        data = request.get_json()
        raw_url = data.get('link', '').strip()
        url = raw_url if raw_url.startswith('http') else 'https://' + raw_url
        domain = urlparse(url).netloc.lower() or url
        
        # تحليل سريع
        ip = socket.gethostbyname(domain)
        vt_url_id = base64.urlsafe_b64encode(url.encode()).decode().strip("=")
        vt_res = requests.get(f"https://www.virustotal.com/api/v3/urls/{vt_url_id}", headers={"x-apikey": VT_API_KEY}).json()
        
        stats = vt_res.get('data', {}).get('attributes', {}).get('last_analysis_stats', {'malicious': 0})
        risk = min(20 + (stats['malicious'] * 20), 100)
        is_bad = risk >= 60

        # تحديث Firebase وتليجرام
        db.reference('stats/clicks').transaction(lambda c: (c or 0) + 1)
        if is_bad: db.reference('stats/threats').transaction(lambda t: (t or 0) + 1)
        
        msg = f"{'🛑' if is_bad else '✅'} *Scan:* {domain}\n*Risk:* {risk}%"
        requests.post(f"https://api.telegram.org/bot{TELEGRAM_TOKEN}/sendMessage", json={"chat_id": CHAT_ID, "text": msg, "parse_mode": "Markdown"})

        return jsonify({"risk_score": risk, "is_blacklisted": is_bad, "server": {"ip": ip}, "screenshot": f"https://s0.wp.com/mshots/v1/{url}?w=800"})
    except Exception as e: return jsonify({"error": str(e)}), 500

@app.route('/generate_report', methods=['POST'])
def generate_report():
    try:
        data = request.get_json()
        html = render_template('report.html', data=data.get('result'), lang=data.get('lang'))
        pdf_out = BytesIO()
        pisa.CreatePDF(html, dest=pdf_out)
        pdf_out.seek(0)
        return send_file(pdf_out, mimetype='application/pdf', as_attachment=True, download_name='SecuCode_Report.pdf')
    except Exception as e: return str(e), 500

if __name__ == '__main__':
    app.run(debug=True)
