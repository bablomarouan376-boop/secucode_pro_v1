from flask import Flask, render_template, send_from_directory, request, jsonify
import os

app = Flask(__name__, static_folder='static', template_folder='templates')

# ربط الملفات الأساسية لمنع خطأ 404
@app.route('/manifest.json')
def manifest():
    return send_from_directory(app.static_folder, 'manifest.json')

@app.route('/')
def index():
    return render_template('index.html')

# دالة فحص تجريبية سريعة جداً
@app.route('/analyze', methods=['POST'])
def analyze():
    # هنا سنضيف الخوارزميات المعقدة لاحقاً، حالياً استجابة فورية للأساس
    data = request.json
    url = data.get('link', '')
    return jsonify({
        "status": "success",
        "points": 10,
        "risk_score": "Safe",
        "analysis_time": 0.05
    })

if __name__ == '__main__':
    app.run(debug=True)
