import os
from flask import Flask, request, jsonify, render_template
import requests
import re 
from urllib.parse import urlparse
from validators import url

# تهيئة تطبيق Flask
# الأهم: يجب أن يكون اسم الكائن "app" لكي يعمل Vercel بشكل صحيح.
app = Flask(__name__)

# --- تعريف قواعد الفحص الأمنية (تم اختصارها للعرض) ---
SECURITY_RULES = [
    # ----------------------------------------------------
    # مجموعة 1: قواعد فحص البنية العامة (Structure & Obfuscation)
    # ----------------------------------------------------
    {
        "check": lambda link, content: any(service in link.lower() for service in ["bit.ly", "goo.gl", "tinyurl", "ow.ly", "cutt.ly", "is.gd", "t.co", "rebrand.ly"]),
        "name": "اختصار الرابط (URL Shortener)",
        "risk": "قد يخفي الوجهة الحقيقية الضارة خلف رابط قصير وموثوق.",
        "points": 3
    },
    # ... (بقية القواعد الـ 42) ...
    {
        "check": lambda link, content: content is not None and bool(re.search(r'<form[^>]*\b(password|user|credit|card|cvv|secure|login)\b', content, re.IGNORECASE | re.DOTALL)),
        "name": "نموذج يطلب معلومات حساسة (Phishing) - فحص المحتوى",
        "risk": "وجود نموذج إدخال (Form) يطلب كلمات مرور أو بيانات بطاقة ائتمان بشكل مباشر وغير موثوق. هذا هو المؤشر الأقوى على موقع تصيد.",
        "points": 15
    }
]


# --- دالة التحليل الأمني (منطق العمل المُحدث) ---
def perform_security_scan(link):
    suspicious_points = 0
    detected_warnings = 0
    page_content = None 
    status_code = 0
    page_content_warning = "لم يتم إجراء تحليل للمحتوى بعد..."
    
    # 1. فحص الاتصال بالرابط والحصول على المحتوى
    try:
        response = requests.get(link, timeout=10, allow_redirects=True) 
        status_code = response.status_code
        final_link = response.url
        page_content = response.text 
        
        if len(response.history) > 3:
            suspicious_points += 10 
            detected_warnings += 1
            page_content_warning = f"تحذير: تمت {len(response.history)} عملية إعادة توجيه. (مشبوه)."

        if status_code != 200:
            suspicious_points += 5
            detected_warnings += 1
            page_content_warning = f"تحذير: الرابط يسبب خطأ {status_code}. (هذا يُعتبر مشبوهاً)."
        else:
            page_content_warning = f"تم جلب محتوى الصفحة بنجاح. (الحالة: {status_code})"
            
    except requests.exceptions.RequestException as e:
        suspicious_points += 15 
        detected_warnings += 1
        page_content_warning = f"خطأ حاد في الاتصال بالرابط أو حدوث مهلة (Timeout). ({e})"
        status_code = 0
        final_link = link 
        
    # 2. تطبيق جميع القواعد الأمنية 
    violated_rules = []
    link_for_rules = final_link
    content_to_check = page_content if page_content else ""

    for rule in SECURITY_RULES:
        try:
            if rule["check"](link_for_rules, content_to_check):
                suspicious_points += rule["points"] 
                detected_warnings += 1
                violated_rules.append({
                    "name": rule["name"],
                    "risk_description": rule["risk"],
                    "points_added": rule["points"]
                })
        except Exception as e:
            print(f"Error applying rule {rule['name']}: {e}") 
            pass

    # 3. تحديد مستوى الخطورة
    risk_score = "Low"
    result_message = "🟢 آمن نسبيًا: لم يتم اكتشاف مخاطر واضحة بناءً على التحليل السريع."

    if suspicious_points > 90:
        risk_score = "Critical"
        result_message = "🔴 خطر حرج جداً! يحتوي على مؤشرات قوية على موقع تصيد أو ملف تنفيذي ضار. يُنصح بشدة بعدم المتابعة."
    elif suspicious_points > 50:
        risk_score = "High"
        result_message = "🔥 خطر عالٍ! تم اكتشاف مخالفات هيكلية وسلوكية متعددة في الرابط."
    elif suspicious_points > 20:
        risk_score = "Medium"
        result_message = "⚠️ خطر متوسط. يحتوي على بعض العناصر المشبوهة التي تقلل من الثقة به. استخدم بحذر."
    
    # 4. إعادة النتيجة
    return {
        "status": "success" if suspicious_points < 20 else "warning" if suspicious_points < 50 else "error",
        "message": f"تحليل مكتمل. تم تطبيق {len(SECURITY_RULES)} قاعدة فحص على الرابط النهائي ({link_for_rules}).",
        "link_input": link, 
        "link_final": link_for_rules, 
        "result_message": result_message,
        "risk_score": risk_score,
        "suspicious_points": suspicious_points,
        "detected_warnings": detected_warnings,
        "page_content_status": page_content_warning,
        "violated_rules": violated_rules 
    }

# --- نقطة النهاية الرئيسية لعرض الواجهة الأمامية ---
@app.route('/', methods=['GET'])
def index():
    return render_template('index.html')


# --- نقطة النهاية للتحليل (API) ---
@app.route('/analyze', methods=['POST'])
def analyze_link():
    
    try:
        data = request.get_json()
        link_to_analyze = data.get('link')
    except Exception:
        return jsonify({
            "status": "critical_error",
            "message": "خطأ في معالجة بيانات الطلب (JSON).",
            "error_code": 400
        }), 400

    if not link_to_analyze or link_to_analyze.strip() == "":
        return jsonify({
            "status": "validation_error",
            "message": "❌ فشل التحقق: الرجاء إدخال رابط. حقل الرابط لا يمكن أن يكون فارغاً.",
            "error_code": 400
        }), 400

    # تعديل صغير: إضافة البروتوكول في حالة عدم وجوده
    if not link_to_analyze.lower().startswith(('http://', 'https://')):
        link_to_analyze = 'https://' + link_to_analyze
    
    # التحقق من صلاحية الرابط باستخدام مكتبة validators
    if url(link_to_analyze) is not True:
         return jsonify({
            "status": "validation_error",
            "message": "❌ الإدخال غير صحيح. الرجاء إدخال رابط حقيقي وصالح بصيغة URL.",
            "error_code": 400
        }), 400
    
    
    analysis_result = perform_security_scan(link_to_analyze) 
    
    return jsonify(analysis_result), 200

# تم حذف جزء 'if __name__ == '__main__': ...' لضمان التوافق مع Vercel
