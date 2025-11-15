import os
from flask import Flask, request, jsonify, render_template
import requests
import re 
from urllib.parse import urlparse
from validators import url

# تهيئة تطبيق Flask
app = Flask(__name__)

# --- تعريف 42 قاعدة أمنية مُحدثة وموسعة باللغة العربية ---
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
    {
        "check": lambda link, content: bool(re.search(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', urlparse(link).netloc)),
        "name": "استخدام رقم IP مباشر في النطاق",
        "risk": "قد يشير إلى خادم مؤقت أو موقع غير مسجل رسمياً، يستخدم لتجنب فحص DNS.",
        "points": 4
    },
    {
        "check": lambda link, content: '@' in link,
        "name": "وجود رمز @ في الرابط (User Info Obfuscation)",
        "risk": "يستخدم لخداع المتصفح والزائر حول الوجهة الحقيقية للرابط (Phishing).",
        "points": 5
    },
    {
        "check": lambda link, content: len(link) > 100,
        "name": "الطول المبالغ فيه للرابط (>100 حرف)",
        "risk": "الروابط الطويلة جداً تستخدم أحياناً لإخفاء محتوى ضار أو لتجنب الفلاتر الأمنية.",
        "points": 2
    },
    {
        "check": lambda link, content: link.lower().startswith('http://'),
        "name": "بروتوكول HTTP غير الآمن",
        "risk": "الرابط غير مشفر (غير HTTPS)، مما يعرض بيانات المستخدمين (مثل كلمات المرور) للتجسس.",
        "points": 6
    },
    {
        "check": lambda link, content: bool(re.search(r':\d{4,}', link)),
        "name": "استخدام منفذ غير قياسي",
        "risk": "قد يشير إلى تشغيل خدمات غير تقليدية أو غير معتادة على المنافذ المعروفة (القياسي هو 80/443).",
        "points": 2
    },
    {
        "check": lambda link, content: link.count('=') > 7,
        "name": "كثرة المتغيرات في الرابط (>7)",
        "risk": "قد تكون محاولة لحقن أو تمرير معلمات ضخمة غير مرغوب فيها.",
        "points": 2
    },
    {
        "check": lambda link, content: link.count('.') > 4,
        "name": "كثرة النطاقات الفرعية العميقة (>4)",
        "risk": "تستخدم لتقليد المواقع الشرعية (مثل: secure.login.google.com.xyz.com).",
        "points": 3
    },
    {
        "check": lambda link, content: link.count('http') > 1,
        "name": "تكرار البروتوكول داخل الرابط",
        "risk": "محاولة خداع متقدمة لتمرير http/https داخل مسار الرابط (مثلاً: https://google.com/http:/malware).",
        "points": 5
    },
    {
        "check": lambda link, content: 'xn--' in link.lower(),
        "name": "وجود Punycode/IDN (خداع الأحرف الدولية)",
        "risk": "يشير إلى استخدام أسماء نطاقات دولية (IDN) قد تُستخدم لانتحال شخصية موقع آخر بحروف مشابهة (Typosquatting بصري).",
        "points": 5
    },
    {
        "check": lambda link, content: bool(re.search(r'%.{2}', link)),
        "name": "وجود ترميز URL (%XX)",
        "risk": "يشير إلى وجود أحرف مشفرة قد تخفي كلمات مفتاحية ضارة أو مسارات غير مرغوبة.",
        "points": 2
    },
    {
        "check": lambda link, content: 'data:' in link.lower() or 'javascript:' in link.lower(),
        "name": "استخدام أنظمة URI خطيرة (Data/JavaScript)",
        "risk": "يسمح بتشغيل كود JavaScript مباشرة في المتصفح أو تضمين محتوى كقاعدة 64. خطر عالٍ.",
        "points": 7
    },
    {
        "check": lambda link, content: bool(re.search(r'\.\./|\.\.\\|\.\.%2f|\.\.%5c', link, re.IGNORECASE)),
        "name": "مؤشر لـ Directory Traversal",
        "risk": "محاولة للوصول إلى ملفات خارج المسار المخصص على الخادم (مثل: `../` أو `..%2F`).",
        "points": 6
    },
    {
        "check": lambda link, content: '//' in urlparse(link).path,
        "name": "مسارات مزدوجة متكررة (Redundant Slashes)",
        "risk": "قد يُستخدم للتخفي أو لإرباك المتصفحات والفلاتر الأمنية البسيطة.",
        "points": 2
    },
    {
        "check": lambda link, content: len(urlparse(link).netloc.split('.')[0]) > 25,
        "name": "طول مبالغ فيه للنطاق الفرعي (Subdomain)",
        "risk": "النطاقات الفرعية الطويلة جداً (مثل سلاسل عشوائية) غالباً ما تكون مؤشراً على الإزعاج أو الخداع.",
        "points": 3
    },
    # ----------------------------------------------------
    # مجموعة 2: قواعد فحص النطاق و Typosquatting
    # ----------------------------------------------------
    {
        "check": lambda link, content: any(ext in link.lower() for ext in ['.cf', '.tk', '.ga', '.ml', '.xyz', '.cc', '.info', '.biz', '.top']),
        "name": "انتهاء نطاق مشبوه (TLD)",
        "risk": "امتدادات النطاقات هذه غالباً ما تستخدم في حملات التصيد والاحتيال لأنها مجانية أو رخيصة.",
        "points": 4
    },
    {
        "check": lambda link, content: any(re.search(rf'{word}', link.lower())) for word in ['faceb?ook', 'g00gle', 'appple', 'micr0s0ft', 'am@zon', 'payp@l'],
        "name": "خطأ إملائي في النطاق (Typosquatting - متقدم)",
        "risk": "انتحال شخصية المواقع الكبرى باستخدام أخطاء إملائية ذكية لسرقة بيانات الاعتماد. خطر حرج.",
        "points": 7
    },
    {
        "check": lambda link, content: any(char.isdigit() for char in urlparse(link).netloc.split('.')[1]) and link.count('.') >= 1,
        "name": "نطاق رئيسي يحتوي على أرقام",
        "risk": "النطاقات الرئيسية التي تحتوي على أرقام (مثل: pay123.com) غالباً ما تكون مشبوهة.",
        "points": 3
    },
    {
        "check": lambda link, content: len(link.split('.')) > 2 and urlparse(link).netloc.split('.')[0].lower() == urlparse(link).netloc.split('.')[-2].lower(),
        "name": "تكرار النطاق الفرعي (Domain Repetition)",
        "risk": "نوع من الخداع لتمرير اسم النطاق الأساسي مرتين لخداع العين.",
        "points": 2
    },
    {
        "check": lambda link, content: urlparse(link).netloc.count('-') > 5,
        "name": "كثرة الواصلات في اسم النطاق (>5)",
        "risk": "تستخدم لزيادة طول النطاق أو لحشو الكلمات المفتاحية في نطاقات الإزعاج.",
        "points": 2
    },
    {
        "check": lambda link, content: link.lower().startswith('https:') and link.lower().count('https') > 1,
        "name": "تكرار HTTPS في المسار (خداع بصري)",
        "risk": "محاولة لتركيز عين المستخدم على HTTPS في البداية وتكراره في المسار دون فائدة.",
        "points": 3
    },
    # ----------------------------------------------------
    # مجموعة 3: قواعد فحص المسار والملفات (Path & Files)
    # ----------------------------------------------------
    {
        "check": lambda link, content: any(word in link.lower() for word in ['gift', 'prize', 'free', 'win', 'claim', 'discount', 'bonus', 'crypto', 'wallet']),
        "name": "استخدام كلمات خداع اجتماعي شائعة",
        "risk": "يشير إلى محاولة خداع اجتماعي أو إغراء المستخدم لتقديم بيانات حساسة.",
        "points": 3
    },
    {
        "check": lambda link, content: any(word in link.lower() for word in ['admin', 'upload', 'config', 'backup', 'db', 'password']),
        "name": "كلمات إدارة وحساسة في الرابط",
        "risk": "قد يشير إلى محاولة الوصول لصفحة إدارة أو تحميل ملفات حساسة أو وجود بيانات حساسة في المسار.",
        "points": 4
    },
    {
        "check": lambda link, content: link.lower().endswith(('.exe', '.bat', '.cmd', '.scr', '.zip', '.rar', '.7z', '.iso')),
        "name": "الانتهاء بملف تنفيذي أو مضغوط ضار",
        "risk": "يشير إلى أن الرابط سيقوم بتحميل أو تشغيل ملف تنفيذي مباشرة على جهاز المستخدم دون تأكيد.",
        "points": 7
    },
    {
        "check": lambda link, content: bool(re.search(r'/\d{10,}/', link)),
        "name": "سلسلة أرقام طويلة جداً في المسار",
        "risk": "قد تشير إلى ملفات تم تحميلها عشوائياً أو مسار مخفي وضخم، أو مُعرف جلسة مشبوه.",
        "points": 2
    },
    {
        "check": lambda link, content: link.count('?') > 1,
        "name": "وجود أكثر من علامة استفهام في الرابط",
        "risk": "الاستخدام غير القياسي لعلامة الاستفهام، والتي تحدد بداية المتغيرات (Query Parameters).",
        "points": 3
    },
    {
        "check": lambda link, content: 'base64' in link.lower() or 'hex' in link.lower(),
        "name": "استخدام كلمات الترميز (Base64/Hex)",
        "risk": "يشير إلى محاولة تمرير بيانات مشفرة في الرابط لتجاوز فلاتر التحليل البسيطة.",
        "points": 4
    },
    {
        "check": lambda link, content: bool(re.search(r'[\u0600-\u06FF]', link)) and 'xn--' not in link.lower(),
        "name": "أحرف عربية أو غير لاتينية غير مشفرة",
        "risk": "قد يشير إلى ترميز غير صحيح أو محاولة لدمج أحرف بصرية غير متوقعة في الرابط.",
        "points": 2
    },
    {
        "check": lambda link, content: link.lower().count('/') > 7,
        "name": "عمق المسار المبالغ فيه (>7 مستويات)",
        "risk": "قد يدل على موقع يتمتع ببنية ملفات معقدة ومخفية بشكل غير طبيعي.",
        "points": 2
    },
    # ----------------------------------------------------
    # مجموعة 4: قواعد فحص الأمان والسلوك (Security & Behavior)
    # ----------------------------------------------------
    {
        "check": lambda link, content: any(word in link.lower() for word in ['secure', 'safe', 'trust', 'login', 'verify', 'ssl']) and 'https' not in link.lower(),
        "name": "كلمات أمان زائفة بدون تشفير",
        "risk": "محاولة إيهام المستخدم بالأمان (مثل رابط فيه 'secure' ولكنه HTTP). خطر عالٍ.",
        "points": 5
    },
    {
        "check": lambda link, content: any(word in urlparse(link).query.lower() for word in ['session', 'cookie', 'token', 'auth']),
        "name": "تضمين كلمات الجلسة الحساسة في متغيرات الرابط",
        "risk": "قد يشير إلى محاولة حقن أو سرقة بيانات الجلسة عبر الرابط.",
        "points": 4
    },
    {
        "check": lambda link, content: len(link) > 40 and link != link.lower() and link != link.upper(),
        "name": "أحرف كبيرة وصغيرة عشوائية",
        "risk": "تستخدم لتجاوز فلاتر البريد المزعج والفلاتر الأمنية البسيطة عن طريق التلاعب بالأحرف.",
        "points": 1
    },
    {
        "check": lambda link, content: link.lower().endswith('.pdf') and 'http' in link.lower(),
        "name": "رابط مباشر لتحميل PDF ببروتوكول HTTP",
        "risk": "تحميل ملفات حساسة (قد تكون ضارة) عبر اتصال غير مشفر.",
        "points": 3
    },
    {
        "check": lambda link, content: 'webmail' in link.lower() or 'cpanel' in link.lower(),
        "name": "كلمات تشير لخدمات بريد/استضافة في نطاق فرعي",
        "risk": "استهداف المستخدمين بالوصول إلى لوحات تحكم الاستضافة أو البريد الإلكتروني.",
        "points": 4
    },
    {
        "check": lambda link, content: link.count('-') > 2 and 'free' in link.lower(),
        "name": "استخدام الواصلات مع كلمة 'Free' (Spam)",
        "risk": "نمط شائع في نطاقات البريد المزعج التي تقدم خدمات مجانية (مثل: free-prize-claim.com).",
        "points": 3
    },
    # ----------------------------------------------------
    # مجموعة 5: قواعد فحص المحتوى (Content Analysis)
    # ----------------------------------------------------
    {
        "check": lambda link, content: content is not None and bool(re.search(r'<form[^>]*\b(password|user|credit|card|cvv|secure|login)\b', content, re.IGNORECASE | re.DOTALL)),
        "name": "نموذج يطلب معلومات حساسة (Phishing) - فحص المحتوى",
        "risk": "وجود نموذج إدخال (Form) يطلب كلمات مرور أو بيانات بطاقة ائتمان بشكل مباشر وغير موثوق. هذا هو المؤشر الأقوى على موقع تصيد.",
        "points": 15
    },
    {
        "check": lambda link, content: content is not None and len(content) < 500,
        "name": "محتوى صفحة قصير جداً (Under Construction/Redirect)",
        "risk": "يشير إلى أن الصفحة فارغة أو أنها مجرد صفحة إعادة توجيه فورية أو صفحة غير مكتملة.",
        "points": 5
    },
    {
        "check": lambda link, content: content is not None and bool(re.search(r'iframe|base64|document\.write', content, re.IGNORECASE)),
        "name": "كود JavaScript أو IFRAME مشبوه",
        "risk": "وجود عناصر برمجية يتم حقنها أو تحميل محتوى خارجي مخفي.",
        "points": 6
    },
    {
        "check": lambda link, content: content is not None and bool(re.search(r'error|404|not found', content, re.IGNORECASE)),
        "name": "الصفحة تحوي رسالة خطأ صريحة في المحتوى",
        "risk": "الرابط يقود إلى صفحة خطأ، مما قد يشير إلى أن الموقع غير مستقر أو تمت إزالته.",
        "points": 1
    },
    {
        "check": lambda link, content: content is not None and bool(re.search(r'window\.location\.replace|window\.location\.href', content, re.IGNORECASE)),
        "name": "كود إعادة توجيه متقدم (Client-Side Redirect)",
        "risk": "يشير إلى محاولة نقل المستخدم فوراً إلى رابط آخر باستخدام جافاسكريبت.",
        "points": 4
    }
]


# --- دالة التحليل الأمني (منطق العمل المُحدث) ---
def perform_security_scan(link):
    suspicious_points = 0
    detected_warnings = 0
    page_content = None # نغير القيمة الافتراضية إلى None لتسهيل الفحص
    status_code = 0
    page_content_warning = "لم يتم إجراء تحليل للمحتوى بعد..."
    
    # 1. فحص الاتصال بالرابط والحصول على المحتوى
    try:
        # requests.get يتبع عمليات إعادة التوجيه تلقائياً
        response = requests.get(link, timeout=10, allow_redirects=True) 
        status_code = response.status_code
        
        # نستخدم الرابط النهائي بعد إعادة التوجيه لبعض الفحوصات
        final_link = response.url
        page_content = response.text 
        
        # قاعدة إضافية: فحص حالة إعادة التوجيه المفرطة
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
        suspicious_points += 15 # نزيد النقاط في حالة فشل الاتصال لخطورة الموضوع
        detected_warnings += 1
        page_content_warning = f"خطأ حاد في الاتصال بالرابط أو حدوث مهلة (Timeout). ({e})"
        status_code = 0
        
    # 2. تطبيق جميع القواعد الأمنية (التي تعتمد على الرابط والمحتوى)
    violated_rules = []
    link_for_rules = final_link if 'final_link' in locals() else link # نستخدم الرابط النهائي
    
    # التأكد من أن جميع فحوصات المحتوى تمرر قيمة المحتوى (قد تكون None إذا فشل الاتصال)
    content_to_check = page_content if page_content else ""

    for rule in SECURITY_RULES:
        try:
            # تمرير محتوى الصفحة (content_to_check) لجميع الدوال
            if rule["check"](link_for_rules, content_to_check):
                suspicious_points += rule["points"] 
                detected_warnings += 1
                violated_rules.append({
                    "name": rule["name"],
                    "risk_description": rule["risk"],
                    "points_added": rule["points"]
                })
        except Exception as e:
            # طباعة الخطأ في حال فشل تطبيق قاعدة معينة
            print(f"Error applying rule {rule['name']}: {e}") 
            pass

    # 3. تحديد مستوى الخطورة بناءً على النقاط (المجموع الأقصى حوالي 130+ نقطة)
    
    risk_score = "Low"
    result_message = "🟢 آمن نسبيًا: لم يتم اكتشاف مخاطر واضحة بناءً على التحليل السريع."

    # تعديل مستويات الخطورة لتناسب النقاط الجديدة
    if suspicious_points > 90:
        risk_score = "Critical"
        result_message = "🔴 خطر حرج جداً! يحتوي على مؤشرات قوية على موقع تصيد أو ملف تنفيذي ضار. يُنصح بشدة بعدم المتابعة."
    elif suspicious_points > 50:
        risk_score = "High"
        result_message = "🔥 خطر عالٍ! تم اكتشاف مخالفات هيكلية وسلوكية متعددة في الرابط (مثل HTTP غير مشفر أو Typosquatting). يفضل تجنبه تماماً."
    elif suspicious_points > 20:
        risk_score = "Medium"
        result_message = "⚠️ خطر متوسط. يحتوي على بعض العناصر المشبوهة التي تقلل من الثقة به. استخدم بحذر."
    
    # 4. إعادة النتيجة
    return {
        "status": "success" if suspicious_points < 20 else "warning" if suspicious_points < 50 else "error",
        "message": f"تحليل مكتمل. تم تطبيق {len(SECURITY_RULES)} قاعدة فحص على الرابط النهائي ({link_for_rules}).",
        "link_input": link, # الرابط الأصلي الذي أدخله المستخدم
        "link_final": link_for_rules, # الرابط النهائي بعد إعادة التوجيه
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
    # سيقوم Flask بالبحث عن index.html في مجلد 'templates' افتراضياً.
    # بما أننا نستخدم ملفاً واحداً في البيئة التفاعلية، سنقوم بتوفير محتواه مباشرة.
    # في البيئة الحقيقية، يجب وضع index.html في مجلد 'templates'.
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

if __name__ == '__main__':
    # لا تقم بتشغيل هذا الجزء في البيئة التفاعلية، ولكن هو ضروري لعمل التطبيق خارجها
    # port = int(os.environ.get('PORT', 5000))
    # app.run(host='0.0.0.0', port=port, debug=True)
    pass
