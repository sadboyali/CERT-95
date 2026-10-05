# دليل النشر — CERT 95

خطّة النشر:
- 📖 **موقع الحلول** (`solutions/`) → **Netlify** (ساكن، مجاني).
- 🎯 **المختبر** (`lab/`) → **Render** (خادم Node مجاني، يشتغل كما هو).

كلاهما من **نفس الريبو على GitHub**، والنشر يصير تلقائياً مع كل تعديل.

جهّزت لك الريبو محلياً مع كل ملفات الإعداد. باقي ثلاث مراحل تسوّيها أنت.

---

## المرحلة 1 — ارفع الكود إلى GitHub

الريبو مُهيّأ ومعمول له commit محلياً. تحتاج فقط ترفعه:

1. أنشئ ريبو فارغاً جديداً على <https://github.com/new> (بلا README/‏.gitignore). خلّيه باسم مثل `cert95`.
2. من مجلد المشروع شغّل (بدّل `USERNAME` باسمك):

```powershell
cd "C:\Users\BGD\Desktop\TASK Ahmed abd"
git remote add origin https://github.com/USERNAME/cert95.git
git branch -M main
git push -u origin main
```

> أول push راح يطلب تسجيل دخول GitHub (المتصفح أو توكن). هذا الجزء لازم تسوّيه أنت — أنا ما أگدر أسجّل دخول لحسابك.

---

## المرحلة 2 — انشر موقع الحلول على Netlify

1. ادخل <https://app.netlify.com> → **Add new site** → **Import an existing project** → **GitHub**.
2. اختر ريبو `cert95`.
3. Netlify راح يقرأ ملف `netlify.toml` تلقائياً، فتظهر الإعدادات جاهزة:
   - **Publish directory:** `solutions`
   - **Build command:** (فارغ)
4. اضغط **Deploy**. خلال ثوانٍ يصير عندك رابط مثل `https://cert95.netlify.app`.

✅ موقع الحلول صار شغّال. كل مرة تعدّل وترفع (`git push`) ينشر تلقائياً.

---

## المرحلة 3 — انشر المختبر على Render

1. ادخل <https://dashboard.render.com> → **New** → **Web Service** → اربط GitHub واختر ريبو `cert95`.
2. Render راح يقرأ ملف `render.yaml` تلقائياً (Blueprint). إذا سألك، أكّد الإعدادات:
   - **Root Directory:** `lab`
   - **Build Command:** `npm install`
   - **Start Command:** `node server.js`
   - **Environment variable:** `HOST = 0.0.0.0` (موجود بالملف)
   - **Instance Type:** Free
3. اضغط **Create / Deploy**. خلال دقيقة-دقيقتين يصير عندك رابط مثل `https://cert95-lab.onrender.com`.

✅ المختبر صار شغّال بالكامل (بما فيه ثغرة SQLi — لأن Render يشغّل خادم Node حقيقي بإصدار 24 حسب `lab/.nvmrc`).

> ⏳ **ملاحظة الخطة المجانية:** خدمة Render المجانية «تنام» بعد ~15 دقيقة خمول، وأول طلب بعدها يأخذ ~30-60 ثانية حتى تصحى. طبيعي ومجاني.

---

## المرحلة 4 — اربط الموقعين (خطوة أخيرة صغيرة)

زر «↩ المختبر» في موقع الحلول يحتاج يعرف رابط Render:

1. افتح `solutions/solutions.js`، أول سطر فيه:

```js
const LAB_URL = "http://127.0.0.1:4000/";
```

2. بدّله برابط Render:

```js
const LAB_URL = "https://cert95-lab.onrender.com/";
```

3. ارفع التعديل:

```powershell
git add solutions/solutions.js
git commit -m "ربط موقع الحلول برابط المختبر على Render"
git push
```

Netlify راح ينشر التحديث تلقائياً. خلص — الموقعان مربوطان. 🎉

---

## تنبيه أمني

المختبر فيه ثغرات مقصودة لكنها معزولة وببيانات اصطناعية (لا تنفيذ أوامر حقيقي، اجتياز المسار محصور بـ sandbox، SQLi على قاعدة بيانات وهمية في الذاكرة). رفعه عام مقبول لأنه محصور. إذا تريد تقلّل أي مخاطرة، تگدر:
- تخلّي رابط Netlify/Render خاصّاً أو تشاركه فقط مع من تثق بهم.
- أو تبقّي المختبر محلياً وترفع موقع الحلول فقط.
