// ═══════════════════════════════════════════════════════════════════════════
//  ATHAR LAB · خادم المختبر المصاب (ثغرات مقصودة للتدريب)
//  Intentionally vulnerable training server. Local & isolated. Synthetic data.
//
//  تشغيل:  node server.js        ← ثم افتح http://127.0.0.1:4000
//
//  ⚠️  كل ثغرة هنا *مقصودة* ومعزولة. لا تستعمل هذا الكود كمرجع للإنتاج.
//      نقاط الضعف معلّمة بـ  «VULN:»  لتشرح نفسها.
// ═══════════════════════════════════════════════════════════════════════════
import http from "node:http";
import { readFileSync, existsSync, writeFileSync, mkdirSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join, extname, normalize, sep } from "node:path";
import { randomBytes, createCipheriv, timingSafeEqual } from "node:crypto";
import { DatabaseSync } from "node:sqlite";
import { FLAGS, META } from "./lib/flags.js";
import { send, sendJSON, sendHTML, readBody, mime, esc, page } from "./lib/util.js";
import { generateArtifacts } from "./lib/artifacts.js";

const __dirname = dirname(fileURLToPath(import.meta.url));
const PORT = Number(process.env.PORT) || 4000;
const HOST = process.env.HOST || "127.0.0.1";
const PUBLIC = join(__dirname, "public");
const CHALLENGES = join(__dirname, "challenges");
const SANDBOX = join(__dirname, "sandbox", "traversal");

// ── إعداد الملفات والبيانات عند الإقلاع ────────────────────────────────────
console.log("· توليد ملفات التحديات…");
generateArtifacts(CHALLENGES);
setupTraversalSandbox();
const db = seedDatabase();
const ECB_KEY = randomBytes(16);                 // مفتاح ثابت طوال عمر العملية
const ECB_SECRET = Buffer.from(FLAGS["crypto-ecb"]);

// ═══════════════════════════ قاعدة البيانات (SQLi) ═════════════════════════
function seedDatabase() {
  const d = new DatabaseSync(":memory:");
  d.exec(`CREATE TABLE users(
    id INTEGER PRIMARY KEY, username TEXT, password TEXT, role TEXT, secret TEXT);`);
  const rows = [
    [1, "admin",   "Zs9!marsad-vault-key", "admin",   FLAGS["web-sqli"]],
    [2, "analyst", "autumn-2025",           "analyst", "ملاحظات داخلية: دوّر مفتاح relay-07 قبل نهاية الدورة."],
    [3, "trainee", "trainee",               "trainee", "مرحباً بك في أرشيف مرصد. صلاحياتك محدودة."],
  ];
  const ins = d.prepare("INSERT INTO users VALUES(?,?,?,?,?)");
  for (const r of rows) ins.run(...r);
  return d;
}

// ═══════════════════════════ sandbox للـ Path Traversal ════════════════════
function setupTraversalSandbox() {
  mkdirSync(join(SANDBOX, "public"), { recursive: true });
  mkdirSync(join(SANDBOX, "private"), { recursive: true });
  const files = {
    "public/notes.txt": "ملاحظات عامة للمتدرّبين. هذا الملف متاح للتنزيل.\nراجع report.txt أيضاً.\n",
    "public/report.txt": "تقرير أسبوعي (عام). لا يحتوي بيانات حساسة.\n",
    "private/config.txt": "db_host=archive-internal\ndb_user=svc-archive\n# تهيئة داخلية — ليست للعرض العام\n",
    "private/flag.txt": FLAGS["web-traversal"] + "\n",
  };
  for (const [rel, body] of Object.entries(files)) {
    const p = join(SANDBOX, rel);
    if (!existsSync(p)) writeFileSync(p, body);
  }
}

// ═══════════════════════════ المحاكي الآمن لـ Command Injection ════════════
// VULN: المدخل يُدمج في «أمر» ويُفسَّر مع عوامل الصدفة (; | && `) بدل تمريره
//       كوسيط واحد. لا يوجد تنفيذ فعلي على النظام — صدفة وهمية معزولة بالكامل.
const FAKE_FS = {
  "/flag.txt": FLAGS["web-cmdi"],
  "/etc/passwd": "root:x:0:0:root:/root:/bin/sh\nsvc-archive:x:1001:1001::/home/svc:/bin/false\n",
  "/home/svc/.note": "لا تنسَ تعطيل أداة فحص الشبكة؛ المدخل غير مُنقّى.\n",
};
function fakeExec(token) {
  const parts = token.trim().split(/\s+/);
  const cmd = parts[0], args = parts.slice(1);
  switch (cmd) {
    case "ping": {
      const host = args.find((a) => !a.startsWith("-")) || "";
      if (!host) return "ping: usage: ping <host>";
      return `PING ${host}: 56 data bytes\n64 bytes from ${host}: icmp_seq=0 ttl=64 time=0.1 ms\n1 packets transmitted, 1 received, 0% packet loss`;
    }
    case "cat": return args.map((p) => FAKE_FS[p] ?? `cat: ${p}: No such file or directory`).join("\n");
    case "ls": return Object.keys(FAKE_FS).join("\n");
    case "whoami": return "svc-archive";
    case "id": return "uid=1001(svc-archive) gid=1001(svc-archive) groups=1001(svc-archive)";
    case "echo": return args.join(" ");
    case "": return "";
    default: return `sh: ${cmd}: command not found`;
  }
}
function fakeShell(line) {
  // تقسيم على عوامل السلسلة الشائعة: ;  &&  ||  |  &  ثم $(...) و `...`
  const expanded = line.replace(/\$\(([^)]*)\)|`([^`]*)`/g, (_, a, b) => fakeExec(a ?? b));
  const tokens = expanded.split(/\s*(?:;|&&|\|\||\||&)\s*/).filter((t) => t.length);
  return tokens.map(fakeExec).join("\n");
}

// ═══════════════════════════════ الموجّه ══════════════════════════════════
const server = http.createServer(async (req, res) => {
  try {
    const url = new URL(req.url, `http://${req.headers.host}`);
    const path = url.pathname;
    const q = url.searchParams;

    // ── API ────────────────────────────────────────────────────────────
    if (path === "/api/challenges") return apiChallenges(res);
    if (path === "/api/submit" && req.method === "POST") return await apiSubmit(req, res);

    // ── تحديات الويب الحية ───────────────────────────────────────────────
    if (path === "/web/" || path === "/web") return webHome(res);
    if (path === "/web/login") return webLogin(res, q);                 // SQLi
    if (path === "/web/search") return webSearch(res, q);               // Reflected XSS
    if (path === "/web/guestbook") return await webGuestbook(req, res); // Stored XSS (no flag)
    if (path === "/web/account") return webAccount(res, q);             // IDOR
    if (path === "/web/export") return webExport(res, q);               // HPP → flag
    if (path === "/web/netcheck") return webNetcheck(res, q);           // Command injection
    if (path === "/web/files") return webFiles(res, q);                 // Path traversal
    if (path === "/web/ecb") return webEcb(res, q);                     // ECB oracle

    // ── تنزيل ملفات التحديات ─────────────────────────────────────────────
    if (path.startsWith("/download/")) return serveUnder(res, CHALLENGES, path.slice("/download/".length));

    // ── الملفات الساكنة لواجهة المختبر ───────────────────────────────────
    if (path === "/" ) return serveStatic(res, join(PUBLIC, "index.html"));
    return serveUnder(res, PUBLIC, path.slice(1) || "index.html");
  } catch (e) {
    console.error("request error:", e);
    sendJSON(res, 500, { error: "خطأ داخلي في المختبر" });
  }
});

// ═══════════════════════════════ API ══════════════════════════════════════
function apiChallenges(res) {
  const list = Object.entries(META).map(([id, m]) => ({ id, ...m }));
  sendJSON(res, 200, { challenges: list });
}
async function apiSubmit(req, res) {
  let body = {};
  try { body = JSON.parse((await readBody(req)).toString() || "{}"); } catch {}
  const submitted = String(body.flag || "").trim();
  let hit = null;
  for (const [id, flag] of Object.entries(FLAGS)) {
    const a = Buffer.from(submitted), b = Buffer.from(flag);
    if (a.length === b.length && timingSafeEqual(a, b)) { hit = id; break; }
  }
  if (hit) sendJSON(res, 200, { correct: true, id: hit, domain: META[hit].domain, title: META[hit].title });
  else sendJSON(res, 200, { correct: false });
}

// ═══════════════════════════ WEB: الصفحة الرئيسية ══════════════════════════
function webHome(res) {
  const card = (href, tag, title, en, desc) =>
    `<a class="wa-card" href="${href}"><span class="wa-tag">${tag}</span><h3>${title}</h3><code>${en}</code><p>${desc}</p></a>`;
  sendHTML(res, 200, page("بوابة مرصد", `
  <section class="wa-hero">
    <h1>بوابة أرشيف مرصد</h1>
    <p>حساب متدرّب نشط. راجعوا ما تسمح به كل خدمة — وما تكشفه حركة الطلبات. كل خدمة تحمل ثغرة واحدة مقصودة.</p>
  </section>
  <div class="wa-grid">
    ${card("/web/login", "SQLi", "الباب المنسي", "SQL Injection", "نموذج دخول يبني الاستعلام بدمج النص مباشرة.")}
    ${card("/web/search?q=مرصد", "XSS", "مرآة الإدخال", "Reflected XSS", "بحث يعكس ما تكتبه في الصفحة دون تهذيب.")}
    ${card("/web/account?id=1001", "IDOR+HPP", "مفتاح في المكان الخطأ", "Broken Access Control", "عرض الحسابات والتصدير. الصلاحية تقرأ قيمة والمصدِّر يقرأ أخرى.")}
    ${card("/web/netcheck?host=127.0.0.1", "CMDi", "خلف الأمر", "Command Injection", "أداة فحص شبكة تمرّر المدخل إلى «صدفة» (محاكاة آمنة).")}
    ${card("/web/files?name=notes.txt", "LFI", "خارج الجذر", "Path Traversal", "تنزيل ملفات يدمج اسم الملف بالمسار دون تحقق.")}
    ${card("/web/ecb?text=AAAAAAAAAAAAAAAA", "CRYPTO", "بايت تلو الآخر", "ECB Oracle", "خدمة تشفّر مدخلك + سرّاً بوضع ECB. تسريب بنيوي.")}
    ${card("/web/guestbook", "XSS", "دفتر الزوّار", "Stored XSS", "تعليقات تُحفظ وتُعرض كما هي (توضيح — بلا فلاگ).")}
  </div>`, { bodyClass: "wa-portal" }));
}

// ═══════════════════════════ WEB: SQL Injection ════════════════════════════
function webLogin(res, q) {
  const u = q.get("username"), p = q.get("password");
  let result = "";
  if (u !== null || p !== null) {
    // VULN: دمج مدخل المستخدم مباشرة في نص SQL. جرّب:  admin' --
    const sql = `SELECT id, username, role, secret FROM users WHERE username='${u ?? ""}' AND password='${p ?? ""}'`;
    try {
      const rows = db.prepare(sql).all();
      if (rows.length) {
        result = `<div class="wa-ok"><strong>تم الدخول (${rows.length} صف):</strong>` +
          rows.map((r) => `<div class="wa-row"><b>${esc(r.username)}</b> · ${esc(r.role)}<br><span class="mono">${esc(r.secret)}</span></div>`).join("") +
          `</div>`;
      } else {
        result = `<div class="wa-err">فشل الدخول: اسم المستخدم أو كلمة المرور غير صحيحة.</div>`;
      }
    } catch (e) {
      // VULN: تسريب رسالة خطأ قاعدة البيانات (error-based SQLi).
      result = `<div class="wa-err mono">SQL error: ${esc(e.message)}<br><small>الاستعلام: ${esc(sql)}</small></div>`;
    }
  }
  sendHTML(res, 200, page("دخول", `
  <section class="wa-panel">
    <h1>دخول الموظفين</h1>
    <p>أدخل بيانات الاعتماد للوصول إلى لوحة الأرشيف.</p>
    <form class="wa-form" method="get" action="/web/login">
      <label><span>اسم المستخدم</span><input name="username" dir="ltr" autocomplete="off" value="${esc(q.get("username") ?? "")}"></label>
      <label><span>كلمة المرور</span><input name="password" dir="ltr" autocomplete="off" value="${esc(q.get("password") ?? "")}"></label>
      <button type="submit">دخول</button>
    </form>
    ${result}
    <p class="wa-hint">الهدف: استخرج سرّ حساب <code>admin</code> دون معرفة كلمة مروره.</p>
  </section>`));
}

// ═══════════════════════════ WEB: Reflected XSS ════════════════════════════
function webSearch(res, q) {
  const term = q.get("q") ?? "";
  // VULN: انعكاس المدخل داخل HTML دون ترميز. ورمز حسّاس في سياق الصفحة.
  const html = page("بحث", `
  <section class="wa-panel">
    <h1>بحث الأرشيف</h1>
    <form class="wa-form" method="get" action="/web/search">
      <label><span>كلمة البحث</span><input name="q" value="${term}"></label>
      <button type="submit">بحث</button>
    </form>
    <div class="wa-results">لا توجد نتائج لـ: ${term}</div>
    <p class="wa-hint">الهدف: نفّذ JavaScript في سياق هذه الصفحة واقرأ <code>document.cookie</code> أو <code>window.__archive_token</code>.</p>
  </section>
  <script>
    // رمز جلسة حسّاس يعيش في سياق الصفحة (غير httpOnly عمداً لهذا التحدي).
    window.__archive_token = ${JSON.stringify(FLAGS["web-xss"])};
    document.cookie = "archive_token=" + encodeURIComponent(window.__archive_token) + "; path=/web";
  </script>`);
  sendHTML(res, 200, html);
}

// ═══════════════════════════ WEB: Stored XSS (توضيحي) ══════════════════════
const guestbook = [{ name: "svc-archive", msg: "مرحباً بالفريق في بوابة الأرشيف." }];
async function webGuestbook(req, res) {
  if (req.method === "POST") {
    let name = "", msg = "";
    try {
      const b = new URLSearchParams((await readBody(req)).toString());
      name = b.get("name") || "مجهول"; msg = b.get("msg") || "";
    } catch {}
    if (msg) guestbook.push({ name, msg }); // VULN: يُخزَّن ويُعرض لاحقاً دون تهذيب
    res.writeHead(302, { Location: "/web/guestbook" }); return res.end();
  }
  const entries = guestbook.map((e) => `<div class="wa-row"><b>${e.name}</b>: ${e.msg}</div>`).join("");
  sendHTML(res, 200, page("دفتر الزوّار", `
  <section class="wa-panel">
    <h1>دفتر الزوّار</h1>
    <form class="wa-form" method="post" action="/web/guestbook">
      <label><span>الاسم</span><input name="name"></label>
      <label><span>التعليق</span><input name="msg"></label>
      <button type="submit">نشر</button>
    </form>
    <div class="wa-results">${entries}</div>
    <p class="wa-hint">كل تعليق يُعرض لكل زائر كما هو — توضيح للـ Stored XSS. لا يوجد فلاگ هنا.</p>
  </section>`));
}

// ═══════════════════════ WEB: IDOR + HTTP Parameter Pollution ══════════════
const ACCOUNTS = {
  "1001": { id: 1001, user: "trainee-04", role: "متدرّب", note: "حسابك. صلاحيات محدودة." },
  "1002": { id: 1002, user: "trainee-05", role: "متدرّب", note: "زميل في نفس الدفعة." },
  "1337": { id: 1337, user: "svc-archive", role: "خدمة", note: "خدمة الأرشيف تحفظ سجلات تسليم داخلية. استخدم /web/export?record=public-brief للتصدير." },
};
const RECORDS = {
  "public-brief":      { title: "دليل المتدرّب", body: "محتوى عام يسمح بتصديره لأي حساب متدرّب." },
  "handover-internal": { title: "سجل التسليم الداخلي", body: FLAGS["web-access"] },
};
function webAccount(res, q) {
  const id = q.get("id") || "1001";
  // VULN: IDOR — لا تحقق من ملكية الحساب؛ أي id يُقرأ مباشرة.
  const acct = ACCOUNTS[id];
  if (!acct) return sendJSON(res, 404, { error: "account not found", hint: "جرّب 1001 أو 1002 أو 1337" });
  sendJSON(res, 200, acct);
}
function webExport(res, q) {
  const records = q.getAll("record");
  const first = records[0] || "public-brief";
  // VULN: فحص الصلاحية يقرأ *أول* قيمة…
  if (first !== "public-brief")
    return sendJSON(res, 403, { error: "access denied: trainee-04 may only export public-brief" });
  // …بينما المصدِّر يقرأ *آخر* قيمة (HTTP Parameter Pollution).
  const chosen = records.at(-1) || first;
  const record = RECORDS[chosen];
  if (!record) return sendJSON(res, 404, { error: "record not found" });
  sendJSON(res, 200, { record: chosen, ...record });
}

// ═══════════════════════════ WEB: Command Injection ════════════════════════
function webNetcheck(res, q) {
  const host = q.get("host");
  let output = "";
  if (host !== null) {
    // VULN: بناء سطر أوامر بدمج المدخل. يُفسَّر مع عوامل الصدفة.
    const commandLine = `ping -c 1 ${host}`;
    output = `<pre class="wa-term">$ ${esc(commandLine)}\n${esc(fakeShell(commandLine))}</pre>`;
  }
  sendHTML(res, 200, page("فحص الشبكة", `
  <section class="wa-panel">
    <h1>أداة فحص الشبكة</h1>
    <p>تتحقق من وصول مضيف عبر ping. (الصدفة محاكاة آمنة — لا تنفيذ فعلي.)</p>
    <form class="wa-form" method="get" action="/web/netcheck">
      <label><span>المضيف</span><input name="host" dir="ltr" value="${esc(q.get("host") ?? "127.0.0.1")}"></label>
      <button type="submit">فحص</button>
    </form>
    ${output}
    <p class="wa-hint">الهدف: اقرأ <code>/flag.txt</code> من خلال حقن أمر في معامل المضيف.</p>
  </section>`));
}

// ═══════════════════════════ WEB: Path Traversal ═══════════════════════════
function webFiles(res, q) {
  const name = q.get("name") || "notes.txt";
  const base = join(SANDBOX, "public");
  // VULN: دمج اسم الملف بالمسار دون منع «../». (محصور داخل SANDBOX للسلامة.)
  const target = normalize(join(base, name));
  // حدّ أمان للمختبر فقط: امنع الهروب خارج sandbox إلى قرص المستخدم الحقيقي.
  if (!target.startsWith(SANDBOX + sep) && target !== SANDBOX)
    return sendJSON(res, 403, { error: "sandbox boundary", note: "هذا الحد موجود لحماية جهازك فقط." });
  if (!existsSync(target))
    return sendJSON(res, 404, { error: `not found: ${name}` });
  try {
    const data = readFileSync(target);
    send(res, 200, data, { "Content-Type": "text/plain; charset=utf-8" });
  } catch {
    sendJSON(res, 400, { error: "cannot read path" });
  }
}

// ═══════════════════════════ WEB: ECB oracle ═══════════════════════════════
function webEcb(res, q) {
  let input;
  if (q.get("hex") !== null) { try { input = Buffer.from(q.get("hex"), "hex"); } catch { input = Buffer.alloc(0); } }
  else input = Buffer.from(q.get("text") ?? "", "utf8");
  // VULN: ECB يشفّر كل كتلة 16 بايت باستقلال. (input || SECRET) يسرّب السرّ
  //        بايتاً بايتاً. المفتاح ثابت للعملية؛ السرّ هو الفلاگ.
  const c = createCipheriv("aes-128-ecb", ECB_KEY, null);
  const ct = Buffer.concat([c.update(Buffer.concat([input, ECB_SECRET])), c.final()]);
  sendJSON(res, 200, { mode: "AES-128-ECB", note: "ciphertext = ECB(your_input || SECRET)", ciphertext: ct.toString("hex") });
}

// ═══════════════════════════ ملفات ساكنة / تنزيل ═══════════════════════════
function serveStatic(res, file) {
  if (!existsSync(file)) return sendJSON(res, 404, { error: "not found" });
  send(res, 200, readFileSync(file), { "Content-Type": mime(extname(file)) });
}
function serveUnder(res, root, rel) {
  const target = normalize(join(root, decodeURIComponent(rel)));
  // هذا المسار (ملفات الواجهة/التنزيل) *ليس* تحدياً — نمنع التجاوز فعلاً.
  if (!target.startsWith(root + sep) && target !== root) return sendJSON(res, 403, { error: "forbidden" });
  if (!existsSync(target)) return sendJSON(res, 404, { error: "not found" });
  send(res, 200, readFileSync(target), { "Content-Type": mime(extname(target)) });
}

server.listen(PORT, HOST, () => {
  console.log("\n  ╔══════════════════════════════════════════════════╗");
  console.log("  ║   ATHAR LAB — بيئة تدريب معزولة بثغرات مقصودة       ║");
  console.log("  ╚══════════════════════════════════════════════════╝");
  console.log(`\n  → افتح المتصفح على:  http://${HOST}:${PORT}\n`);
  console.log("  (اضغط Ctrl+C لإيقاف الخادم)\n");
});
