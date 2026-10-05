// CERT 95 — منطق عرض الشرائح: تنقّل، كشف الفلاگ، نسخ الأوامر، شريط التقدّم.

// ⚙️ بعد نشر المختبر على Render، بدّل هذا الرابط برابط خدمتك (مثال: https://cert95-lab.onrender.com)
const LAB_URL = "http://127.0.0.1:4000/";
const _back = document.getElementById("backlink");
if (_back) _back.href = LAB_URL;

const DECK = window.DECK;
const DOMAIN = { web: "ويب", crypto: "تشفير", reverse: "عكسية", forensics: "فورنسِك" };
let cur = 0;

const esc = (s) => String(s).replace(/[&<>]/g, (m) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;" }[m]));

function slideHTML(s) {
  if (s.type === "intro")
    return `<section class="slide intro">
      <div class="kicker">OPERATION · MR-024</div>
      <h1>${s.title}</h1><div class="sub">${s.sub}</div>
      ${s.body}</section>`;
  if (s.type === "finale")
    return `<section class="slide finale">
      <div class="kicker">CASE CLOSED</div>
      <h1>${s.title}</h1><div class="sub">${s.sub}</div>
      ${s.body}</section>`;

  const tools = s.tools.map((t) => `<li>${t}</li>`).join("");
  const steps = s.steps.map((st, i) =>
    `<li><div class="st-t"><span class="st-n">${i + 1}</span><div>${st.t}</div></div>` +
    (st.c ? `<pre>${esc(st.c)}</pre>` : "") + `</li>`).join("");

  return `<section class="slide">
    <div class="s-head">
      <div class="s-num">${String(s.n).padStart(2, "0")}</div>
      <div class="s-ttl"><h1>${s.title}</h1><div class="en">${s.en}</div></div>
      <div class="s-tags"><span class="tag">${DOMAIN[s.domain]}</span><span class="tag lvl">${"●".repeat(s.level)}</span></div>
    </div>

    <div class="story">${s.story}</div>

    <div class="sec"><h3>🎯 الهدف</h3><p class="objective">${s.objective}</p></div>
    <div class="sec"><h3>📘 الثغرة</h3><p>${s.concept}</p></div>
    <div class="sec"><h3>🧰 أدوات كالي</h3><ul class="tools">${tools}</ul></div>
    <div class="sec"><h3>🪜 خطوات الحل</h3><ol class="steps">${steps}</ol></div>

    <div class="flagbox"><div class="lbl">🏴 الفلاگ</div><span class="val" title="انقر للكشف">${s.flag}</span></div>

    <div class="sec fix"><h3>🛡️ الإصلاح</h3><p>${s.fix}</p></div>
    ${s.transition ? `<div class="transition">↪ ${s.transition}</div>` : ""}
  </section>`;
}

function renderPills() {
  const pills = document.getElementById("pills");
  pills.innerHTML = DECK.map((s, i) => {
    const label = s.type === "intro" ? "⚑" : s.type === "finale" ? "🏁" : String(s.n).padStart(2, "0");
    return `<button class="pill ${i === cur ? "active" : ""}" data-i="${i}" title="${esc(s.title)}">${label}</button>`;
  }).join("");
}

function render() {
  const s = DECK[cur];
  const stage = document.getElementById("stage");
  stage.innerHTML = slideHTML(s);
  stage.scrollTop = 0;
  window.scrollTo(0, 0);

  document.getElementById("counter").textContent = `${cur + 1} / ${DECK.length}`;
  document.getElementById("prev").disabled = cur === 0;
  document.getElementById("next").disabled = cur === DECK.length - 1;
  document.getElementById("pfill").style.width = `${((cur + 1) / DECK.length) * 100}%`;
  renderPills();

  // كشف الفلاگ
  stage.querySelectorAll(".flagbox .val").forEach((el) =>
    el.addEventListener("click", () => el.classList.toggle("show")));
  // أزرار نسخ
  stage.querySelectorAll("pre").forEach((pre) => {
    const b = document.createElement("button");
    b.className = "copy"; b.textContent = "نسخ";
    b.addEventListener("click", async () => {
      try { await navigator.clipboard.writeText(pre.textContent); b.textContent = "تم ✓"; setTimeout(() => (b.textContent = "نسخ"), 1200); }
      catch { b.textContent = "حدّد يدوياً"; }
    });
    pre.appendChild(b);
  });

  if (DECK[cur].id) location.hash = DECK[cur].id;
  else location.hash = DECK[cur].type;
}

function go(i) { cur = Math.max(0, Math.min(DECK.length - 1, i)); render(); }

document.getElementById("prev").addEventListener("click", () => go(cur - 1));
document.getElementById("next").addEventListener("click", () => go(cur + 1));
document.getElementById("pills").addEventListener("click", (e) => {
  const p = e.target.closest(".pill"); if (p) go(Number(p.dataset.i));
});
// الأسهم (RTL: يسار = التالي، يمين = السابق)
document.addEventListener("keydown", (e) => {
  if (e.target.matches("input,textarea")) return;
  if (e.key === "ArrowLeft") go(cur + 1);
  else if (e.key === "ArrowRight") go(cur - 1);
});

// فتح على شريحة من الـ hash
const start = DECK.findIndex((s) => (s.id || s.type) === location.hash.slice(1));
if (start >= 0) cur = start;
render();
