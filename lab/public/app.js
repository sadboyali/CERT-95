// ═══════════════════════════════════════════════════════════════
//  منطق حملة «الأرشيف الصامت»: خط زمني مترابط، فتح تدريجي، رتب، تلميحات.
// ═══════════════════════════════════════════════════════════════
const CH = window.CAMPAIGN;
const DOMAIN = {
  web:       { g: "🌐", name: "ويب" },
  crypto:    { g: "🔐", name: "تشفير" },
  reverse:   { g: "⚙️", name: "عكسية" },
  forensics: { g: "🔬", name: "فورنسِك" },
};
const RANKS = [
  { min: 0,  name: "متدرّب" },
  { min: 3,  name: "محلّل" },
  { min: 7,  name: "محقّق" },
  { min: 11, name: "خبير" },
  { min: 13, name: "خبير العمليات" },
];

const LS = "athar-solved";
const solved = new Set(JSON.parse(localStorage.getItem(LS) || "[]"));
const save = () => localStorage.setItem(LS, JSON.stringify([...solved]));

const revealed = {};                 // تلميحات مكشوفة لكل فصل
let openIndex = -1;                   // الفصل المفتوح حالياً

const isDone = (c) => solved.has(c.flagId);
const isUnlocked = (i) => i === 0 || CH.slice(0, i).every(isDone);

function currentIndex() {
  for (let i = 0; i < CH.length; i++) if (isUnlocked(i) && !isDone(CH[i])) return i;
  return -1; // كل شيء مكتمل
}

function esc(s) { return String(s).replace(/[&<>"]/g, (m) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" }[m])); }

function render() {
  const done = solved.size;
  // الترويسة
  document.getElementById("pfill").style.width = `${(done / CH.length) * 100}%`;
  document.getElementById("count").textContent =
    `${String(done).padStart(2, "0")} / ${CH.length} فصلاً مكتملاً`;
  const rank = [...RANKS].reverse().find((r) => done >= r.min);
  document.getElementById("rank").textContent = rank.name;
  const next = RANKS.find((r) => r.min > done);
  document.getElementById("rank-next").textContent = next ? `— ${next.min - done} فصول للرتبة «${next.name}»` : "— أعلى رتبة";
  document.getElementById("finale").classList.toggle("show", done === CH.length);

  if (openIndex === -1) openIndex = currentIndex();

  const root = document.getElementById("chapters");
  root.innerHTML = CH.map((c, i) => {
    const done_ = isDone(c), unlocked = isUnlocked(i), cur = !done_ && unlocked;
    const open = openIndex === i && unlocked;
    const d = DOMAIN[c.domain];
    const cls = ["chapter", done_ ? "done" : cur ? "current" : "locked", open ? "open" : ""].join(" ");
    const node = done_ ? "✓" : unlocked ? String(c.n).padStart(2, "0") : "🔒";
    const state = done_ ? "مكتمل" : cur ? "الفصل الحالي" : "مغلق";

    if (!unlocked) {
      return `<div class="${cls}" data-i="${i}"><div class="node">${node}</div>
        <div class="ch-card"><div class="ch-head">
          <div class="meta"><div class="t">الفصل ${c.n}</div><div class="s">LOCKED</div></div>
          <div class="state">🔒 مغلق</div>
        </div>
        <div class="locked-msg">🔒 أكمل الفصل ${c.n - 1} لفتح هذا الفصل.</div></div></div>`;
    }

    const body = open ? chapterBody(c, i) : "";
    return `<div class="${cls}" data-i="${i}"><div class="node">${node}</div>
      <div class="ch-card">
        <div class="ch-head" data-act="toggle" data-i="${i}">
          <div class="meta"><div class="t">${c.n}. ${c.title}</div><div class="s">${c.en}</div></div>
          <div class="dom">${d.g} ${d.name}</div>
          <div class="state">${done_ ? "✓ " : ""}${state}</div>
          <div class="chev">▸</div>
        </div>
        ${body}
      </div></div>`;
  }).join("");
}

function chapterBody(c, i) {
  const done_ = isDone(c);
  const r = revealed[i] || 0;
  const hintsHtml = c.hints.slice(0, r).map((h, k) => `<div class="hint"><b>تلميح ${k + 1}</b>${h}</div>`).join("");
  const hintBtn = r < c.hints.length
    ? `<button class="btn ghost" data-act="hint" data-i="${i}">💡 تلميح ${r > 0 ? `(${r}/${c.hints.length})` : ""}</button>` : "";
  const actions = c.actions.map((a) =>
    `<a class="btn ${a.primary ? "primary" : ""} ${a.dl ? "dl" : ""}" href="${a.href}" ${a.dl ? "download" : 'target="_blank" rel="noopener"'}>${a.label}</a>`
  ).join("");

  return `<div class="ch-body">
    <div class="story">${c.story}</div>
    <div class="block"><div class="label">🎯 هدفك</div><div class="objective">${c.objective}</div></div>
    <details class="concept"><summary><span class="ico">📘</span> اعرف أكثر — ${esc(c.en)} (${c.learn})</summary>
      <div class="inner">${c.concept}</div></details>
    <div class="ch-actions">${actions}${hintBtn}</div>
    <div class="hints">${hintsHtml}</div>
    ${done_
      ? `<div class="stage-note ok">✓ أُنجز هذا الفصل. <span style="color:var(--muted)">${c.transition}</span></div>`
      : `<div class="stage-flag">
           <input data-flag="${i}" placeholder="ATHAR{...} ← فلاگ هذا الفصل" autocomplete="off" spellcheck="false">
           <button class="btn primary" data-act="stage-submit" data-i="${i}">تحقّق</button>
         </div><div class="stage-note" data-note="${i}"></div>`}
  </div>`;
}

// ─── التحقق من فلاگ ───
async function verify(flag) {
  const r = await fetch("/api/submit", {
    method: "POST", headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ flag: flag.trim() }),
  });
  return r.json();
}

async function submitGlobal() {
  const input = document.getElementById("flag-input");
  const msg = document.getElementById("submit-msg");
  const val = input.value.trim();
  if (!val) return;
  const d = await verify(val);
  if (d.correct) {
    const ch = CH.find((c) => c.flagId === d.id);
    solved.add(d.id); save(); input.value = "";
    openIndex = currentIndex();
    render();
    msg.className = "submit-msg ok";
    msg.textContent = `✓ صحيح! الفصل ${ch.n} «${ch.title}» — ${solved.size}/${CH.length}`;
  } else {
    msg.className = "submit-msg no";
    msg.textContent = "✗ فلاگ غير صحيح. راجع الاستخراج والتنسيق ATHAR{…}.";
  }
}

async function submitStage(i) {
  const input = document.querySelector(`input[data-flag="${i}"]`);
  const note = document.querySelector(`[data-note="${i}"]`);
  const val = (input?.value || "").trim();
  if (!val) return;
  const d = await verify(val);
  if (d.correct && d.id === CH[i].flagId) {
    solved.add(d.id); save();
    openIndex = currentIndex();
    render();
  } else if (d.correct) {
    note.className = "stage-note no";
    note.textContent = "هذا فلاگ صحيح لكنه لفصل آخر. ألصقه في شريط الأعلى.";
  } else {
    note.className = "stage-note no";
    note.textContent = "✗ فلاگ غير صحيح لهذا الفصل.";
  }
}

// ─── أحداث ───
document.getElementById("flag-submit").addEventListener("click", submitGlobal);
document.getElementById("flag-input").addEventListener("keydown", (e) => { if (e.key === "Enter") submitGlobal(); });

document.getElementById("chapters").addEventListener("click", (e) => {
  const el = e.target.closest("[data-act]");
  if (!el) return;
  const i = Number(el.dataset.i);
  const act = el.dataset.act;
  if (act === "toggle") { openIndex = openIndex === i ? -1 : i; render(); }
  else if (act === "hint") { revealed[i] = Math.min((revealed[i] || 0) + 1, CH[i].hints.length); render(); }
  else if (act === "stage-submit") submitStage(i);
});
document.getElementById("chapters").addEventListener("keydown", (e) => {
  if (e.key === "Enter" && e.target.matches("input[data-flag]")) submitStage(Number(e.target.dataset.flag));
});

render();
