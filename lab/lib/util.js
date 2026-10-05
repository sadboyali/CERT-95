// أدوات مساعدة عامة للخادم. General server helpers (no challenge secrets here).
import { createHash } from "node:crypto";

export const sha256 = (buf) => createHash("sha256").update(buf).digest("hex");

// CRC-32 (IEEE) — needed for ZIP and PNG artifact generation.
export function crc32(data) {
  let c = 0xffffffff;
  for (const b of data) {
    c ^= b;
    for (let k = 0; k < 8; k++) c = (c >>> 1) ^ ((c & 1) ? 0xedb88320 : 0);
  }
  return (c ^ 0xffffffff) >>> 0;
}

// Minimal store ZIP (no compression) — produces valid archives readable by any tool.
export function zip(files) {
  const toBuf = (v) => (typeof v === "string" ? Buffer.from(v, "utf8") : Buffer.from(v));
  const locals = [], central = [];
  let offset = 0;
  const names = Object.keys(files);
  for (const name of names) {
    const n = Buffer.from(name, "utf8");
    const data = toBuf(files[name]);
    const crc = crc32(data);
    const h = Buffer.alloc(30);
    h.writeUInt32LE(0x04034b50, 0);
    h.writeUInt16LE(20, 4);
    h.writeUInt16LE(0x0800, 6);           // UTF-8 names
    h.writeUInt32LE(crc, 14);
    h.writeUInt32LE(data.length, 18);
    h.writeUInt32LE(data.length, 22);
    h.writeUInt16LE(n.length, 26);
    locals.push(h, n, data);
    const c = Buffer.alloc(46);
    c.writeUInt32LE(0x02014b50, 0);
    c.writeUInt16LE(20, 4);
    c.writeUInt16LE(20, 6);
    c.writeUInt16LE(0x0800, 8);
    c.writeUInt32LE(crc, 16);
    c.writeUInt32LE(data.length, 20);
    c.writeUInt32LE(data.length, 24);
    c.writeUInt16LE(n.length, 28);
    c.writeUInt32LE(offset, 42);
    central.push(c, n);
    offset += h.length + n.length + data.length;
  }
  const directory = Buffer.concat(central);
  const end = Buffer.alloc(22);
  end.writeUInt32LE(0x06054b50, 0);
  end.writeUInt16LE(names.length, 8);
  end.writeUInt16LE(names.length, 10);
  end.writeUInt32LE(directory.length, 12);
  end.writeUInt32LE(offset, 16);
  return Buffer.concat([...locals, directory, end]);
}

// HTML escape — used by the SAFE parts of the app. The vulnerable endpoints
// deliberately skip it; that contrast is the teaching point.
export const esc = (s) =>
  String(s)
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#39;");

const MIME = {
  ".html": "text/html; charset=utf-8",
  ".css": "text/css; charset=utf-8",
  ".js": "text/javascript; charset=utf-8",
  ".mjs": "text/javascript; charset=utf-8",
  ".json": "application/json; charset=utf-8",
  ".svg": "image/svg+xml",
  ".png": "image/png",
  ".ico": "image/x-icon",
  ".txt": "text/plain; charset=utf-8",
  ".wasm": "application/wasm",
  ".pcap": "application/vnd.tcpdump.pcap",
  ".raw": "application/octet-stream",
  ".zip": "application/zip",
};
export const mime = (ext) => MIME[ext] || "application/octet-stream";

export function send(res, status, body, headers = {}) {
  const buf = Buffer.isBuffer(body) ? body : Buffer.from(String(body));
  res.writeHead(status, {
    "Content-Length": buf.length,
    "X-Content-Type-Options": "nosniff",
    "Cache-Control": "no-store",
    ...headers,
  });
  res.end(buf);
}

export const sendJSON = (res, status, obj, headers = {}) =>
  send(res, status, JSON.stringify(obj, null, 2), {
    "Content-Type": "application/json; charset=utf-8",
    ...headers,
  });

export const sendHTML = (res, status, html, headers = {}) =>
  send(res, status, html, { "Content-Type": "text/html; charset=utf-8", ...headers });

// Read a request body up to a cap (prevents a stray huge upload hanging the lab).
export function readBody(req, cap = 1 << 20) {
  return new Promise((resolve, reject) => {
    const chunks = [];
    let size = 0;
    req.on("data", (c) => {
      size += c.length;
      if (size > cap) { reject(new Error("body too large")); req.destroy(); return; }
      chunks.push(c);
    });
    req.on("end", () => resolve(Buffer.concat(chunks)));
    req.on("error", reject);
  });
}

// Wrap a full HTML document with the shared vulnerable-app chrome.
export function page(title, inner, { bodyClass = "" } = {}) {
  return `<!doctype html>
<html lang="ar" dir="rtl">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>${esc(title)} · MARSAD Portal</title>
<link rel="stylesheet" href="/app.css">
</head>
<body class="webapp ${bodyClass}">
<header class="wa-top">
  <a class="wa-brand" href="/web/">⬡ بوابة مرصد <small>MARSAD PORTAL</small></a>
  <nav class="wa-nav">
    <a href="/">← المختبر</a>
    <span class="wa-env">بيئة تدريب معزولة · بيانات اصطناعية</span>
  </nav>
</header>
<main class="wa-main">
${inner}
</main>
</body>
</html>`;
}
