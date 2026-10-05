// ─────────────────────────────────────────────────────────────────────────
// مولّدات ملفات التحديات القابلة للتنزيل (تشفير / هندسة عكسية / فورنسِك).
// Generators for the downloadable challenge artifacts.
//
// تُنشأ الملفات مرة واحدة عند تشغيل الخادم داخل lab/challenges/.
// تحتوي الأسرار (الفلاگات) مغروسة بشكل يُستعاد فقط بعد التحليل الصحيح.
// ─────────────────────────────────────────────────────────────────────────
import { createCipheriv } from "node:crypto";
import zlib from "node:zlib";
import { writeFileSync, mkdirSync } from "node:fs";
import { join } from "node:path";
import { FLAGS } from "./flags.js";
import { zip, crc32, sha256 } from "./util.js";

const B = (s) => Buffer.from(s, "utf8");

// ═══════════════════════════════ CRYPTO ═══════════════════════════════════

// 1) Repeating-key XOR — مفتاح قصير متكرر على نص إنجليزي واضح.
function xorChallenge() {
  const plaintext =
    "FIELD NOTE — MARSAD ARCHIVE INCIDENT MR-024.\n" +
    "The night shift reported that the handover log stopped updating at 02:17.\n" +
    "No door was forced; a key was simply used in the wrong place.\n" +
    "Reusing a short secret across every line is the same mistake, twice.\n" +
    "For the record, the recovered vault token reads: " + FLAGS["crypto-xor"] + "\n" +
    "Rotate the credential and retire this channel before the next cycle.\n";
  const key = B("marsad");
  const ct = Buffer.alloc(plaintext.length);
  for (let i = 0; i < plaintext.length; i++) ct[i] = plaintext.charCodeAt(i) ^ key[i % key.length];
  const readme =
    "MARSAD / intercepted note (crypto-xor)\n" +
    "======================================\n" +
    "The file cipher.hex is ASCII text encrypted with a repeating-key XOR.\n" +
    "The key is a short lowercase word. The plaintext is an English memo.\n" +
    "Recover the plaintext; the flag is one of its lines.\n";
  return {
    "cipher.hex": ct.toString("hex").replace(/(.{64})/g, "$1\n") + "\n",
    "README.txt": readme,
  };
}

// 2) AES-256-CTR nonce/counter reuse — نفس المفتاح والعدّاد لرسالتين (two-time pad).
function ctrChallenge() {
  const known =
    "MARSAD/1\nkind=heartbeat\nfrom=relay-07\nto=archive-02\nstatus=healthy\n".padEnd(192, ".");
  const secret =
    `MARSAD/1\nkind=handover\nnote=rotate-now\nvault_token=${FLAGS["crypto-ctr"]}\n`.padEnd(192, ".");
  // مفتاح وعدّاد ثابتان ومُعاد استخدامهما عمداً عبر الإطارين.
  const key = Buffer.alloc(32, 0); B("relay-07-master-key-DO-NOT-REUSE").copy(key);
  const iv = Buffer.alloc(16, 0); B("relay-counter-01").copy(iv);
  const enc = (m) => {
    const c = createCipheriv("aes-256-ctr", key, iv);
    return Buffer.concat([c.update(B(m)), c.final()]).toString("hex");
  };
  const channel = {
    algorithm: "AES-256-CTR",
    counter_bits: 128,
    encoding: "hex",
    note: "two frames captured off relay-07",
    frames: [
      { id: "health",   key_id: "relay-key-07", counter: iv.toString("hex"), ciphertext: enc(known) },
      { id: "handover", key_id: "relay-key-07", counter: iv.toString("hex"), ciphertext: enc(secret) },
    ],
  };
  const protocol =
    "MARSAD/1 heartbeat template (UTF-8, LF only):\n" +
    "---BEGIN---\n" + known + "\n---END---\n" +
    "Every frame is exactly 192 bytes, padded with '.' and no trailing LF.\n" +
    "The 'health' frame follows this template verbatim.\n" +
    "Both frames share key_id and counter. Recover the 'handover' frame.\n";
  return {
    "channel.json": JSON.stringify(channel, null, 2) + "\n",
    "protocol.txt": protocol,
  };
}

// ═══════════════════════ REVERSE ENGINEERING ══════════════════════════════

// WebAssembly validator — يبني وحدة فعلية تقبل بايتات الفلاگ فقط.
const uleb = (n) => { const a = []; do { let b = n & 127; n >>>= 7; if (n) b |= 128; a.push(b); } while (n); return a; };
const sleb = (n) => { const a = []; let more = true; while (more) { let b = n & 127; n >>= 7; more = !((n === 0 && (b & 64) === 0) || (n === -1 && (b & 64) !== 0)); if (more) b |= 128; a.push(b); } return a; };
const wstr = (s) => [...uleb(B(s).length), ...B(s)];
const wsec = (id, data) => [id, ...uleb(data.length), ...data];

const WASM_SALT = 0x9e3779b1; // ثابت معروف، مذكور في README الخاص بالتحدي.

function buildWasm(value, salt) {
  const table = Array(value.length).fill(0);
  let prev = 0x5a;
  for (let i = 0; i < value.length; i++) {
    const x = ((value[i] ^ ((salt >>> ((i % 4) * 8)) & 255)) + i * 17) & 255;
    const v = (((x << 3) | (x >>> 5)) & 255) ^ prev;
    table[(i * 5) % value.length] = v;
    prev = v;
  }
  const c = (n) => [0x41, ...sleb(n)];
  const load = (addr) => [...c(addr), 0x2d, 0, 0];
  const code = [1, 1, 0x7f, 0x20, 1, ...c(value.length), 0x47, 0x04, 0x40, ...c(0), 0x0f, 0x0b];
  for (let i = 0; i < value.length; i++)
    code.push(
      0x20, 0, ...c(i), 0x6a, 0x2d, 0, 0, 0x23, 0, ...c((i % 4) * 8), 0x76, ...c(255), 0x71, 0x73,
      ...c(i * 17), 0x6a, ...c(255), 0x71, 0x22, 2, ...c(3), 0x74, 0x20, 2, ...c(5), 0x76, 0x72, ...c(255), 0x71,
      ...(i === 0 ? c(0x5a) : load(1024 + ((i - 1) * 5) % value.length)), 0x73,
      ...load(1024 + (i * 5) % value.length), 0x47, 0x04, 0x40, ...c(0), 0x0f, 0x0b
    );
  code.push(...c(1), 0x0b);
  return Buffer.from([
    0, 97, 115, 109, 1, 0, 0, 0,
    ...wsec(1, [1, 0x60, 2, 0x7f, 0x7f, 1, 0x7f]),
    ...wsec(2, [1, ...wstr("env"), ...wstr("salt"), 3, 0x7f, 0]),
    ...wsec(3, [1, 0]),
    ...wsec(5, [1, 0, 1]),
    ...wsec(7, [2, ...wstr("memory"), 2, 0, ...wstr("validate"), 0, 0]),
    ...wsec(10, [1, ...uleb(code.length), ...code]),
    ...wsec(11, [1, 0, ...c(1024), 0x0b, ...uleb(table.length), ...table]),
  ]);
}

function wasmChallenge() {
  const wasm = buildWasm(B(FLAGS["rev-wasm"]), WASM_SALT);
  const readme =
    "MARSAD gate / WebAssembly validator (rev-wasm)\n" +
    "==============================================\n" +
    "Exports: memory, validate(ptr: i32, len: i32) -> 1 (accept) or 0 (reject).\n" +
    `Import:  env.salt — an immutable i32 global. Its value is ${WASM_SALT} (0x${WASM_SALT.toString(16)}).\n` +
    "Place your UTF-8 candidate at memory offset 0, then call validate(0, length).\n" +
    "A shuffled comparison table lives in memory starting at offset 1024.\n" +
    "\n" +
    "The accepted string IS the flag. Reverse the per-byte transform and the\n" +
    "table shuffle to reconstruct it — do not brute force.\n" +
    "\n" +
    "Run locally:  node run.mjs \"<candidate>\"\n";
  const run =
    "// Harness: node run.mjs \"<candidate>\"\n" +
    "import { readFile } from 'node:fs/promises';\n" +
    `const SALT = ${WASM_SALT};\n` +
    "const candidate = process.argv[2];\n" +
    "if (!candidate) { console.error('Usage: node run.mjs \"<candidate>\"'); process.exit(1); }\n" +
    "const bin = await readFile(new URL('./verifier.wasm', import.meta.url));\n" +
    "const { instance } = await WebAssembly.instantiate(bin, {\n" +
    "  env: { salt: new WebAssembly.Global({ value: 'i32', mutable: false }, SALT | 0) },\n" +
    "});\n" +
    "const bytes = new TextEncoder().encode(candidate);\n" +
    "if (bytes.length > 512) throw new Error('input too long');\n" +
    "new Uint8Array(instance.exports.memory.buffer).set(bytes, 0);\n" +
    "const ok = instance.exports.validate(0, bytes.length) === 1;\n" +
    "console.log(ok ? 'ACCEPTED ✓' : 'REJECTED ✗');\n";
  return { "verifier.wasm": wasm, "run.mjs": run, "README.txt": readme };
}

// Obfuscated JS keygen — دالة check مموّهة بمصفوفة سلاسل وتحويلات بايت.
function jsChallenge() {
  const flag = FLAGS["rev-js"];
  // نفس منطق التحقق المموّه، نحسب جدول الهدف هنا من الفلاگ.
  const target = [];
  for (let i = 0; i < flag.length; i++) {
    let c = flag.charCodeAt(i);
    c = ((c + i * 7) ^ 0x5a) & 0xff;        // step 1: add positional, XOR 0x5a
    c = ((c << 1) | (c >>> 7)) & 0xff;      // step 2: rotate-left 1
    target.push(c);
  }
  const targetHex = Buffer.from(target).toString("hex");
  // تمويه: مصفوفة سلاسل بإزاحة، أسماء قصيرة، ثوابت ست عشرية، الهدف كسلسلة hex.
  const licence =
`(function(){
  var _0x=['charCodeAt','length','fromCharCode','push','log'];
  function _r(_a){return _0x[_a-0x1a7]}
  var _t='${targetHex}';
  function _h(s){var o=[];for(var i=0;i<s[_r(0x1a8)];i+=0x2)o[_r(0x1aa)](parseInt(s.substr(i,0x2),0x10));return o}
  function _v(_k){
    var _g=_h(_t);
    if(_k[_r(0x1a8)]!==_g[_r(0x1a8)])return!0x1;
    for(var _i=0x0;_i<_k[_r(0x1a8)];_i++){
      var _c=_k[_r(0x1a7)](_i);
      _c=((_c+_i*0x7)^0x5a)&0xff;
      _c=((_c<<0x1)|(_c>>>0x7))&0xff;
      if(_c!==_g[_i])return!0x1;
    }
    return!0x0;
  }
  if(typeof module!=='undefined')module.exports={check:_v};
  if(typeof globalThis!=='undefined')globalThis.check=_v;
})();`;
  const run =
    "// Harness: node run.mjs \"<candidate>\"\n" +
    "import { createRequire } from 'node:module';\n" +
    "const require = createRequire(import.meta.url);\n" +
    "const { check } = require('./licence.js');\n" +
    "const k = process.argv[2];\n" +
    "if (!k) { console.error('Usage: node run.mjs \"<candidate>\"'); process.exit(1); }\n" +
    "console.log(check(k) ? 'VALID LICENCE ✓' : 'INVALID ✗');\n";
  const readme =
    "MARSAD licence check (rev-js)\n" +
    "=============================\n" +
    "licence.js exports check(key) -> true only for the correct licence key.\n" +
    "The key IS the flag. The checker is obfuscated; deobfuscate it, read the\n" +
    "transform, and invert the embedded target table. Do not brute force.\n" +
    "\n" +
    "Run locally:  node run.mjs \"<candidate>\"\n";
  return { "licence.js": licence, "run.mjs": run, "README.txt": readme };
}

// ═══════════════════════════════ FORENSICS ════════════════════════════════

// 1) File carving — صورة خام فيها أرشيف ZIP مغروس (مع آخر مُضلِّل).
function carveChallenge() {
  const raw = Buffer.alloc(65536);
  // ضجيج شبه-عشوائي حتمي حتى يبدو كالتقاط ذاكرة.
  const seed = Buffer.from(sha256("mr-024-capture"), "hex");
  for (let i = 0; i < raw.length; i++) raw[i] = (seed[i % 32] + i * 29 + (i >>> 8)) & 255;
  raw.write("MRSD CAPTURE ENVELOPE v1\nSnapshot: 2026-09-18T23:23:00Z\n", 0);

  // أرشيف حقيقي يحمل الفلاگ (base64 ليجبر المحلّل على خطوة فك إضافية).
  const payload =
    "MARSAD evidence handover\n" +
    "case=MR-024\n" +
    "The vault token survived outside the index:\n" +
    Buffer.from(FLAGS["forensics-carve"]).toString("base64") + "\n";
  const real = zip({
    "evidence/handover.txt": payload,
    "evidence/mail.eml":
      "From: relay@marsad.invalid\r\nTo: archive@marsad.invalid\r\n" +
      "Subject: handover\r\nContent-Transfer-Encoding: base64\r\n\r\n" +
      "The token in handover.txt is Base64; decode it once.\r\n",
  });
  // أرشيف مُضلِّل (معايرة قديمة مرفوضة).
  const decoy = zip({ "readme.txt": "Calibration snapshot, 2025. Rejected evidence.\n" });

  decoy.copy(raw, 0x0800);
  real.copy(raw, 0x5200);
  const sum = sha256(raw);
  return {
    "capture.raw": raw,
    "SHA256SUMS": `${sum}  capture.raw\n`,
    "custody.txt":
      "Case MR-024 | Synthetic evidence\n" +
      "Acquired 2026-09-18T23:23:00Z. Preserve the original; analyse a copy.\n" +
      "This is a raw media/memory envelope, not a mountable filesystem.\n" +
      "The catalogue was lost. Archived records may survive outside the index.\n" +
      "Look for embedded file signatures (ZIP local header = PK\\x03\\x04).\n",
  };
}

// 2) LSB steganography — PNG حقيقي، الفلاگ مخبّأ في أقل بت من كل قناة.
function encodePNG(width, height, rgb) {
  const chunk = (type, data) => {
    const t = Buffer.from(type, "ascii");
    const len = Buffer.alloc(4); len.writeUInt32BE(data.length, 0);
    const body = Buffer.concat([t, data]);
    const crc = Buffer.alloc(4); crc.writeUInt32BE(crc32(body), 0);
    return Buffer.concat([len, body, crc]);
  };
  const stride = width * 3;
  const raw = Buffer.alloc((stride + 1) * height);
  for (let y = 0; y < height; y++) {
    raw[y * (stride + 1)] = 0; // filter type: None
    rgb.copy(raw, y * (stride + 1) + 1, y * stride, y * stride + stride);
  }
  const idat = zlib.deflateSync(raw, { level: 9 });
  const ihdr = Buffer.alloc(13);
  ihdr.writeUInt32BE(width, 0); ihdr.writeUInt32BE(height, 4);
  ihdr[8] = 8; ihdr[9] = 2; ihdr[10] = 0; ihdr[11] = 0; ihdr[12] = 0; // 8-bit RGB
  return Buffer.concat([
    Buffer.from([137, 80, 78, 71, 13, 10, 26, 10]),
    chunk("IHDR", ihdr), chunk("IDAT", idat), chunk("IEND", Buffer.alloc(0)),
  ]);
}

function stegoChallenge() {
  const W = 96, H = 96;
  const rgb = Buffer.alloc(W * H * 3);
  // تدرّج لوني لطيف ليبدو كصورة حقيقية.
  for (let y = 0; y < H; y++)
    for (let x = 0; x < W; x++) {
      const o = (y * W + x) * 3;
      rgb[o] = (x * 255 / W) | 0;
      rgb[o + 1] = (y * 255 / H) | 0;
      rgb[o + 2] = ((x + y) * 255 / (W + H)) | 0;
    }
  // الرسالة = طول 32-بت (big-endian) + بايتات الفلاگ. تُغرس في LSB تسلسلياً.
  const flag = Buffer.from(FLAGS["forensics-stego"]);
  const header = Buffer.alloc(4); header.writeUInt32BE(flag.length, 0);
  const message = Buffer.concat([header, flag]);
  let bit = 0;
  for (let i = 0; i < message.length; i++)
    for (let b = 7; b >= 0; b--) {
      const value = (message[i] >> b) & 1;
      rgb[bit] = (rgb[bit] & 0xfe) | value;
      bit++;
    }
  const png = encodePNG(W, H, rgb);
  const readme =
    "MARSAD media / cover image (forensics-stego)\n" +
    "============================================\n" +
    "cover.png looks like a plain gradient. A message is hidden in the least\n" +
    "significant bit of each colour byte, in row-major R,G,B order.\n" +
    "Layout: first 32 bits = big-endian message length (bytes), then the bytes.\n" +
    "Decode the LSB plane to recover the flag.\n";
  return { "cover.png": png, "README.txt": readme };
}

// 3) PCAP — التقاط شبكة فيه طلب تسجيل دخول بكلمة مرور = الفلاگ.
function buildPcap(packets) {
  const gh = Buffer.alloc(24);
  gh.writeUInt32LE(0xa1b2c3d4, 0);   // magic
  gh.writeUInt16LE(2, 4); gh.writeUInt16LE(4, 6); // version 2.4
  gh.writeInt32LE(0, 8); gh.writeUInt32LE(0, 12); // thiszone, sigfigs
  gh.writeUInt32LE(65535, 16);       // snaplen
  gh.writeUInt32LE(1, 20);           // network = Ethernet
  const parts = [gh];
  let ts = 1758232620; // 2025-09-18-ish
  for (const pkt of packets) {
    const rec = Buffer.alloc(16);
    rec.writeUInt32LE(ts, 0); rec.writeUInt32LE(0, 4);
    rec.writeUInt32LE(pkt.length, 8); rec.writeUInt32LE(pkt.length, 12);
    parts.push(rec, pkt); ts += 1;
  }
  return Buffer.concat(parts);
}

function tcpSegment(src, dst, sport, dport, seq, ack, flags, payload) {
  const pl = Buffer.from(payload);
  const tcp = Buffer.alloc(20);
  tcp.writeUInt16BE(sport, 0); tcp.writeUInt16BE(dport, 2);
  tcp.writeUInt32BE(seq >>> 0, 4); tcp.writeUInt32BE(ack >>> 0, 8);
  tcp[12] = 5 << 4; tcp[13] = flags; tcp.writeUInt16BE(0xffff, 14);
  const ip = Buffer.alloc(20);
  ip[0] = 0x45; ip.writeUInt16BE(20 + 20 + pl.length, 2);
  ip.writeUInt16BE(0x4000, 6); ip[8] = 64; ip[9] = 6;
  Buffer.from(src.split(".").map(Number)).copy(ip, 12);
  Buffer.from(dst.split(".").map(Number)).copy(ip, 16);
  let sum = 0; for (let i = 0; i < 20; i += 2) sum += ip.readUInt16BE(i);
  while (sum >> 16) sum = (sum & 0xffff) + (sum >> 16);
  ip.writeUInt16BE((~sum) & 0xffff, 10);
  const eth = Buffer.alloc(14);
  Buffer.from([0x02, 0, 0, 0, 0, 0x02]).copy(eth, 0);
  Buffer.from([0x02, 0, 0, 0, 0, 0x01]).copy(eth, 6);
  eth.writeUInt16BE(0x0800, 12);
  return Buffer.concat([eth, ip, tcp, pl]);
}

function pcapChallenge() {
  const body = `username=analyst&password=${FLAGS["forensics-pcap"]}`;
  const request =
    "POST /api/login HTTP/1.1\r\n" +
    "Host: archive.marsad.invalid\r\n" +
    "User-Agent: marsad-client/1.0\r\n" +
    "Content-Type: application/x-www-form-urlencoded\r\n" +
    `Content-Length: ${Buffer.byteLength(body)}\r\n\r\n` + body;
  const response =
    "HTTP/1.1 200 OK\r\n" +
    "Content-Type: application/json\r\n" +
    "Server: marsad-gw\r\n\r\n" +
    '{"status":"authenticated","role":"analyst","mfa":false}';
  const C = "10.8.0.17", S = "10.8.0.3";
  const packets = [
    tcpSegment(C, S, 49201, 80, 1000, 1, 0x02, ""),                       // SYN
    tcpSegment(S, C, 80, 49201, 1, 1001, 0x12, ""),                       // SYN-ACK
    tcpSegment(C, S, 49201, 80, 1001, 2, 0x18, request),                  // PSH-ACK request
    tcpSegment(S, C, 80, 49201, 2, 1001 + request.length, 0x18, response),// PSH-ACK response
  ];
  return {
    "capture.pcap": buildPcap(packets),
    "README.txt":
      "MARSAD network capture (forensics-pcap)\n" +
      "=======================================\n" +
      "capture.pcap holds one short TCP conversation with the archive gateway.\n" +
      "Open it in Wireshark (Follow TCP Stream) or run strings/tshark on it.\n" +
      "An analyst authenticated over plaintext HTTP. Recover the credential.\n",
  };
}

// ═══════════════════════════ WRITE TO DISK ════════════════════════════════

export function generateArtifacts(root) {
  const groups = {
    "crypto-xor": xorChallenge(),
    "crypto-ctr": ctrChallenge(),
    "reverse/wasm": wasmChallenge(),
    "reverse/js": jsChallenge(),
    "forensics/carve": carveChallenge(),
    "forensics/stego": stegoChallenge(),
    "forensics/pcap": pcapChallenge(),
  };
  for (const [sub, files] of Object.entries(groups)) {
    const dir = join(root, sub);
    mkdirSync(dir, { recursive: true });
    for (const [name, data] of Object.entries(files)) {
      writeFileSync(join(dir, name.replaceAll("/", "__")), Buffer.isBuffer(data) ? data : Buffer.from(data));
    }
  }
  return Object.keys(groups);
}
