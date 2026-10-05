// ─────────────────────────────────────────────────────────────────────────
// أسرار الخادم فقط — لا تُستورد أبداً في كود يصل للمتصفح.
// Server-only secrets. Never imported into client-reachable bundles.
//
// كل فلاگ هو "جائزة" حل تحدٍّ واحد. يظهر الفلاگ فقط عند الاستغلال الناجح
// (ويب) أو عند استعادة النص الأصلي بعد التحليل (تشفير/عكسية/فورنسِك).
// Each flag is the reward for one challenge, revealed only on successful
// exploitation (web) or recovery of plaintext (crypto / reverse / forensics).
// ─────────────────────────────────────────────────────────────────────────

export const FLAGS = {
  // 🌐 WEB
  "web-sqli":       "ATHAR{sqli_un10n_l34ks_th3_4dm1n}",
  "web-xss":        "ATHAR{r3fl3ct3d_x55_st34ls_th3_c00k13}",
  "web-access":     "ATHAR{1d0r_plus_h77p_p4r4m_p0llut10n}",
  "web-cmdi":       "ATHAR{c0mm4nd_1nj3ct10n_ch41n3d}",
  "web-traversal":  "ATHAR{d0t_d0t_sl4sh_3sc4p3d_th3_r00t}",

  // 🔐 CRYPTO
  "crypto-xor":     "ATHAR{r3p3471ng_k3y_x0r_1s_n0t_s3cur3}",
  "crypto-ctr":     "ATHAR{ctr_n0nc3_r3us3_1s_4_tw0_71m3_p4d}",
  "crypto-ecb":     "ATHAR{byt3_47_4_71m3_3cb_0r4cl3_pwn}",

  // ⚙️ REVERSE ENGINEERING
  "rev-wasm":       "ATHAR{w3b4ss3mbly_r3v3rs3d_w17h0u7_7h3_ui}",
  "rev-js":         "ATHAR{d30bfusc473d_7h3_l1c3ns3_k3yg3n}",

  // 🔬 FORENSICS
  "forensics-carve":"ATHAR{f1l3_c4rv1ng_fr0m_4_r4w_dump}",
  "forensics-stego":"ATHAR{lsb_s73g0_h1dd3n_1n_pl41n_p1x3ls}",
  "forensics-pcap": "ATHAR{cr3d3n714ls_l34k3d_1n_7h3_pc4p}",
};

// بيانات وصفية للعرض في الواجهة وموقع الحلول (لا تحتوي الأسرار).
// Display metadata for the UI and solutions site (no secrets here).
export const META = {
  "web-sqli":       { domain: "web",       level: 2, title: "الباب المنسي",        en: "SQL Injection" },
  "web-xss":        { domain: "web",       level: 2, title: "مرآة الإدخال",         en: "Cross-Site Scripting" },
  "web-access":     { domain: "web",       level: 3, title: "مفتاح في المكان الخطأ", en: "Broken Access Control (IDOR + HPP)" },
  "web-cmdi":       { domain: "web",       level: 3, title: "خلف الأمر",            en: "Command Injection" },
  "web-traversal":  { domain: "web",       level: 2, title: "خارج الجذر",           en: "Path Traversal" },
  "crypto-xor":     { domain: "crypto",    level: 1, title: "المفتاح المتكرر",       en: "Repeating-Key XOR" },
  "crypto-ctr":     { domain: "crypto",    level: 3, title: "الصدى المزدوج",         en: "CTR Nonce Reuse" },
  "crypto-ecb":     { domain: "crypto",    level: 3, title: "بايت تلو الآخر",        en: "ECB Byte-at-a-Time Oracle" },
  "rev-wasm":       { domain: "reverse",   level: 3, title: "خلف التعليمات",         en: "WebAssembly Validator" },
  "rev-js":         { domain: "reverse",   level: 2, title: "المفتاح المموَّه",       en: "Obfuscated JS Keygen" },
  "forensics-carve":{ domain: "forensics", level: 2, title: "ذاكرة لا تُنسى",        en: "File Carving" },
  "forensics-stego":{ domain: "forensics", level: 2, title: "الصورة الصامتة",        en: "LSB Steganography" },
  "forensics-pcap": { domain: "forensics", level: 2, title: "همس الشبكة",           en: "PCAP Credential Extraction" },
};

export const flagList = () => Object.keys(FLAGS);
