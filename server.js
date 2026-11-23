/* =====================================================================
   KAIRO SERVER v2 — Anti-crack + Telegram Bot + Encrypted API Proxy
   Deploy Render: Start Command = node server.js
   ENV cần set trên Render:
     BOT_TOKEN  = 9027713238:AAENbDfyG_beYGT7YldXXhjuAW1CCh46AcU
     ADMIN_ID   = 7757046138
     MASTER_SECRET = (chuỗi riêng của bạn, càng dài càng tốt)
     API_HU_URL  = (url api hu gốc)
     API_MD5_URL = (url api md5 gốc)
   ===================================================================== */
'use strict';

const express = require('express');
const cors = require('cors');
const crypto = require('crypto');
const path = require('path');

/* ================== CONFIG ================== */
const PORT          = process.env.PORT || 3000;
const BOT_TOKEN     = process.env.BOT_TOKEN || '9027713238:AAENbDfyG_beYGT7YldXXhjuAW1CCh46AcU';
const ADMIN_ID      = String(process.env.ADMIN_ID || '7757046138');
const ADMIN_USER    = 'tranhoang2286';
const MASTER_SECRET = process.env.MASTER_SECRET || 'CHANGE_ME_TO_RANDOM_64_CHARS_KAIRO_2025_x9f3Kq';

const API_HU_URL  = process.env.API_HU_URL  || 'https://fictional-happiness-betf.onrender.com/api/predict/lc79/hu';
const API_MD5_URL = process.env.API_MD5_URL || 'https://fictional-happiness-betf.onrender.com/api/predict/lc79/md5';

/* ================== APP ================== */
const app = express();
app.use(cors());
app.use(express.json({ limit: '64kb' }));

/* ================== STORAGE (in-memory, chống mất khi bot restart Render
   bằng cách load/save vào biến global — vẫn mất khi restart, xem ghi chú) */
const KEYS     = new Map(); // key -> { tool, expiresAt, hwid, createdAt, maxHwid, note }
const SESSIONS = new Map(); // token -> { key, tool, hwid, expiresAt }
const NONCES   = new Map(); // nonce -> ts (chống replay)

/* ================== CRYPTO HELPERS ================== */
const SECRET_BUF = crypto.createHash('sha256').update(MASTER_SECRET).digest();

function encrypt(obj) {
  const iv = crypto.randomBytes(12);
  const c  = crypto.createCipheriv('aes-256-gcm', SECRET_BUF, iv);
  const d  = Buffer.concat([c.update(JSON.stringify(obj), 'utf8'), c.final()]);
  const t  = c.getAuthTag();
  return `${iv.toString('base64url')}.${d.toString('base64url')}.${t.toString('base64url')}`;
}
function decrypt(str) {
  const [ivB, d, t] = String(str).split('.');
  const iv = Buffer.from(ivB, 'base64url');
  const dd = Buffer.from(d,  'base64url');
  const tt = Buffer.from(t,  'base64url');
  const dc = crypto.createDecipheriv('aes-256-gcm', SECRET_BUF, iv);
  dc.setAuthTag(tt);
  return JSON.parse(Buffer.concat([dc.update(dd), dc.final()]).toString('utf8'));
}
function hmac(msg) {
  return crypto.createHmac('sha256', SECRET_BUF).update(msg).digest('hex');
}
function safeEq(a, b) {
  const A = Buffer.from(String(a));
  const B = Buffer.from(String(b));
  return A.length === B.length && crypto.timingSafeEqual(A, B);
}

/* ================== KEY UTILS ================== */
function genKey(tool) {
  const prefix = tool === 'md5' ? 'MD5' : 'HU';
  const raw = crypto.randomBytes(10).toString('hex').toUpperCase();
  return `KAIRO-${prefix}-${raw}`;
}
function newKey(tool, days, maxHwid) {
  const key = genKey(tool);
  KEYS.set(key, {
    tool,
    expiresAt: Date.now() + days * 86400000,
    createdAt: Date.now(),
    hwid: null,
    maxHwid: maxHwid || 1,
    note: ''
  });
  return key;
}
function checkKeyUsable(key, tool) {
  const k = KEYS.get(key);
  if (!k) return { ok: false, code: 'NOT_FOUND', msg: 'Key không tồn tại' };
  if (k.tool !== tool) return { ok: false, code: 'WRONG_TOOL', msg: 'Key này dùng cho tool ' + k.tool.toUpperCase() };
  if (k.expiresAt < Date.now()) return { ok: false, code: 'EXPIRED', msg: 'Key đã hết hạn' };
  return { ok: true, data: k };
}

/* ================== TELEGRAM BOT ================== */
const TG_API = `https://api.telegram.org/bot${BOT_TOKEN}`;
let tgOffset = 0;

async function tg(method, body) {
  try {
    const r = await fetch(`${TG_API}/${method}`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(body)
    });
    return await r.json();
  } catch (e) {
    console.error('[TG]', method, e.message);
    return { ok: false };
  }
}
function reply(chatId, text, extra = {}) {
  return tg('sendMessage', { chat_id: chatId, text, parse_mode: 'Markdown', ...extra });
}

function isAdmin(id) { return String(id) === ADMIN_ID; }

async function handleUpdate(u) {
  const msg = u.message || u.edited_message;
  if (!msg || !msg.text) return;
  const chatId = msg.chat.id;
  const fromId = String(msg.from.id);
  const text   = msg.text.trim();
  const parts  = text.split(/\s+/);
  const cmd    = parts[0].toLowerCase();

  // Log mọi admin action
  if (!isAdmin(fromId)) {
    if (cmd === '/start' || cmd === '/help') {
      return reply(chatId,
`🚫 *Bạn không phải admin.*
Chỉ @${ADMIN_USER} mới có quyền tạo key.`);
    }
    return;
  }

  /* ---- ADMIN COMMANDS ---- */
  if (cmd === '/start' || cmd === '/help') {
    return reply(chatId,
`🔥 *KAIRO ADMIN BOT* 🔥

*TẠO KEY:*
\`/newkey <hu|md5> <số_ngày> [số_thiết_bị]\`
Ví dụ: \`/newkey hu 7 1\`

*LIỆT KÊ KEY:*
\`/listkey\`  hoặc \`/listkey hu\`

*XOÁ KEY:*
\`/delkey <KEY>\`
\`/delkey all\`  — xoá tất cả
\`/delkey expired\` — xoá key hết hạn

*THÔNG TIN KEY:*
\`/info <KEY>\`

*RESET HWID (khi user đổi máy):*
\`/resethwid <KEY>\`

*GIA HẠN:*
\`/extend <KEY> <số_ngày>\`

*THỐNG KÊ:*
\`/stats\``);
  }

  if (cmd === '/newkey') {
    const tool = (parts[1] || 'hu').toLowerCase();
    const days = parseInt(parts[2] || '7');
    const maxHwid = parseInt(parts[3] || '1');
    if (!['hu','md5'].includes(tool)) return reply(chatId, '❌ tool phải là `hu` hoặc `md5`');
    if (!days || days < 1 || days > 365) return reply(chatId, '❌ số ngày 1–365');
    const key = newKey(tool, days, maxHwid);
    return reply(chatId,
`✅ *KEY MỚI ĐÃ TẠO*
\`\`\`
${key}
\`\`\`
🎯 Tool: *${tool.toUpperCase()}*
⏱ Hết hạn: *${days} ngày*
📱 Số thiết bị: *${maxHwid}*`);
  }

  if (cmd === '/listkey') {
    const filter = (parts[1] || '').toLowerCase();
    const arr = [...KEYS.entries()].filter(([,v]) => !filter || v.tool === filter);
    if (!arr.length) return reply(chatId, '📭 Không có key nào');
    const lines = arr.map(([k,v]) => {
      const left = Math.max(0, Math.ceil((v.expiresAt - Date.now())/86400000));
      const status = v.expiresAt < Date.now() ? '💀' : '✅';
      return `${status} \`${k}\` | ${v.tool.toUpperCase()} | còn ${left}d`;
    });
    return reply(chatId, `📋 *DANH SÁCH KEY (${arr.length})*\n\n` + lines.slice(0,40).join('\n') +
      (lines.length > 40 ? `\n... +${lines.length-40} key nữa` : ''));
  }

  if (cmd === '/delkey') {
    const target = parts.slice(1).join(' ').trim();
    if (!target) return reply(chatId, '❌ `/delkey <KEY>` | `all` | `expired`');
    if (target.toLowerCase() === 'all') {
      const n = KEYS.size; KEYS.clear();
      return reply(chatId, `🗑 Đã xoá *${n}* key`);
    }
    if (target.toLowerCase() === 'expired') {
      let n = 0;
      for (const [k,v] of KEYS) if (v.expiresAt < Date.now()) { KEYS.delete(k); n++; }
      return reply(chatId, `🗑 Đã xoá *${n}* key hết hạn`);
    }
    if (!KEYS.has(target)) return reply(chatId, '❌ Key không tồn tại');
    KEYS.delete(target);
    // Xoá luôn session dính key
    for (const [t, s] of SESSIONS) if (s.key === target) SESSIONS.delete(t);
    return reply(chatId, `🗑 Đã xoá key \`${target}\``);
  }

  if (cmd === '/info') {
    const key = parts[1];
    if (!key) return reply(chatId, '❌ `/info <KEY>`');
    const k = KEYS.get(key);
    if (!k) return reply(chatId, '❌ Key không tồn tại');
    const left = Math.max(0, Math.ceil((k.expiresAt - Date.now())/86400000));
    return reply(chatId,
`🔎 *THÔNG TIN KEY*
\`${key}\`
🎯 Tool: *${k.tool.toUpperCase()}*
⏱ Còn: *${left} ngày* (${new Date(k.expiresAt).toLocaleString('vi-VN')})
📱 HWID: *${k.hwid || 'chưa khóa'}* (max ${k.maxHwid})
📅 Tạo: ${new Date(k.createdAt).toLocaleString('vi-VN')}`);
  }

  if (cmd === '/resethwid') {
    const key = parts[1];
    const k = KEYS.get(key);
    if (!k) return reply(chatId, '❌ Key không tồn tại');
    k.hwid = null;
    return reply(chatId, `♻️ Đã reset HWID cho \`${key}\``);
  }

  if (cmd === '/extend') {
    const key = parts[1];
    const days = parseInt(parts[2] || '0');
    const k = KEYS.get(key);
    if (!k) return reply(chatId, '❌ Key không tồn tại');
    if (!days || days < 1) return reply(chatId, '❌ số ngày > 0');
    k.expiresAt = Math.max(k.expiresAt, Date.now()) + days * 86400000;
    return reply(chatId, `⏱ Đã cộng *${days} ngày* cho \`${key}\``);
  }

  if (cmd === '/stats') {
    let active = 0, expired = 0, hu = 0, md5 = 0;
    for (const k of KEYS.values()) {
      if (k.expiresAt < Date.now()) expired++; else active++;
      if (k.tool === 'hu') hu++; else md5++;
    }
    return reply(chatId,
`📊 *THỐNG KÊ*
🔑 Tổng key: *${KEYS.size}*
✅ Active: *${active}*
💀 Hết hạn: *${expired}*
🎯 HŨ: *${hu}* | MD5: *${md5}*
👥 Session: *${SESSIONS.size}*`);
  }

  return reply(chatId, '❓ Lệnh không hợp lệ. Gõ /help');
}

async function botLoop() {
  try {
    const r = await fetch(`${TG_API}/getUpdates?offset=${tgOffset}&timeout=25`);
    const j = await r.json();
    if (j.ok && j.result.length) {
      for (const u of j.result) {
        tgOffset = u.update_id + 1;
        handleUpdate(u).catch(e => console.error('[HANDLE]', e.message));
      }
    }
  } catch (e) {
    console.error('[BOT LOOP]', e.message);
  }
  setTimeout(botLoop, 1500);
}

/* ================== MIDDLEWARE ================== */
function adminAuth(req, res, next) {
  // Chỉ dùng cho endpoint nội bộ — HTML không bao giờ gọi admin routes
  const id = req.headers['x-tg-id'] || req.query.id;
  if (!isAdmin(id)) return res.status(403).json({ ok: false });
  next();
}

function requireTool(tool) {
  return (req, res, next) => {
    const auth = req.headers['authorization'] || '';
    const token = auth.startsWith('Bearer ') ? auth.slice(7) : '';
    const sig   = req.headers['x-kairo'] || '';
    const nonce = req.headers['x-nonce'] || '';

    if (!token || !sig || !nonce) return res.status(401).json({ ok: false, msg: 'missing' });

    // Chống replay
    if (NONCES.has(nonce)) return res.status(409).json({ ok: false, msg: 'replay' });
    NONCES.set(nonce, Date.now());
    // Dọn nonce cũ > 60s
    if (NONCES.size > 5000) {
      const cut = Date.now() - 60000;
      for (const [n, ts] of NONCES) if (ts < cut) NONCES.delete(n);
    }

    // Verify HMAC: token|tool|nonce
    if (!safeEq(sig, hmac(token + '|' + tool + '|' + nonce))) {
      return res.status(403).json({ ok: false, msg: 'bad sig' });
    }

    const s = SESSIONS.get(token);
    if (!s || s.tool !== tool || s.expiresAt < Date.now()) {
      return res.status(403).json({ ok: false, msg: 'session' });
    }
    const ck = checkKeyUsable(s.key, tool);
    if (!ck.ok) return res.status(403).json({ ok: false, msg: ck.code });

    // Kiểm tra HWID thực tế
    const hwid = req.headers['x-hwid'] || '';
    if (!hwid || hwid !== s.hwid) return res.status(403).json({ ok: false, msg: 'hwid' });

    req.kairo = { token, key: s.key, tool };
    next();
  };
}

/* ================== ENDPOINTS ================== */

/* 1. Bootstrap: HTML gọi 1 lần để lấy config đã mã hoá */
app.get('/api/bootstrap', (req, res) => {
  const payload = {
    ts: Date.now(),
    sigAlg: 'HMAC-SHA256-AES-GCM',
    endpoints: { hu: '/api/tool/hu', md5: '/api/tool/md5' },
    activate: '/api/activate',
    version: '2.0'
  };
  res.type('text/plain').send(encrypt(payload));
});

/* 2. Activate key -> trả session (mã hoá) */
app.post('/api/activate', (req, res) => {
  const { key, tool, hwid } = req.body || {};
  if (!key || !tool || !hwid) {
    return res.status(400).json({ ok: false, msg: 'Thiếu key/tool/hwid' });
  }
  if (!['hu','md5'].includes(tool)) {
    return res.status(400).json({ ok: false, msg: 'tool phải hu|md5' });
  }
  const ck = checkKeyUsable(key, tool);
  if (!ck.ok) return res.status(403).json({ ok: false, msg: ck.msg });

  // HWID lock
  const k = ck.data;
  if (!k.hwid) {
    k.hwid = String(hwid).slice(0, 128);
  } else if (k.hwid !== String(hwid)) {
    return res.status(403).json({ ok: false, msg: 'Key đã khóa vào thiết bị khác. Liên hệ @' + ADMIN_USER + ' để reset.' });
  }

  const token = crypto.randomBytes(24).toString('base64url');
  SESSIONS.set(token, {
    key,
    tool,
    hwid: k.hwid,
    expiresAt: k.expiresAt
  });

  res.type('text/plain').send(encrypt({
    token,
    tool,
    hwid: k.hwid,
    expiresAt: k.expiresAt,
    serverTime: Date.now()
  }));
});

/* 3. Tool proxy (yêu cầu key + sig + hwid + nonce) */
async function proxy(url, res, label) {
  try {
    const r = await fetch(url + '?_=' + Date.now(), { cache: 'no-store' });
    if (!r.ok) throw new Error('upstream ' + r.status);
    const j = await r.json();
    res.json(j);
  } catch (e) {
    res.status(502).json({ ok: false, msg: label + ' lỗi: ' + e.message });
  }
}
app.get('/api/tool/hu',  requireTool('hu'),  (req, res) => proxy(API_HU_URL,  res, 'HU'));
app.get('/api/tool/md5', requireTool('md5'), (req, res) => proxy(API_MD5_URL, res, 'MD5'));

/* 4. Health */
app.get('/api/health', (req, res) => res.json({
  ok: true, ts: Date.now(), keys: KEYS.size, sessions: SESSIONS.size
}));

/* 5. Trang chủ serve HTML */
app.get('/', (req, res) => res.sendFile(path.join(__dirname, 'index.html')));
app.get('/index.html', (req, res) => res.sendFile(path.join(__dirname, 'index.html')));

/* ================== START ================== */
app.listen(PORT, () => {
  console.log(`[KAIRO] Server on :${PORT}`);
  console.log(`[KAIRO] Admin ID: ${ADMIN_ID}`);
  console.log(`[KAIRO] Bot polling starting...`);
  botLoop();
});
