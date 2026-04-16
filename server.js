// server.js
const fs = require("fs");
const path = require("path");
require("dotenv").config();
const bcrypt = require("bcryptjs");
const express = require("express");
const cookieParser = require("cookie-parser");
const QRCode = require("qrcode");
const crypto = require("crypto");
const FormData = require("form-data");
const { createCanvas, loadImage } = require("canvas");
const db = require("./db");

const app = express();

// ====== body + cookies ======
app.use(express.json({ limit: "1mb" }));
app.use(express.urlencoded({ extended: true }));
app.use(cookieParser());

// ====== Simple auth (đủ dùng nội bộ) ======
const USERS = {
  [process.env.ADMIN_USER]: { passwordHash: process.env.ADMIN_PASS, role: "admin" },
  [process.env.STAFF_USER]: { passwordHash: process.env.STAFF_PASS, role: "staff" },
  "bong": { passwordHash: "$2b$10$55BPxlmk/nq6fW9WV9mkFuYD/pdyiHl5gPaV.3CEco/xKcB6.VYVG", role: "entry" },
};

const SESSION_SECRET = process.env.SESSION_SECRET || "dev-secret-change-me";

// Group nhận yêu cầu xóa
const DELETE_GROUP_CHAT_ID = process.env.DELETE_GROUP_CHAT_ID || "-1003710611209";

function sign(val) {
  return crypto.createHmac("sha256", SESSION_SECRET).update(val).digest("hex");
}
function makeSessionCookie(username) {
  const payload = JSON.stringify({ u: username, iat: Date.now() });
  const b64 = Buffer.from(payload).toString("base64url");
  const sig = sign(b64);
  return `${b64}.${sig}`;
}
function readSessionCookie(cookieVal) {
  if (!cookieVal) return null;
  const [b64, sig] = cookieVal.split(".");
  if (!b64 || !sig) return null;
  if (sign(b64) !== sig) return null;
  try {
    return JSON.parse(Buffer.from(b64, "base64url").toString("utf8"));
  } catch {
    return null;
  }
}

function requireAuth(req, res, next) {
  const sess = readSessionCookie(req.cookies?.wms_auth);
  const u = sess?.u;
  if (!u || !USERS[u]) return res.status(401).json({ error: "Not logged in" });
  req.user = u;
  req.role = USERS[u].role || "staff";
  next();
}
function requireAdmin(req, res, next) {
  if (req.role !== "admin") return res.status(403).json({ error: "Admin only" });
  next();
}
function requireSuperAdmin(req, res, next) {
  if (req.role !== "admin" || req.user !== "tho") return res.status(403).json({ error: "Tho Admin only" });
  next();
}
function requireStaff(req, res, next) {
  if (req.role !== "admin" && req.role !== "staff") return res.status(403).json({ error: "Staff/Admin only" });
  next();
}

// ====== Export folder ======
const EXPORT_DIR = path.join(__dirname, "public", "exports");
fs.mkdirSync(EXPORT_DIR, { recursive: true });

// ====== Guard HTML pages: chưa login -> đá về /login.html ======
app.use((req, res, next) => {
  const p = req.path;

  // cho phép login + assets cơ bản + api login/logout
  const allow =
    p === "/" ||
    p === "/login.html" ||
    p === "/styles.css" ||
    p.startsWith("/styles.") ||
    p.startsWith("/favicon") ||
    p.startsWith("/assets/") ||
    p.startsWith("/api/login") ||
    p.startsWith("/api/logout");

  if (allow) return next();

  // nếu request file html mà chưa login -> redirect login
  if (p.endsWith(".html")) {
    const sess = readSessionCookie(req.cookies?.wms_auth);
    const u = sess?.u;
    if (!u || !USERS[u]) return res.redirect("/login.html");
  }

  next();
});

// ====== Guard exports: chưa login -> không tải được CSV ======
app.use("/exports", (req, res, next) => {
  const sess = readSessionCookie(req.cookies?.wms_auth);
  const u = sess?.u;
  if (!u || !USERS[u]) return res.status(401).send("Not logged in");
  next();
});

// ====== Static files (sau guard) ======
app.use(express.static("public"));

// ====== Root ======
app.get("/", (req, res) => res.redirect("/login.html"));

// ====== Login/Logout ======
app.post("/api/login", async (req, res) => {
  const { username, password } = req.body;

  const user = USERS[username];
  if (!user || !user.passwordHash) {
    return res.status(401).json({ error: "Invalid credentials" });
  }

  const ok = await bcrypt.compare(String(password || ""), user.passwordHash);
  if (!ok) {
    return res.status(401).json({ error: "Invalid credentials" });
  }

  res.cookie("wms_auth", makeSessionCookie(username), {
    httpOnly: true,
    sameSite: "lax",
  });

  // Tự động kiểm tra hàng tồn quá hạn khi có người login (không block response)
  checkStaleItemsAndNotify().catch(e => console.error("Auto check failed:", e));

  res.json({ ok: true });
});

app.post("/api/logout", (req, res) => {
  res.clearCookie("wms_auth");
  res.json({ ok: true });
});

// ====== Helpers ======
function csvCell(v) {
  const s = String(v ?? "");
  if (/[,"\n]/.test(s)) return `"${s.replace(/"/g, '""')}"`;
  return s;
}

function escTg(s) {
  return String(s ?? "").replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;");
}

let cachedCategories = [];
async function loadCategories() {
  try {
    const { rows } = await db.execute("SELECT * FROM category_rules ORDER BY priority DESC, id ASC");
    cachedCategories = rows.map(r => ({
      name: r.name,
      keywords: r.keywords.split(",").map(k => k.trim().toLowerCase()).filter(Boolean)
    }));
  } catch (e) {
    console.error("Failed to load categories:", e);
  }
}
// Load ngay khi khởi động
loadCategories();

function detectCategory(name) {
  const n = (name || "").toLowerCase();
  for (const cat of cachedCategories) {
    if (cat.keywords.some(kw => n.includes(kw))) {
      return cat.name;
    }
  }
  return "else";
}

function nowISO() {
  const d = new Date();
  const jst = d.toLocaleString("sv-SE", { timeZone: "Asia/Tokyo" }).replace(" ", "T");
  return jst + "+09:00";
}
function genToken() {
  return crypto.randomBytes(24).toString("hex");
}
function yyyymmddLocal(d = new Date()) {
  return d.toLocaleDateString("sv-SE", { timeZone: "Asia/Tokyo" }).replace(/-/g, "");
}
function pad2(n) {
  return String(n).padStart(2, "0");
}
function todayKey() {
  return yyyymmddLocal();
}
function fmtTimeLocal(iso) {
  if (!iso) return "-";
  try {
    const d = new Date(iso);
    return d.toLocaleString("vi-VN", { timeZone: "Asia/Tokyo" });
  } catch (e) { return iso; }
}

// ====== Telegram Alerts ======
async function sendTelegramMessage(text) {
  const token = process.env.TELEGRAM_BOT_TOKEN;
  const chatId = process.env.TELEGRAM_CHAT_ID;
  if (!token || !chatId) return;

  try {
    const url = `https://api.telegram.org/bot${token}/sendMessage`;
    await fetch(url, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        chat_id: chatId,
        text,
        parse_mode: "HTML"
      })
    });
  } catch (e) {
    console.error("Telegram send failed:", e);
  }
}

async function sendTelegramDocument(filePath, caption = "") {
  const token = process.env.TELEGRAM_BOT_TOKEN;
  const chatId = process.env.TELEGRAM_CHAT_ID;
  if (!token || !chatId || !fs.existsSync(filePath)) return;

  try {
    const url = `https://api.telegram.org/bot${token}/sendDocument`;

    // Sử dụng Native FormData (Node 18+) để đảm bảo tương thích tốt nhất với native fetch
    const form = new globalThis.FormData();
    form.append("chat_id", chatId);
    form.append("caption", caption);

    // Đọc file và đóng gói vào Blob
    const fileBuffer = fs.readFileSync(filePath);
    const blob = new globalThis.Blob([fileBuffer], { type: "text/csv" });
    form.append("document", blob, path.basename(filePath));

    const res = await fetch(url, {
      method: "POST",
      body: form
      // Lưu ý: KHÔNG set Content-Type header thủ công khi dùng native FormData, 
      // fetch sẽ tự động set boundary cho mình.
    });

    if (!res.ok) {
      const errBody = await res.text();
      console.error("Telegram document send failed:", res.status, errBody);
      throw new Error(`Telegram rejected (Status ${res.status}): ${errBody}`);
    }
  } catch (e) {
    console.error("sendTelegramDocument Error:", e.message);
    throw e;
  }
}

async function sendTelegramPhoto(imageBuffer, caption = "", replyMarkup = null) {
  const token = process.env.TELEGRAM_BOT_TOKEN;
  const chatId = process.env.TELEGRAM_CHAT_ID;
  if (!token || !chatId) return;

  try {
    const url = `https://api.telegram.org/bot${token}/sendPhoto`;
    const form = new globalThis.FormData();
    form.append("chat_id", chatId);
    form.append("caption", caption);
    form.append("parse_mode", "HTML");
    if (replyMarkup) {
      form.append("reply_markup", JSON.stringify(replyMarkup));
    }

    const blob = new globalThis.Blob([imageBuffer], { type: "image/png" });
    form.append("photo", blob, "qr_code.png");

    const res = await fetch(url, {
      method: "POST",
      body: form
    });

    if (!res.ok) {
      const errBody = await res.text();
      console.error("Telegram photo send failed:", res.status, errBody);
      return null;
    }
    const data = await res.json();
    return data.result; // Tra ve thong tin tin nhan (co message_id)
  } catch (e) {
    console.error("sendTelegramPhoto Error:", e.message);
    return null;
  }
}

// ====== Image Label Generation (Mirror Frontend) ======
function wrapText(ctx, text, x, y, maxWidth, lineHeight, maxLines) {
  const words = (text || "").split(/\s+/).filter(Boolean);
  let line = "";
  let lines = 0;
  for (let i = 0; i < words.length; i++) {
    const test = line ? (line + " " + words[i]) : words[i];
    if (ctx.measureText(test).width <= maxWidth) {
      line = test;
    } else {
      ctx.fillText(line, x, y);
      y += lineHeight;
      lines++;
      if (maxLines && lines >= maxLines) return y;
      line = words[i];
    }
  }
  if (line) { ctx.fillText(line, x, y); y += lineHeight; }
  return y;
}

async function generateLabelBuffer(item, qrBuffer) {
  const LABEL_W = 548;
  const LABEL_H = 338;
  const canvas = createCanvas(LABEL_W, LABEL_H);
  const ctx = canvas.getContext("2d");

  // Background
  ctx.fillStyle = "#fff";
  ctx.fillRect(0, 0, LABEL_W, LABEL_H);

  const pad = 7;
  const qrSize = 326;
  const qrX = LABEL_W - pad - qrSize;
  const qrY = pad;

  // Draw QR
  const qrImg = await loadImage(qrBuffer);
  ctx.drawImage(qrImg, qrX, qrY, qrSize, qrSize);

  // Left side text
  const leftX = pad;
  const textW = qrX - 5 - leftX;

  ctx.fillStyle = "#000";

  // MVD
  ctx.font = "bold 34px sans-serif";
  let y = pad + 38;
  ctx.fillText(String(item.mvd || "-").trim(), leftX, y);

  // Serial
  y += 24;
  ctx.font = "bold 18px sans-serif";
  let sn = (item.serial_clean || item.serial_raw || "-").trim();
  while (ctx.measureText(sn).width > textW && sn.length > 4) { sn = sn.slice(0, -2) + "…"; }
  ctx.fillText(sn, leftX, y);

  // Name
  y += 26;
  ctx.font = "bold 20px sans-serif";
  wrapText(ctx, (item.name || "-").trim(), leftX, y, textW, 24, 10);

  // Logo
  try {
    const logoRelPath = "public/images/logo.png";
    const logoFull = path.join(__dirname, logoRelPath);
    if (fs.existsSync(logoFull)) {
      const logoImg = await loadImage(logoFull);
      const scale = Math.min(textW / logoImg.width, 140 / logoImg.height);
      const dw = logoImg.width * scale;
      const dh = logoImg.height * scale;
      ctx.drawImage(logoImg, leftX + (textW - dw) / 2, LABEL_H - pad - dh, dw, dh);
    }
  } catch (e) {
    console.error("Logo draw failed:", e);
  }

  return canvas.toBuffer("image/png");
}

async function checkStaleItemsAndNotify(isManual = false) {
  const today = todayKey();

  // Kiểm tra xem hôm nay đã gửi chưa (nếu không phải gửi thủ công)
  if (!isManual) {
    const { rows } = await db.execute({ sql: "SELECT value FROM kv_store WHERE key = 'last_stale_alert_date'", args: [] });
    if (rows[0]?.value === today) return;
  }

  // Tìm hàng tồn > 15 ngày (READY_TO_SHIP hoặc CREATED)
  // Tính 15 ngày trước từ giờ Nhật Bản
  const staleDate = new Date(new Date().getTime() + 9 * 60 * 60 * 1000 - 15 * 24 * 60 * 60 * 1000).toISOString().split('T')[0];

  const { rows: staleItems } = await db.execute({
    sql: `
      SELECT package_id, name, created_at
      FROM items
      WHERE is_deleted = 0
        AND status = 'READY_TO_SHIP'
        AND substr(created_at, 1, 10) < ?
      ORDER BY created_at ASC
      LIMIT 20
    `,
    args: [staleDate]
  });

  if (staleItems.length > 0) {
    let msg = `⚠️ <b>CẢNH BÁO HÀNG TỒN > 15 NGÀY</b>\n\n`;
    staleItems.forEach((it, i) => {
      msg += `${i + 1}. <code>${it.package_id}</code> - ${it.name}\n   (Tồn: ${Math.floor((new Date() - new Date(it.created_at)) / (1000 * 60 * 60 * 24))} ngày)\n`;
    });
    msg += `\n👉 <a href="${process.env.APP_URL || ''}/list.html">Xem danh sách đầy đủ</a>`;

    await sendTelegramMessage(msg);

    // Lưu lại ngày đã gửi
    await db.execute({
      sql: "INSERT OR REPLACE INTO kv_store (key, value) VALUES ('last_stale_alert_date', ?)",
      args: [today]
    });
  }
}
async function nextPackageId() {
  const key = todayKey();
  const { rows } = await db.execute({
    sql: `
    SELECT package_id
    FROM items
    WHERE package_id LIKE ?
    ORDER BY package_id DESC
    LIMIT 1
  `,
    args: [`${key}%`]
  });

  const row = rows[0];

  let nextSeq = 1;
  if (row?.package_id) {
    const m = row.package_id.match(/(\d{2})$/);
    if (m) nextSeq = parseInt(m[1], 10) + 1;
  }

  if (nextSeq > 99) throw new Error("Hết số thứ tự trong ngày (01-99).");
  return `${key}${pad2(nextSeq)}`;
}

function parsePayload(text) {
  let obj;
  try {
    obj = JSON.parse(text);
  } catch {
    throw new Error("Không parse được JSON. Hãy dán đúng format JSON.");
  }

  const serial_raw = obj.serial ?? "";
  const serial_clean = (serial_raw.match(/[A-Z0-9]{6,}/i)?.[0] ?? "").trim();

  return {
    name: (obj.name ?? "").trim(),
    serial_raw: serial_raw.trim(),
    serial_clean,
    condition: (obj.condition ?? "").trim(),
    mvd: (obj.mvd ?? "").trim(),
    note: (obj.note ?? "").trim(),
    battery: (obj.battery ?? "").trim(),
    coverage: (obj.coverage ?? "").trim(),
  };
}

// ====== Create item + label ======
app.post("/api/items", requireAuth, requireStaff, async (req, res) => {
  try {
    const { raw_text } = req.body;
    const fields = parsePayload(raw_text);

    if (!fields.serial_clean) {
      return res.status(400).json({ error: "Thiếu/không nhận diện được serial trong JSON." });
    }

    const { rows: existRows } = await db.execute({
      sql: `
      SELECT id, package_id, name, serial_clean
      FROM items
      WHERE serial_clean = ?
        AND is_deleted = 0
      LIMIT 1
    `,
      args: [fields.serial_clean]
    });
    const existed = existRows[0];

    if (existed) {
      return res.status(409).json({
        error: "Đã có item này (serial trùng) và đang tồn tại.",
        existed,
      });
    }

    const package_id = await nextPackageId();
    const token = genToken();

    const t = nowISO();
    try {
      await db.execute({
        sql: `
        INSERT INTO items (
          package_id, token,
          name, serial_raw, serial_clean, condition, mvd, note, battery, coverage,
          status, inventory_status,
          created_at, updated_at,
          is_deleted, created_by, category
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'READY_TO_SHIP', 'UNKNOWN', ?, ?, 0, ?, ?)
      `,
        args: [
          package_id, token,
          fields.name, fields.serial_raw, fields.serial_clean, fields.condition, fields.mvd, fields.note, fields.battery, fields.coverage,
          t, t, req.user, detectCategory(fields.name)
        ]
      });
    } catch (e) {
      if (String(e.message || "").toLowerCase().includes("unique")) {
        return res.status(409).json({ error: "Đã có item này (serial trùng) và đang tồn tại." });
      }
      throw e;
    }

    const { rows: itemRows } = await db.execute({ sql: "SELECT * FROM items WHERE token = ?", args: [token] });
    const item = itemRows[0];

    const scanUrl = `${req.protocol}://${req.get("host")}/scan.html?token=${encodeURIComponent(token)}`;
    const qrDataUrl = await QRCode.toDataURL(token, { margin: 1, width: 400, errorCorrectionLevel: 'L' });

    res.json({ item, scanUrl, qrDataUrl });
  } catch (e) {
    res.status(400).json({ error: e.message || "Create failed" });
  }
});

// ====== Shortcut API: Create item via external POST ======
app.post("/api/external/create", async (req, res) => {
  const apiKey = req.headers["x-api-key"];
  if (!apiKey || apiKey !== process.env.SHORTCUT_API_KEY) {
    return res.status(401).json({ error: "Unauthorized. Missing or invalid x-api-key header." });
  }

  try {
    const fields = {
      name: (req.body.name ?? "").trim(),
      serial_raw: (req.body.serial ?? "").trim(),
      condition: (req.body.condition ?? "Unknown").trim(),
      mvd: (req.body.mvd ?? "").trim(),
      note: (req.body.note ?? "").trim(),
      battery: (req.body.battery ?? "").trim(),
      coverage: (req.body.coverage ?? "").trim(),
    };

    fields.serial_clean = (fields.serial_raw.match(/[A-Z0-9]{6,}/i)?.[0] ?? "").trim();

    if (!fields.name || !fields.serial_clean) {
      return res.status(400).json({ error: "Thiếu tên sản phẩm hoặc serial hợp lệ." });
    }

    // Check duplicate
    const { rows: existRows } = await db.execute({
      sql: `SELECT package_id FROM items WHERE serial_clean = ? AND is_deleted = 0 LIMIT 1`,
      args: [fields.serial_clean]
    });
    if (existRows[0]) {
      return res.status(409).json({ error: "Sản phẩm đã tồn tại.", package_id: existRows[0].package_id });
    }

    const package_id = await nextPackageId();
    const token = genToken();
    const t = nowISO();

    await db.execute({
      sql: `
        INSERT INTO items (
          package_id, token, name, serial_raw, serial_clean, condition, mvd, note, battery, coverage,
          status, inventory_status, created_at, updated_at, is_deleted, created_by, category
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'READY_TO_SHIP', 'UNKNOWN', ?, ?, 0, 'shortcut', ?)
      `,
      args: [
        package_id, token, fields.name, fields.serial_raw, fields.serial_clean, fields.condition, fields.mvd, fields.note, fields.battery, fields.coverage,
        t, t, detectCategory(fields.name)
      ]
    });

    const { rows: itemRows } = await db.execute({ sql: "SELECT id FROM items WHERE token = ?", args: [token] });
    const newItem = itemRows[0];

    // Notify Telegram with Formatted Label + Button
    const qrBuffer = await QRCode.toBuffer(token, { margin: 1, width: 400, errorCorrectionLevel: 'L' });
    const labelBuffer = await generateLabelBuffer(fields, qrBuffer);

    let caption = `📌 <b>ITEM MỚI (SHORTCUT)</b>\n\n` +
      `📦 ID: <code>${package_id}</code>\n` +
      `🏷 Tên: <b>${escTg(fields.name)}</b>\n` +
      `🔢 Serial: <code>${fields.serial_clean}</code>\n` +
      `💎 Tình trạng: ${escTg(fields.condition)}\n` +
      `📅 Ngày tạo: ${fmtTimeLocal(t)}`;

    if (process.env.APP_URL) {
      caption += `\n\n🔗 <a href="${process.env.APP_URL}/scan.html?token=${token}">Xem chi tiết</a>`;
    }

    const replyMarkup = {
      inline_keyboard: [
        [
          { text: `🟡 READY_TO_SHIP`, callback_data: "none" },
          { text: "↩️", callback_data: `request_return_tg:${newItem.id}` },
          { text: "🗑️", callback_data: `request_delete_tg:${newItem.id}` }
        ],
        [
          { text: "🔴 Post Meru", callback_data: `posted:${newItem.id}` },
          { text: "🔴 Log Meru", callback_data: `meru:${newItem.id}` }
        ]
      ]
    };

    const tgMsg = await sendTelegramPhoto(labelBuffer, caption, replyMarkup).catch(e => {
      console.error("Shortcut Telegram notify failed:", e);
      return null;
    });

    // Neu gui Telegram thanh cong, luu ID tin nhan de sau nay dong bo nut bam
    if (tgMsg) {
      await db.execute({
        sql: "UPDATE items SET tg_chat_id = ?, tg_msg_id = ? WHERE id = ?",
        args: [String(tgMsg.chat.id), String(tgMsg.message_id), newItem.id]
      });
    }

    res.json({ ok: true, package_id, token });
  } catch (e) {
    console.error("Shortcut API failed:", e);
    res.status(500).json({ error: e.message || "Shortcut processing failed" });
  }
});

// ====== Telegram Webhook Handler ======
app.post("/api/telegram/webhook", async (req, res) => {
  const token = process.env.TELEGRAM_BOT_TOKEN;
  const authorizedChatId = process.env.TELEGRAM_CHAT_ID;

  if (!req.body) return res.sendStatus(200);

  // 1. Handle Button Clicks (Callback Queries)
  if (req.body.callback_query) {
    const cb = req.body.callback_query;
    const chatId = String(cb.message.chat.id);
    const isFromAuthorizedChat = chatId === String(authorizedChatId) || chatId === String(DELETE_GROUP_CHAT_ID);
    if (!isFromAuthorizedChat) return res.sendStatus(200);

    const [action, itemId] = cb.data.split(":");
    try {
      // Kiểm tra quyền hạn người dùng theo rule mới
      const bongId = String(process.env.TELEGRAM_BONG || "").trim();
      const aaronId = String(process.env.TELEGRAM_AARON || "").trim();
      const adminId = "7818712996";
      const userId = String(cb.from.id);

      // Phân quyền chi tiết
      let allowed = false;

      if (userId === adminId) {
        allowed = true; // Admin có toàn quyền
      } else if (bongId && userId === bongId) {
        if (action === "posted") allowed = true;
      } else if (aaronId && userId === aaronId) {
        if (action === "request_delete_tg") allowed = true;
      } else {
        // Fallback for other users in the whitelist
        const authorizedUserIds = (process.env.AUTHORIZED_TELEGRAM_USER_IDS || "").split(",").map(id => id.trim()).filter(Boolean);
        if (authorizedUserIds.includes(userId)) {
          allowed = true;
        }
      }

      if (!allowed) {
        const answerUrl = `https://api.telegram.org/bot${token}/answerCallbackQuery`;
        await fetch(answerUrl, {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({
            callback_query_id: cb.id,
            text: "❌ Bạn không có quyền thực hiện thao tác này!",
            show_alert: true
          })
        });
        return res.sendStatus(200);
      }

      if (action === "meru") {
        const { rows } = await db.execute({ sql: "SELECT id, is_meru_logged FROM items WHERE id = ?", args: [itemId] });
        const item = rows[0];
        if (item) {
          const updated_at = nowISO();
          const next_val = item.is_meru_logged ? 0 : 1;
          await db.execute({ sql: "UPDATE items SET is_meru_logged = ?, updated_at = ? WHERE id = ?", args: [next_val, updated_at, itemId] });
          await db.execute({ sql: "INSERT INTO edit_logs(item_id, actor, changes_json, created_at) VALUES(?,?,?,?)", args: [itemId, 'TelegramBot', JSON.stringify({ is_meru_logged: next_val }), updated_at] });

          await syncTelegramButtons(itemId).catch(e => console.error("Sync TG Meru failed:", e));

          const answerUrl = `https://api.telegram.org/bot${token}/answerCallbackQuery`;
          await fetch(answerUrl, {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({
              callback_query_id: cb.id,
              text: next_val ? "✅ Đã Log Meru!" : "🔄 Đã Hủy Log Meru",
              show_alert: false
            })
          });
        }
      }

      if (action === "posted") {
        const { rows } = await db.execute({ sql: "SELECT id, package_id, is_posted FROM items WHERE id = ?", args: [itemId] });
        const item = rows[0];
        if (item) {
          const updated_at = nowISO();
          if (!item.is_posted) {
            await db.execute({ sql: "UPDATE items SET is_posted = 1, updated_at = ? WHERE id = ?", args: [updated_at, itemId] });
            await db.execute({ sql: "INSERT INTO edit_logs(item_id, actor, changes_json, created_at) VALUES(?,?,?,?)", args: [itemId, 'TelegramBot', JSON.stringify({ is_posted: 1 }), updated_at] });

            await syncTelegramButtons(itemId).catch(e => console.error("Sync TG Posted failed:", e));

            // Trả lời Telegram kèm thông báo
            const answerUrl = `https://api.telegram.org/bot${token}/answerCallbackQuery`;
            await fetch(answerUrl, {
              method: "POST",
              headers: { "Content-Type": "application/json" },
              body: JSON.stringify({
                callback_query_id: cb.id,
                text: "✅ Đã đăng bán thành công!",
                show_alert: false
              })
            });
          } else {
            const answerUrl = `https://api.telegram.org/bot${token}/answerCallbackQuery`;
            await fetch(answerUrl, {
              method: "POST",
              headers: { "Content-Type": "application/json" },
              body: JSON.stringify({
                callback_query_id: cb.id,
                text: "ℹ️ Sản phẩm này đã được đăng bán rồi.",
                show_alert: false
              })
            });
          }
        }
      }
      if (action === "request_return_tg") {
        const userId = String(cb.from.id);
        if (userId !== "7818712996") {
          await fetch(`https://api.telegram.org/bot${token}/answerCallbackQuery`, {
            method: "POST", headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ callback_query_id: cb.id, text: "❌ Chỉ admin mới có quyền yêu cầu Return!", show_alert: true })
          });
          return res.sendStatus(200);
        }

        const itemId2 = itemId;
        const { rows: iRows } = await db.execute({ sql: "SELECT * FROM items WHERE id = ? AND is_deleted = 0", args: [itemId2] });
        const itemData = iRows[0];

        if (!itemData) {
          await fetch(`https://api.telegram.org/bot${token}/answerCallbackQuery`, {
            method: "POST", headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ callback_query_id: cb.id, text: "❌ Không tìm thấy sản phẩm.", show_alert: true })
          });
          return res.sendStatus(200);
        }

        const { rows: pendingRows } = await db.execute({
          sql: "SELECT id FROM delete_requests WHERE item_id = ? AND status = 'PENDING'",
          args: [itemId2]
        });
        if (pendingRows[0]) {
          await fetch(`https://api.telegram.org/bot${token}/answerCallbackQuery`, {
            method: "POST", headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ callback_query_id: cb.id, text: "⚠️ Đã có yêu cầu đang chờ duyệt!", show_alert: true })
          });
          return res.sendStatus(200);
        }

        const t = nowISO();
        const requester = cb.from.username ? `@${cb.from.username}` : (cb.from.first_name || 'Admin');

        await db.execute({
          sql: "UPDATE items SET status = 'REQUEST_RETURN', updated_at = ? WHERE id = ?",
          args: [t, itemId2]
        });

        await db.execute({
          sql: "INSERT INTO delete_requests (item_id, requested_by, status, created_at) VALUES (?, ?, 'PENDING', ?)",
          args: [itemId2, requester, t]
        });

        const { rows: newReqRows } = await db.execute({
          sql: "SELECT id FROM delete_requests WHERE item_id = ? AND status = 'PENDING' ORDER BY id DESC LIMIT 1",
          args: [itemId2]
        });
        const newReqId = newReqRows[0].id;

        const returnGroupId = process.env.RETURN_GROUP_CHAT_ID || "-1003767068395";
        const taskGroupId = process.env.TASK_GROUP_CHAT_ID || returnGroupId;
        const retMsg = `📦 <b>YÊU CẦU RETURN & XÓA</b>\n\n` +
          `📦 ID: <code>${itemData.package_id}</code>\n` +
          `🏷️ Tên: <b>${escTg(itemData.name)}</b>\n` +
          `🔢 Serial: <code>${itemData.serial_clean || "-"}</code>\n` +
          `📍 Trạng thái: ${itemData.status} ➔ <b>REQUEST_RETURN</b>\n` +
          `👤 Yêu cầu bởi: <b>${escTg(requester)}</b>\n` +
          `⏰ Thời gian: ${fmtTimeLocal(t)}`;

        const buttons = [
          { text: "✅ Done", callback_data: `return_done:${newReqId}` },
          { text: `📍 ${itemData.status}`, callback_data: "none" }
        ];

        try {
          // 1. Gửi tin nhắn tới nhóm Admin/Return
          const tgRes = await fetch(`https://api.telegram.org/bot${token}/sendMessage`, {
            method: "POST", headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ chat_id: returnGroupId, text: retMsg, parse_mode: "HTML", reply_markup: { inline_keyboard: [buttons] } })
          });
          const tgData = await tgRes.json();
          let adminMsgId = null;
          if (tgData.ok && tgData.result) {
            adminMsgId = String(tgData.result.message_id);
          }

          // 2. Gửi tin nhắn tới nhóm Task
          const taskMsg = `📝 <b>TASK: KIỂM TRA HÀNG RETURN</b>\n\n` +
            `📦 ID: <code>${itemData.package_id}</code>\n` +
            `🏷 Tên: <b>${escTg(itemData.name)}</b>\n` +
            `🔢 Serial: <code>${itemData.serial_clean || "-"}</code>\n` +
            `👤 Người yêu cầu: ${escTg(requester)}`;

          const taskRes = await fetch(`https://api.telegram.org/bot${token}/sendMessage`, {
            method: "POST", headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ chat_id: taskGroupId, text: taskMsg, parse_mode: "HTML" })
          });
          const taskData = await taskRes.json();
          let taskMsgId = null;
          if (taskData.ok && taskData.result) {
            taskMsgId = String(taskData.result.message_id);
          }

          // 3. Cập nhật database với ID của cả 2 tin nhắn
          await db.execute({
            sql: "UPDATE delete_requests SET tg_chat_id = ?, tg_msg_id = ?, task_chat_id = ?, task_msg_id = ? WHERE id = ?",
            args: [returnGroupId, adminMsgId, taskGroupId, taskMsgId, newReqId]
          });

        } catch (e) {
          console.error("Telegram request return failed:", e);
        }

        await fetch(`https://api.telegram.org/bot${token}/answerCallbackQuery`, {
          method: "POST", headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ callback_query_id: cb.id, text: "✅ Đã gửi yêu cầu Return tới admin!", show_alert: true })
        });
        return res.sendStatus(200);
      }

      if (action === "request_delete_tg") {
        const itemId2 = itemId;
        const { rows: iRows } = await db.execute({ sql: "SELECT * FROM items WHERE id = ? AND is_deleted = 0", args: [itemId2] });
        const itemData = iRows[0];

        if (!itemData) {
          await fetch(`https://api.telegram.org/bot${token}/answerCallbackQuery`, {
            method: "POST", headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ callback_query_id: cb.id, text: "❌ Không tìm thấy sản phẩm.", show_alert: true })
          });
          return res.sendStatus(200);
        }

        // Kiểm tra pending request
        const { rows: pendingRows } = await db.execute({
          sql: "SELECT id FROM delete_requests WHERE item_id = ? AND status = 'PENDING'",
          args: [itemId2]
        });
        if (pendingRows[0]) {
          await fetch(`https://api.telegram.org/bot${token}/answerCallbackQuery`, {
            method: "POST", headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ callback_query_id: cb.id, text: "⚠️ Đã có yêu cầu xóa đang chờ duyệt!", show_alert: true })
          });
          return res.sendStatus(200);
        }

        const t = nowISO();
        const requester = cb.from.username ? `@${cb.from.username}` : (cb.from.first_name || 'Telegram user');

        await db.execute({
          sql: "INSERT INTO delete_requests (item_id, requested_by, status, created_at) VALUES (?, ?, 'PENDING', ?)",
          args: [itemId2, requester, t]
        });

        const { rows: newReqRows } = await db.execute({
          sql: "SELECT id FROM delete_requests WHERE item_id = ? AND status = 'PENDING' ORDER BY id DESC LIMIT 1",
          args: [itemId2]
        });
        const newReqId = newReqRows[0].id;

        const delMsg = `🗑️ <b>YÊU CẦU XÓA SẢN PHẨM</b>\n\n` +
          `📦 ID: <code>${itemData.package_id}</code>\n` +
          `🏷️ Tên: <b>${escTg(itemData.name)}</b>\n` +
          `🔢 Serial: <code>${itemData.serial_clean || "-"}</code>\n` +
          `📍 Trạng thái: ${itemData.status}\n` +
          `👤 Yêu cầu bởi: <b>${escTg(requester)}</b>\n` +
          `⏰ Thời gian: ${fmtTimeLocal(t)}`;

        const buttons = [
          { text: "✅ Duyệt xóa", callback_data: `approve_delete:${newReqId}` },
          { text: "❌ Từ chối", callback_data: `reject_delete:${newReqId}` }
        ];



        const delMarkup = {
          inline_keyboard: [buttons]
        };

        try {
          const tgRes = await fetch(`https://api.telegram.org/bot${token}/sendMessage`, {
            method: "POST", headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ chat_id: DELETE_GROUP_CHAT_ID, text: delMsg, parse_mode: "HTML", reply_markup: delMarkup })
          });
          const tgData = await tgRes.json();
          if (tgData.ok && tgData.result) {
            await db.execute({
              sql: "UPDATE delete_requests SET tg_chat_id = ?, tg_msg_id = ? WHERE id = ?",
              args: [String(tgData.result.chat.id), String(tgData.result.message_id), newReqId]
            });
          }
        } catch (e) { console.error("Telegram delete request from TG button failed:", e); }

        await fetch(`https://api.telegram.org/bot${token}/answerCallbackQuery`, {
          method: "POST", headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ callback_query_id: cb.id, text: "✅ Đã gửi yêu cầu xóa tới admin!", show_alert: true })
        });
        return res.sendStatus(200);
      }

      if (action === "return_done") {
        const userId = String(cb.from.id);
        if (userId !== "7818712996") {
          await fetch(`https://api.telegram.org/bot${token}/answerCallbackQuery`, {
            method: "POST", headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ callback_query_id: cb.id, text: "❌ Chỉ admin mới có quyền nhấn Done!", show_alert: true })
          });
          return res.sendStatus(200);
        }

        const reqId = itemId; // Doi voi return_done, itemId thuc chat la reqId
        const { rows: reqRows } = await db.execute({ sql: "SELECT * FROM delete_requests WHERE id = ?", args: [reqId] });
        const request = reqRows[0];
        if (!request) return res.sendStatus(200);

        const { rows: itemRows } = await db.execute({ sql: "SELECT * FROM items WHERE id = ?", args: [request.item_id] });
        const item = itemRows[0];
        if (!item) return res.sendStatus(200);

        const t = nowISO();

        // 1. Cập nhật trạng thái sản phẩm
        await db.execute({
          sql: "UPDATE items SET status = 'RETURN', updated_at = ? WHERE id = ?",
          args: [t, item.id]
        });

        // 2. Cập nhật trạng thái yêu cầu
        await db.execute({
          sql: "UPDATE delete_requests SET status = 'DONE', resolved_at = ? WHERE id = ?",
          args: [t, reqId]
        });

        // 3. Xóa tin nhắn bên nhóm Task (nếu có)
        if (request.task_chat_id && request.task_msg_id) {
          await fetch(`https://api.telegram.org/bot${token}/deleteMessage`, {
            method: "POST", headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ chat_id: request.task_chat_id, message_id: request.task_msg_id })
          }).catch(e => console.error("Xóa task message thất bại:", e));
        }

        // 4. Cập nhật lại tin nhắn hiện tại
        const newText = cb.message.text.replace("YÊU CẦU RETURN & XÓA", "✅ ĐÃ HOÀN TẤT RETURN") + `\n\n✅ Đã xử lý bởi: <b>${escTg(cb.from.first_name)}</b>`;
        await fetch(`https://api.telegram.org/bot${token}/editMessageText`, {
          method: "POST", headers: { "Content-Type": "application/json" },
          body: JSON.stringify({
            chat_id: cb.message.chat.id,
            message_id: cb.message.message_id,
            text: newText,
            parse_mode: "HTML",
            reply_markup: {
              inline_keyboard: [[{ text: "📍 RETURN", callback_data: "none" }]]
            }
          })
        });

        // 5. Đồng bộ nút bấm tin nhắn gốc
        await syncTelegramButtons(item.id);

        await fetch(`https://api.telegram.org/bot${token}/answerCallbackQuery`, {
          method: "POST", headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ callback_query_id: cb.id, text: "✅ Đã xác nhận hoàn tất Return!" })
        });
        return res.sendStatus(200);
      }


      if (action === "approve_delete") {
        const reqId = itemId;
        const { rows: reqRows } = await db.execute({
          sql: `SELECT dr.*, i.package_id, i.name, i.tg_chat_id as item_tg_chat, i.tg_msg_id as item_tg_msg
                FROM delete_requests dr JOIN items i ON dr.item_id = i.id WHERE dr.id = ?`,
          args: [reqId]
        });
        const reqData = reqRows[0];

        if (!reqData || reqData.status !== 'PENDING') {
          await fetch(`https://api.telegram.org/bot${token}/answerCallbackQuery`, {
            method: "POST", headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ callback_query_id: cb.id, text: "⚠️ Yêu cầu này đã được xử lý rồi.", show_alert: true })
          });
          return res.sendStatus(200);
        }

        const t = nowISO();

        // Soft-delete item
        await db.execute({
          sql: `UPDATE items SET is_deleted=1, status='DELETED', deleted_at=?, deleted_by=?, updated_at=? WHERE id=?`,
          args: [t, cb.from.username || cb.from.first_name || 'TelegramBot', t, reqData.item_id]
        });

        // Update request status
        await db.execute({
          sql: `UPDATE delete_requests SET status='APPROVED', resolved_at=? WHERE id=?`,
          args: [t, reqId]
        });

        // Xóa tin nhắn gốc của item trên Telegram (nếu có)
        if (reqData.item_tg_chat && reqData.item_tg_msg) {
          try {
            await fetch(`https://api.telegram.org/bot${token}/deleteMessage`, {
              method: "POST", headers: { "Content-Type": "application/json" },
              body: JSON.stringify({ chat_id: reqData.item_tg_chat, message_id: Number(reqData.item_tg_msg) })
            });
          } catch (e) { console.error("Delete item TG msg failed:", e); }
        }

        // Xóa tin nhắn yêu cầu trong group
        if (reqData.tg_chat_id && reqData.tg_msg_id) {
          try {
            await fetch(`https://api.telegram.org/bot${token}/deleteMessage`, {
              method: "POST", headers: { "Content-Type": "application/json" },
              body: JSON.stringify({ chat_id: reqData.tg_chat_id, message_id: Number(reqData.tg_msg_id) })
            });
          } catch (e) { console.error("Delete request TG msg failed:", e); }
        }

        await fetch(`https://api.telegram.org/bot${token}/answerCallbackQuery`, {
          method: "POST", headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ callback_query_id: cb.id, text: `✅ Đã duyệt xóa: ${reqData.package_id}`, show_alert: true })
        });
        return res.sendStatus(200);
      }

      if (action === "reject_delete") {
        const reqId = itemId;
        const { rows: reqRows } = await db.execute({
          sql: `SELECT * FROM delete_requests WHERE id = ?`,
          args: [reqId]
        });
        const reqData = reqRows[0];

        if (!reqData || reqData.status !== 'PENDING') {
          await fetch(`https://api.telegram.org/bot${token}/answerCallbackQuery`, {
            method: "POST", headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ callback_query_id: cb.id, text: "⚠️ Yêu cầu này đã được xử lý rồi.", show_alert: true })
          });
          return res.sendStatus(200);
        }

        const t = nowISO();
        await db.execute({
          sql: `UPDATE delete_requests SET status='REJECTED', resolved_at=? WHERE id=?`,
          args: [t, reqId]
        });

        // Xóa tin nhắn yêu cầu trong group
        if (reqData.tg_chat_id && reqData.tg_msg_id) {
          try {
            await fetch(`https://api.telegram.org/bot${token}/deleteMessage`, {
              method: "POST", headers: { "Content-Type": "application/json" },
              body: JSON.stringify({ chat_id: reqData.tg_chat_id, message_id: Number(reqData.tg_msg_id) })
            });
          } catch (e) { console.error("Delete reject TG msg failed:", e); }
        }

        await fetch(`https://api.telegram.org/bot${token}/answerCallbackQuery`, {
          method: "POST", headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ callback_query_id: cb.id, text: "❌ Đã từ chối yêu cầu xóa.", show_alert: false })
        });
        return res.sendStatus(200);
      }

      // Luôn trả lời Telegram nếu chưa trả lời ở trên (để tắt spinner)
      const answerUrl = `https://api.telegram.org/bot${token}/answerCallbackQuery`;
      await fetch(answerUrl, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ callback_query_id: cb.id })
      });

    } catch (e) {
      console.error("Telegram callback error:", e);
    }
    return res.sendStatus(200);
  }

  const msg = req.body.message;
  if (!msg || !msg.chat) return res.sendStatus(200);
  const chatId = String(msg.chat.id);
  if (chatId !== String(authorizedChatId) && chatId !== String(DELETE_GROUP_CHAT_ID)) return res.sendStatus(200);

  // Handle Serial as Text (Mark as Posted)
  if (msg.text) {
    const text = msg.text.trim();
    const serial_clean = (text.match(/[A-Z0-9]{6,}/i)?.[0] ?? "").trim();

    if (serial_clean) {
      try {
        const { rows } = await db.execute({
          sql: "SELECT * FROM items WHERE (serial_clean = ? OR serial_raw = ?) AND is_deleted = 0 LIMIT 1",
          args: [serial_clean, text]
        });
        const item = rows[0];

        if (item) {
          const updated_at = nowISO();
          if (!item.is_posted) {
            await db.execute({ sql: "UPDATE items SET is_posted = 1, updated_at = ? WHERE id = ?", args: [updated_at, item.id] });
            await db.execute({ sql: "INSERT INTO edit_logs(item_id, actor, changes_json, created_at) VALUES(?,?,?,?)", args: [item.id, 'TelegramBot', JSON.stringify({ is_posted: 1 }), updated_at] });
            await sendTelegramMessage(`✅ <b>Đã cập nhật Đã đăng:</b>\n📦 ID: <code>${item.package_id}</code>\n🏷️ Tên: ${escTg(item.name)}\n🔢 Serial: <code>${item.serial_clean}</code>`);
          } else {
            await sendTelegramMessage(`ℹ️ SP <code>${item.package_id}</code> (${item.serial_clean}) đã được đánh dấu Đã đăng từ trước.`);
          }
        } else {
          if (text.length >= 6) await sendTelegramMessage(`❌ Không tìm thấy sản phẩm nào có Serial: <code>${text}</code>`);
        }
      } catch (e) {
        console.error("Telegram text processing failed:", e);
      }
    }

    // ── Task / Reminder ──────────────────────────────────────────
    if (msg.text && /^(nhắc|remind|task)\s*:/i.test(msg.text.trim())) {
      try {
        const raw = msg.text.replace(/^(nhắc|remind|task)\s*:/i, "").trim();

        // Parse time: 30p | 1h | 2h30p | 14:30 | 9h30
        let dueMs = null;
        let title = raw;
        const VN_OFFSET = 7 * 3600000;
        const nowVN = () => Date.now() + VN_OFFSET;

        // Pattern 1: ends with NhMp or Nh or Mp
        const relMatch = raw.match(/(\d+h)?(\d+p)?\s*$/i);
        const clockMatch = raw.match(/(?:lúc\s*)?(\d{1,2})[h:](\d{2})/i);
        const hOnly = raw.match(/(\d+)h\s*$/i);
        const mOnly = raw.match(/(\d+)p\s*$/i);

        if (clockMatch) {
          const hh = parseInt(clockMatch[1]), mm = parseInt(clockMatch[2]);
          const todayVN = new Date(nowVN());
          let due = new Date(Date.UTC(todayVN.getUTCFullYear(), todayVN.getUTCMonth(), todayVN.getUTCDate(), hh - 7, mm));
          if (due.getTime() <= Date.now()) due = new Date(due.getTime() + 86400000); // tomorrow
          dueMs = due.getTime();
          title = raw.replace(clockMatch[0], "").replace(/\s*(lúc)?\s*$/, "").trim();
        } else if (hOnly && mOnly && relMatch[1] && relMatch[2]) {
          const h = parseInt(relMatch[1]), m = parseInt(relMatch[2]);
          dueMs = Date.now() + (h * 3600 + m * 60) * 1000;
          title = raw.replace(relMatch[0].trim(), "").trim();
        } else if (hOnly) {
          const h = parseInt(hOnly[1]);
          dueMs = Date.now() + h * 3600000;
          title = raw.replace(hOnly[0].trim(), "").trim();
        } else if (mOnly) {
          const m = parseInt(mOnly[1]);
          dueMs = Date.now() + m * 60000;
          title = raw.replace(mOnly[0].trim(), "").trim();
        }

        if (!dueMs || !title) {
          await sendTelegramMessage(`⚠️ Không hiểu thời gian. Ví dụ:\n<code>nhắc: Kiểm hàng 30p</code>\n<code>nhắc: Gọi khách 1h30p</code>\n<code>nhắc: Meeting 14:30</code>`);
        } else {
          const due_at = new Date(dueMs).toISOString();
          const created_at = nowISO();
          const from = msg.from?.username ? `@${msg.from.username}` : (msg.from?.first_name || "TG");
          const chatId = String(msg.chat.id);

          const result = await db.execute({
            sql: "INSERT INTO tasks (title, due_at, chat_id, created_by, status, created_at) VALUES (?,?,?,?,?,?)",
            args: [title, due_at, chatId, from, "PENDING", created_at]
          });
          const taskId = Number(result.lastInsertRowid);

          // Format due time in Vietnam TZ
          const dueVN = new Date(dueMs + VN_OFFSET);
          const dueStr = `${String(dueVN.getUTCHours()).padStart(2, "0")}:${String(dueVN.getUTCMinutes()).padStart(2, "0")}`;

          await sendTelegramMessage(
            `⏰ <b>Đã đặt nhắc:</b> ${escTg(title)}\n🕐 Nhắc lúc: <b>${dueStr}</b>`,
            { inline_keyboard: [[{ text: "❌ Huỷ nhắc", callback_data: `task_cancel:${taskId}` }]] }
          );
        }
      } catch (e) { console.error("Task creation failed:", e); }
    }
  }

  res.sendStatus(200);
});

// ── Task callbacks: done / snooze / cancel ────────────────────────────
// (handled inside existing callback_query block above via action routing)

// ── Background scheduler: fire due reminders every 30s ───────────────
setInterval(async () => {
  try {
    const now = nowISO();
    const { rows } = await db.execute({
      sql: "SELECT * FROM tasks WHERE status = 'PENDING' AND due_at <= ? ORDER BY due_at ASC LIMIT 20",
      args: [now]
    });

    for (const task of rows) {
      const markup = {
        inline_keyboard: [[
          { text: "✅ Xong", callback_data: `task_done:${task.id}` },
          { text: "⏰ +15p", callback_data: `task_snooze15:${task.id}` },
          { text: "⏰ +1h", callback_data: `task_snooze60:${task.id}` }
        ]]
      };

      const token = process.env.TELEGRAM_BOT_TOKEN;
      const count = (task.remind_count || 0) + 1;
      const prefix = count > 1 ? `🔔×${count} ` : "🔔 ";

      try {
        const tgRes = await fetch(`https://api.telegram.org/bot${token}/sendMessage`, {
          method: "POST", headers: { "Content-Type": "application/json" },
          body: JSON.stringify({
            chat_id: task.chat_id,
            text: `${prefix}<b>Nhắc nhở:</b> ${escTg(task.title)}`,
            parse_mode: "HTML",
            reply_markup: markup
          })
        });
        const tgData = await tgRes.json();
        const newMsgId = tgData.ok ? String(tgData.result.message_id) : null;

        // Snooze 5p nếu chưa có phản hồi (tránh spam)
        const nextDue = new Date(Date.now() + 5 * 60000).toISOString();
        await db.execute({
          sql: "UPDATE tasks SET status='PENDING', due_at=?, remind_count=?, tg_msg_id=? WHERE id=?",
          args: [nextDue, count, newMsgId, task.id]
        });
      } catch (e) { console.error("Reminder send failed:", e); }
    }
  } catch (e) { console.error("Scheduler error:", e); }
}, 30000);


function buildItemQuery(req) {
  const q = req.query.q;
  const status = req.query.status;
  const inventory = req.query.inventory;
  const tab = req.query.tab;
  const posted = req.query.posted;

  const where = ["is_deleted = 0"];
  const params = [];
  const like = `%${q}%`;

  if (q) {
    where.push(
      `(package_id LIKE ? OR name LIKE ? OR serial_clean LIKE ? OR tracking_code LIKE ?)`
    );
    params.push(like, like, like, like);
  }

  if (tab === 'stock') {
    where.push(`status IN ('READY_TO_SHIP', 'CREATED')`);
  } else if (tab === 'shipped') {
    where.push(`status = 'SHIPPED'`);
  } else if (tab === 'return') {
    where.push(`status IN ('HENBIN', 'RETURNED', 'RETURN', 'REQUEST_RETURN')`);
  } else if (tab === 'not_posted') {
    where.push(`is_posted = 0 AND status NOT IN ('SHIPPED', 'RETURNED', 'HENBIN', 'RETURN', 'REQUEST_RETURN')`);
  } else if (status) {
    where.push(`status = ?`);
    params.push(status);
  }

  if (inventory) {
    where.push(`inventory_status = ?`);
    params.push(inventory);
  }

  if (posted === '1') {
    where.push(`is_posted = 1`);
  } else if (posted === '0') {
    where.push(`is_posted = 0`);
  }

  return { where, params };
}

// ====== List/search ======
app.get("/api/items", requireAuth, async (req, res) => {
  const { where, params } = buildItemQuery(req);

  const sql = `
    SELECT id, package_id, name, serial_clean, mvd, status, inventory_status, is_posted, last_inventory_at, created_at, updated_at, category
    FROM items
    WHERE ${where.join(" AND ")}
    ORDER BY datetime(updated_at) DESC
    LIMIT 1000
  `;

  const { rows } = await db.execute({ sql, args: params });

  // Lấy thống kê số lượng theo loại dựa trên bộ lọc hiện tại
  const summarySql = `
    SELECT coalesce(category, 'else') as category, COUNT(*) as count 
    FROM items 
    WHERE ${where.join(" AND ")}
    GROUP BY category
  `;
  const { rows: summaryRows } = await db.execute({ sql: summarySql, args: params });

  res.json({ rows, summary: summaryRows });
});

app.post("/api/items/export", requireAuth, requireStaff, async (req, res) => {
  const { where, params } = buildItemQuery(req);
  const date_key = yyyymmddLocal();

  try {
    const { rows } = await db.execute({
      sql: `
        SELECT category, name, serial_clean, tracking_code, package_id, mvd, status, inventory_status, created_at, updated_at
        FROM items
        WHERE ${where.join(" AND ")}
        ORDER BY category ASC, name ASC
      `,
      args: params
    });

    if (rows.length === 0) {
      return res.json({ ok: true, url: null, count: 0, message: "No data" });
    }

    const header = ["Category", "Name", "Serial", "Tracking", "PackageID", "MVD", "Status", "InventoryStatus", "Created", "Updated"];
    const csv = [header.join(",")]
      .concat(
        rows.map((r) =>
          [
            csvCell(r.category),
            csvCell(r.name),
            csvCell(r.serial_clean),
            csvCell(r.tracking_code),
            csvCell(r.package_id),
            csvCell(r.mvd),
            csvCell(r.status),
            csvCell(r.inventory_status),
            csvCell(r.created_at),
            csvCell(r.updated_at),
          ].join(",")
        )
      )
      .join("\n");

    const filename = `list_export_${date_key}_${Date.now()}.csv`;
    const filePath = path.join(EXPORT_DIR, filename);
    fs.writeFileSync(filePath, csv, "utf8");
    const url = `/exports/${filename}`;

    await db.execute({
      sql: `
        INSERT INTO inventory_exports(date_key, actor, filename, url, row_count, created_at)
        VALUES(?,?,?,?,?,?)
      `,
      args: [date_key, req.user, filename, url, rows.length, nowISO()]
    });

    res.json({ ok: true, url, count: rows.length, filename });

    // Gửi Telegram (Plain Text)
    sendTelegramDocument(filePath, `Báo cáo Danh sách (Filter)\nNgày: ${date_key}\nSố lượng: ${rows.length} món\nNgười xuất: ${req.user}`)
      .catch(e => console.error("Telegram export notify failed:", e));

  } catch (e) {
    res.status(500).json({ error: "Export failed: " + e.message });
  }
});

// ====== Scan: fetch by token ======
app.get("/api/scan/:token", requireAuth, async (req, res) => {
  const { token } = req.params;
  const { rows } = await db.execute({ sql: "SELECT * FROM items WHERE token = ?", args: [token] });
  const item = rows[0];
  if (!item) return res.status(404).json({ error: "Not found" });
  res.json({ item });
});

// ====== Inventory work ======
app.post("/api/inventory/add", requireAuth, requireStaff, async (req, res) => {
  const { token } = req.body || {};
  if (!token) return res.status(400).json({ error: "Missing token" });

  const { rows: itemRows } = await db.execute({ sql: "SELECT * FROM items WHERE token = ?", args: [token] });
  const item = itemRows[0];
  if (!item) return res.status(404).json({ error: "Not found" });
  if (item.is_deleted === 1 || item.status === "DELETED") {
    return res.status(400).json({ error: "Item is deleted" });
  }
  if (item.status === "SHIPPED") {
    return res.status(400).json({ error: "Hàng đã giao, không thể kiểm kho lại." });
  }

  const date_key = yyyymmddLocal();
  const scanned_at = nowISO();

  try {
    const tx = await db.transaction("write");

    // 1. Thêm vào bảng công việc kiểm kê ngày hôm nay
    await tx.execute({
      sql: `
      INSERT INTO inventory_work(date_key, token, item_id, package_id, name, mvd, serial, actor, scanned_at)
      VALUES(?,?,?,?,?,?,?,?,?)
    `,
      args: [
        date_key,
        token,
        item.id,
        item.package_id || "",
        item.name || "",
        item.mvd || "",
        item.serial_clean || item.serial_raw || "",
        req.user,
        scanned_at
      ]
    });

    // 2. Cập nhật trạng thái trong bảng items chính
    await tx.execute({
      sql: `UPDATE items SET inventory_status = 'IN_STOCK', last_inventory_at = ?, updated_at = ? WHERE id = ?`,
      args: [scanned_at, scanned_at, item.id]
    });

    // 3. Ghi nhật ký kiểm kê (Inventory Logs)
    await tx.execute({
      sql: `INSERT INTO inventory_logs(item_id, action, actor, created_at) VALUES(?,?,?,?)`,
      args: [item.id, 'IN_STOCK', req.user, scanned_at]
    });

    await tx.commit();
    res.json({ ok: true });
  } catch (e) {
    res.status(500).json({ error: e.message || "DB error" });
  }
});

app.get("/api/inventory/today", requireAuth, async (req, res) => {
  const date_key = yyyymmddLocal();
  const { rows } = await db.execute({
    sql: `
    SELECT w.package_id, w.name, w.serial, w.mvd, w.scanned_at, w.actor, w.token, i.category
    FROM inventory_work w
    LEFT JOIN items i ON w.item_id = i.id
    WHERE w.date_key = ?
    ORDER BY datetime(w.scanned_at) DESC
  `,
    args: [date_key]
  });

  res.json({ date_key, rows });
});

app.delete("/api/inventory/exports/:id", requireAuth, requireAdmin, async (req, res) => {
  const id = Number(req.params.id);

  const { rows } = await db.execute({
    sql: `SELECT id, filename FROM inventory_exports WHERE id = ?`,
    args: [id]
  });
  const row = rows[0];

  if (!row) return res.status(404).json({ error: "Not found" });

  const filePath = path.join(EXPORT_DIR, row.filename);

  // xoá file csv (nếu file đã bị xoá trước đó vẫn cho xoá DB)
  try {
    if (fs.existsSync(filePath)) fs.unlinkSync(filePath);
  } catch (e) {
    return res.status(500).json({ error: "Delete file failed" });
  }

  await db.execute({ sql: `DELETE FROM inventory_exports WHERE id = ?`, args: [id] });
  res.json({ ok: true });
});

app.post("/api/inventory/reset", requireAuth, requireSuperAdmin, async (req, res) => {
  try {
    await db.execute({
      sql: `UPDATE items SET inventory_status = 'UNKNOWN', last_inventory_at = NULL WHERE is_deleted = 0`,
      args: []
    });
    res.json({ ok: true, message: "Đã reset toàn bộ trạng thái kiểm kho về UNKNOWN." });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

app.post("/api/inventory/export", requireAuth, requireStaff, async (req, res) => {
  const date_key = yyyymmddLocal();

  try {
    const tx = await db.transaction("write");

    // 1. Lấy hàng đã quét hôm nay (kèm category)
    const { rows: scanned } = await tx.execute({
      sql: `
        SELECT w.package_id, w.name, w.serial, w.mvd, w.scanned_at, w.actor, 'OK' as audit_status, i.category
        FROM inventory_work w
        LEFT JOIN items i ON w.item_id = i.id
        WHERE w.date_key = ?
        ORDER BY datetime(w.scanned_at) DESC
      `,
      args: [date_key]
    });

    // 2. Lấy hàng còn đang UNKNOWN (chưa quét - kèm category)
    const { rows: missing } = await tx.execute({
      sql: `
        SELECT package_id, name, serial_clean as serial, mvd, '-' as scanned_at, '-' as actor, 'MISSING' as audit_status, category
        FROM items
        WHERE inventory_status = 'UNKNOWN' AND is_deleted = 0
        ORDER BY category ASC, name ASC
      `,
      args: []
    });

    const allRows = [...scanned, ...missing];

    if (allRows.length === 0) {
      await tx.rollback();
      return res.json({ ok: true, url: null, count: 0, message: "No data" });
    }

    const header = ["status", "category", "time", "package_id", "mvd", "serial", "name", "actor"];
    const csv = [header.join(",")]
      .concat(
        allRows.map((r) =>
          [
            csvCell(r.audit_status),
            csvCell(r.category || "unknown"),
            csvCell(r.scanned_at),
            csvCell(r.package_id),
            csvCell(r.mvd),
            csvCell(r.serial),
            csvCell(r.name),
            csvCell(r.actor),
          ].join(",")
        )
      )
      .join("\n");

    const filename = `inventory_audit_${date_key}_${Date.now()}.csv`;
    const filePath = path.join(EXPORT_DIR, filename);

    fs.writeFileSync(filePath, csv, "utf8");

    const url = `/exports/${filename}`;

    await tx.execute({
      sql: `
      INSERT INTO inventory_exports(date_key, actor, filename, url, row_count, created_at)
      VALUES(?,?,?,?,?,?)
    `,
      args: [date_key, req.user, filename, url, allRows.length, nowISO()]
    });

    await tx.execute({
      sql: `DELETE FROM inventory_work WHERE date_key = ?`,
      args: [date_key]
    });

    await tx.commit();
    res.json({ ok: true, url, count: allRows.length, filename });

    // Gửi Telegram (Plain Text)
    sendTelegramDocument(filePath, `Báo cáo Kiểm kê Kho (Audit)\nNgày: ${date_key}\nSố lượng: ${allRows.length} món\nNgười xuất: ${req.user}`)
      .catch(e => console.error("Telegram inventory export notify failed:", e));

  } catch (e) {
    res.status(500).json({ error: "Export failed" });
  }
});

app.get("/api/inventory/exports", requireAuth, async (req, res) => {
  const { rows } = await db.execute({
    sql: `
    SELECT id, date_key, actor, filename, url, row_count, created_at
    FROM inventory_exports
    ORDER BY datetime(created_at) DESC
    LIMIT 200
  `
  });
  res.json({ rows });
});

// ====== Update status (ship/henbin) ======
app.post("/api/items/:id/status", requireAuth, requireStaff, async (req, res) => {
  const { id } = req.params;
  const { to_status } = req.body;

  const allowed = new Set(["READY_TO_SHIP", "SHIPPED", "RETURN", "CREATED", "REQUEST_RETURN"]);
  if (!allowed.has(to_status)) return res.status(400).json({ error: "Invalid status" });

  const { rows } = await db.execute({ sql: "SELECT * FROM items WHERE id = ?", args: [id] });
  const item = rows[0];

  if (!item) return res.status(404).json({ error: "Not found" });
  if (item.is_deleted === 1 || item.status === "DELETED") {
    return res.status(400).json({ error: "Item is deleted" });
  }

  const from_status = item.status;
  const updated_at = nowISO();

  let inventory_status = item.inventory_status;
  let shipped_at = item.shipped_at;

  if (to_status === "SHIPPED") {
    inventory_status = "NOT_IN_STOCK";
    shipped_at = updated_at;
  } else if (to_status === "RETURN") {
    inventory_status = "NOT_IN_STOCK";
  }

  await db.execute({
    sql: "UPDATE items SET status = ?, inventory_status = ?, shipped_at = ?, updated_at = ? WHERE id = ?",
    args: [to_status, inventory_status, shipped_at, updated_at, id]
  });

  // CHỈ ghi log nếu trạng thái thay đổi
  if (from_status !== to_status) {
    await db.execute({
      sql: `
      INSERT INTO status_logs(item_id, from_status, to_status, actor, created_at)
      VALUES(?, ?, ?, ?, ?)
    `,
      args: [id, from_status, to_status, req.user, updated_at]
    });

    // Dong bo Telegram
    syncTelegramButtons(id).catch(e => console.error("Sync TG status failed:", e));
  }

  res.json({ ok: true });
});

// ====== Inventory: In stock ======
app.post("/api/items/:id/inventory", requireAuth, requireStaff, async (req, res) => {
  const { id } = req.params;
  const { inventory_status } = req.body;

  const allowed = new Set(["IN_STOCK", "NOT_IN_STOCK", "UNKNOWN"]);
  if (!allowed.has(inventory_status)) return res.status(400).json({ error: "Invalid inventory_status" });

  const { rows } = await db.execute({ sql: "SELECT * FROM items WHERE id = ?", args: [id] });
  const item = rows[0];
  if (!item) return res.status(404).json({ error: "Not found" });
  if (item.is_deleted === 1 || item.status === "DELETED") {
    return res.status(400).json({ error: "Item is deleted" });
  }

  const from_inv = item.inventory_status;
  const t = nowISO();

  await db.execute({
    sql: "UPDATE items SET inventory_status = ?, last_inventory_at = ?, last_inventory_by = ?, updated_at = ? WHERE id = ?",
    args: [inventory_status, t, req.user, t, id]
  });

  // CHỈ ghi log nếu trạng thái kho thay đổi
  if (from_inv !== inventory_status) {
    await db.execute({
      sql: `
      INSERT INTO inventory_logs(item_id, action, actor, created_at)
      VALUES(?, ?, ?, ?)
    `,
      args: [id, inventory_status, req.user, t]
    });
  }

  res.json({ ok: true });
});

app.post("/api/items/:id/posted", requireAuth, async (req, res) => {
  const { id } = req.params;
  const { is_posted } = req.body;

  const { rows } = await db.execute({ sql: "SELECT * FROM items WHERE id = ?", args: [id] });
  const item = rows[0];
  if (!item) return res.status(404).json({ error: "Not found" });

  const updated_at = nowISO();
  const next_val = is_posted ? 1 : 0;

  await db.execute({
    sql: "UPDATE items SET is_posted = ?, updated_at = ? WHERE id = ?",
    args: [next_val, updated_at, id]
  });

  // Chỉ ghi log nếu giá trị thực sự thay đổi
  if (item.is_posted !== next_val) {
    await db.execute({
      sql: `INSERT INTO edit_logs(item_id, actor, changes_json, created_at) VALUES(?,?,?,?)`,
      args: [id, req.user, JSON.stringify({ is_posted: next_val }), updated_at]
    });

    // Dong bo nut bam Telegram neu co
    syncTelegramButtons(id).catch(e => console.error("Sync TG Posted failed:", e));
  }

  res.json({ ok: true });
});

// ====== Toggle Meru Logged Status ======
app.post("/api/items/:id/meru-logged", requireAuth, async (req, res) => {
  const { id } = req.params;
  const { is_meru_logged } = req.body;

  const { rows } = await db.execute({ sql: "SELECT * FROM items WHERE id = ?", args: [id] });
  const item = rows[0];
  if (!item) return res.status(404).json({ error: "Not found" });

  const updated_at = nowISO();
  const next_val = is_meru_logged ? 1 : 0;

  await db.execute({
    sql: "UPDATE items SET is_meru_logged = ?, updated_at = ? WHERE id = ?",
    args: [next_val, updated_at, id]
  });

  if (item.is_meru_logged !== next_val) {
    await db.execute({
      sql: `INSERT INTO edit_logs(item_id, actor, changes_json, created_at) VALUES(?,?,?,?)`,
      args: [id, req.user, JSON.stringify({ is_meru_logged: next_val }), updated_at]
    });

    // Dong bo nut bam Telegram neu co
    syncTelegramButtons(id).catch(e => console.error("Sync TG Meru failed:", e));
  }

  res.json({ ok: true });
});

// ====== Shortcut API: Mark as Posted by Serial ======
app.post("/api/external/mark-posted", async (req, res) => {
  const apiKey = req.headers["x-api-key"];
  if (!apiKey || apiKey !== process.env.SHORTCUT_API_KEY) {
    return res.status(401).json({ error: "Unauthorized" });
  }

  const serial = (req.body.serial ?? "").trim();
  if (!serial || serial.length < 4) {
    return res.status(400).json({ error: "Missing or too short serial" });
  }

  try {
    const { rows } = await db.execute({
      sql: "SELECT * FROM items WHERE (serial_clean = ? OR serial_raw = ?) AND is_deleted = 0 LIMIT 1",
      args: [serial, serial]
    });
    const item = rows[0];

    if (!item) {
      return res.json({ ok: false, error: `Serial not found: ${serial}` });
    }

    if (item.is_posted) {
      return res.json({ ok: true, already: true, message: `Already posted: ${item.package_id} (${item.serial_clean})` });
    }

    const updated_at = nowISO();
    await db.execute({ sql: "UPDATE items SET is_posted = 1, updated_at = ? WHERE id = ?", args: [updated_at, item.id] });
    await db.execute({
      sql: "INSERT INTO edit_logs(item_id, actor, changes_json, created_at) VALUES(?,?,?,?)",
      args: [item.id, "Shortcut", JSON.stringify({ is_posted: 1, method: "shortcut" }), updated_at]
    });

    // Sync Telegram buttons
    syncTelegramButtons(item.id).catch(e => console.error("Sync TG mark-posted failed:", e));

    // Send TG notification to group
    try {
      const msg = `✅ <b>Đã đăng (Shortcut)</b>\n📦 ID: <code>${item.package_id}</code>\n🏷️ ${escTg(item.name)}\n🔢 Serial: <code>${item.serial_clean || "-"}</code>`;
      await fetch(`https://api.telegram.org/bot${process.env.TELEGRAM_BOT_TOKEN}/sendMessage`, {
        method: "POST", headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ chat_id: DELETE_GROUP_CHAT_ID, text: msg, parse_mode: "HTML" })
      });
    } catch (e) { console.error("TG notify mark-posted failed:", e); }

    res.json({ ok: true, message: `Marked as posted: ${item.package_id} — ${item.name} (${item.serial_clean})` });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// ====== Batch Update Posted Status by Serials ======
app.post("/api/items/batch-posted", requireAuth, async (req, res) => {
  const { serials_text } = req.body;
  if (!serials_text) return res.status(400).json({ error: "Missing serials_text" });

  const serials = serials_text.split(/[\n,]/)
    .map(s => s.trim())
    .filter(Boolean);

  if (serials.length === 0) return res.status(400).json({ error: "No valid serials found" });

  try {
    const updated_at = nowISO();
    let totalUpdated = 0;
    const notFound = [];
    const alreadyPosted = [];

    for (const sn of serials) {
      // Tìm máy theo serial_clean hoặc serial_raw
      const { rows } = await db.execute({
        sql: "SELECT id, is_posted FROM items WHERE (serial_clean = ? OR serial_raw = ?) AND is_deleted = 0",
        args: [sn, sn]
      });

      if (rows.length === 0) {
        notFound.push(sn);
        continue;
      }

      for (const item of rows) {
        if (!item.is_posted) {
          await db.execute({
            sql: "UPDATE items SET is_posted = 1, updated_at = ? WHERE id = ?",
            args: [updated_at, item.id]
          });

          await db.execute({
            sql: `INSERT INTO edit_logs(item_id, actor, changes_json, created_at) VALUES(?,?,?,?)`,
            args: [item.id, req.user, JSON.stringify({ is_posted: 1, method: "batch" }), updated_at]
          });
          totalUpdated++;
        } else {
          // Nếu đã đăng rồi, thêm vào danh sách bỏ qua để báo cáo
          if (!alreadyPosted.includes(sn)) alreadyPosted.push(sn);
        }
      }
    }

    res.json({ ok: true, count: totalUpdated, notFound, alreadyPosted });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

app.post("/api/items/:id", requireAuth, async (req, res) => {
  const { rows } = await db.execute({ sql: "SELECT * FROM items WHERE id=?", args: [req.params.id] });
  const it = rows[0];
  if (!it) return res.status(404).json({ error: "Not found" });

  const allowed = ["name", "serial_raw", "serial_clean", "condition", "mvd", "note", "battery", "coverage"];
  const updates = {};
  for (const k of allowed) if (k in req.body) updates[k] = String(req.body[k] ?? "").trim();

  const changes = {};
  for (const k of Object.keys(updates)) {
    if ((it[k] ?? "") !== updates[k]) changes[k] = { from: it[k] ?? "", to: updates[k] };
  }

  const updated_at = nowISO();
  await db.execute({
    sql: `
    UPDATE items SET
      name=?,
      serial_raw=?,
      serial_clean=?,
      condition=?,
      mvd=?,
      note=?,
      battery=?,
      coverage=?,
      updated_at=?
    WHERE id=?
  `,
    args: [
      updates.name ?? it.name,
      updates.serial_raw ?? it.serial_raw,
      updates.serial_clean ?? it.serial_clean,
      updates.condition ?? it.condition,
      updates.mvd ?? it.mvd,
      updates.note ?? it.note,
      updates.battery ?? it.battery,
      updates.coverage ?? it.coverage,
      updated_at,
      req.params.id
    ]
  });

  if (Object.keys(changes).length) {
    await db.execute({
      sql: `
      INSERT INTO edit_logs(item_id, actor, changes_json, created_at)
      VALUES(?,?,?,?)
    `,
      args: [req.params.id, req.user, JSON.stringify(changes), updated_at]
    });
  }

  res.json({ ok: true });
});

app.get("/api/items/:id", requireAuth, async (req, res) => {
  const id = req.params.id;
  const { rows } = await db.execute({ sql: "SELECT * FROM items WHERE id = ?", args: [id] });
  const item = rows[0];
  if (!item) return res.status(404).json({ error: "Not found" });

  const scanUrl = `${req.protocol}://${req.get("host")}/scan.html?token=${encodeURIComponent(item.token)}`;
  const qrDataUrl = await QRCode.toDataURL(item.token, { margin: 1, width: 400, errorCorrectionLevel: 'L' });

  res.json({ item, scanUrl, qrDataUrl });
});

app.get("/api/items/:id/history", requireAuth, async (req, res) => {
  const id = req.params.id;

  const { rows: itemRows } = await db.execute({ sql: "SELECT created_at, created_by FROM items WHERE id = ?", args: [id] });
  const item = itemRows[0];
  if (!item) return res.status(404).json({ error: "Not found" });

  const [statusLogs, invLogs, editLogs] = await Promise.all([
    db.execute({ sql: "SELECT 'status' as type, from_status, to_status, actor, created_at FROM status_logs WHERE item_id = ? ORDER BY created_at ASC", args: [id] }),
    db.execute({ sql: "SELECT 'inventory' as type, action, actor, created_at FROM inventory_logs WHERE item_id = ? ORDER BY created_at ASC", args: [id] }),
    db.execute({ sql: "SELECT 'edit' as type, changes_json, actor, created_at FROM edit_logs WHERE item_id = ? ORDER BY created_at ASC", args: [id] })
  ]);

  const history = [
    { type: 'created', actor: item.created_by || 'System', created_at: item.created_at },
    ...statusLogs.rows,
    ...invLogs.rows,
    ...editLogs.rows
  ].sort((a, b) => new Date(a.created_at) - new Date(b.created_at));

  res.json({ history });
});

// ====== Telegram Bot Diagnostics ======
app.post("/api/telegram/test", requireAuth, requireSuperAdmin, async (req, res) => {
  try {
    // 1. Thử gửi tin nhắn
    await sendTelegramMessage("🔔 <b>Hệ thống WMS:</b> Đang kiểm tra kết nối Bot...");

    // 2. Thử tạo và gửi file mẫu
    const testFile = path.join(EXPORT_DIR, "test_connection.csv");
    fs.writeFileSync(testFile, "ID,Name,Status\n1,Test Item,Success", "utf8");

    await sendTelegramDocument(testFile, "📄 Đây là tệp tin kiểm tra từ hệ thống WMS.");

    res.json({ ok: true, message: "Đã gửi tin nhắn và file mẫu tới Telegram. Hãy kiểm tra điện thoại của bạn!" });
  } catch (e) {
    // Trả về nội dung lỗi chi tiết từ Telegram nếu có
    res.status(500).json({ error: e.message });
  }
});

app.post("/api/telegram/test", requireAuth, requireAdmin, async (req, res) => {
  const token = process.env.TELEGRAM_BOT_TOKEN;
  const chatId = process.env.TELEGRAM_CHAT_ID;

  if (!token || !chatId) {
    return res.status(400).json({ error: "Thiếu cấu hình TELEGRAM_BOT_TOKEN hoặc TELEGRAM_CHAT_ID trên Render." });
  }

  try {
    const text = `🚀 <b>KẾT NỐI THÀNH CÔNG!</b>\n\nHệ thống WMS đã kết nối được với Telegram của bạn.\nThời gian: ${nowISO()}`;
    await sendTelegramMessage(text);
    res.json({ ok: true, message: "Đã gửi tin nhắn test thành công!" });
  } catch (e) {
    res.status(500).json({ error: "Gửi thất bại: " + e.message });
  }
});

// API Chạy tay báo cáo hàng tồn (dành cho Admin)
app.post("/api/telegram/notify-stale-manual", requireAuth, requireAdmin, async (req, res) => {
  try {
    await checkStaleItemsAndNotify(true);
    res.json({ ok: true, message: "Đã kích hoạt quét hàng tồn và gửi qua Telegram." });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// ====== Request Delete (any authenticated user) ======
app.post("/api/items/:id/request-delete", requireAuth, async (req, res) => {
  const id = req.params.id;

  const { rows } = await db.execute({ sql: "SELECT * FROM items WHERE id = ? AND is_deleted = 0", args: [id] });
  const item = rows[0];
  if (!item) return res.status(404).json({ error: "Không tìm thấy sản phẩm" });

  // Kiểm tra nếu đã có yêu cầu đang pending cho item này
  const { rows: pendingRows } = await db.execute({
    sql: "SELECT id FROM delete_requests WHERE item_id = ? AND status = 'PENDING'",
    args: [id]
  });
  if (pendingRows[0]) {
    return res.status(409).json({ error: "Đã có yêu cầu xóa đang chờ duyệt cho sản phẩm này" });
  }

  const t = nowISO();

  // 1. Lưu yêu cầu xóa vào database
  await db.execute({
    sql: "INSERT INTO delete_requests (item_id, requested_by, status, created_at) VALUES (?, ?, 'PENDING', ?)",
    args: [id, req.user, t]
  });

  const { rows: reqRows } = await db.execute({
    sql: "SELECT id FROM delete_requests WHERE item_id = ? AND status = 'PENDING' ORDER BY id DESC LIMIT 1",
    args: [id]
  });
  const reqId = reqRows[0].id;

  // 2. Gửi thông báo Telegram (Yêu cầu xóa)
  const tgToken = process.env.TELEGRAM_BOT_TOKEN;
  if (tgToken) {
    try {
      const targetChatId = DELETE_GROUP_CHAT_ID || "-1003710611209";
      const title = "🗑️ <b>YÊU CẦU XÓA SẢN PHẨM</b>";

      const msg = `${title}\n\n` +
        `📦 ID: <code>${item.package_id}</code>\n` +
        `🏷️ Tên: <b>${escTg(item.name)}</b>\n` +
        `🔢 Serial: <code>${item.serial_clean || "-"}</code>\n` +
        `📍 Trạng thái: ${item.status}\n` +
        `👤 Yêu cầu bởi: <b>${escTg(req.user)}</b>\n` +
        `⏰ Thời gian: ${fmtTimeLocal(t)}`;

      const buttons = [
        { text: "✅ Duyệt xóa", callback_data: `approve_delete:${reqId}` },
        { text: "❌ Từ chối", callback_data: `reject_delete:${reqId}` }
      ];



      const tgRes = await fetch(`https://api.telegram.org/bot${tgToken}/sendMessage`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          chat_id: targetChatId,
          text: msg,
          parse_mode: "HTML",
          reply_markup: { inline_keyboard: [buttons] }
        })
      });
      const tgData = await tgRes.json();

      if (tgData.ok && tgData.result) {
        await db.execute({
          sql: "UPDATE delete_requests SET tg_chat_id = ?, tg_msg_id = ? WHERE id = ?",
          args: [String(tgData.result.chat.id), String(tgData.result.message_id), reqId]
        });
      }
    } catch (e) {
      console.error("Request-delete notify error:", e);
    }
  }

  res.json({ ok: true });
});

// ====== Request Return (Admin only) ======
app.post("/api/items/:id/request-return", requireAuth, requireAdmin, async (req, res) => {
  const id = req.params.id;

  const { rows } = await db.execute({ sql: "SELECT * FROM items WHERE id = ? AND is_deleted = 0", args: [id] });
  const item = rows[0];
  if (!item) return res.status(404).json({ error: "Không tìm thấy sản phẩm" });

  // Kiểm tra pending
  const { rows: pendingRows } = await db.execute({
    sql: "SELECT id FROM delete_requests WHERE item_id = ? AND status = 'PENDING'",
    args: [id]
  });
  if (pendingRows[0]) return res.status(409).json({ error: "Đã có yêu cầu đang chờ duyệt cho sản phẩm này" });

  const t = nowISO();

  // 1. Đổi trạng thái thành REQUEST_RETURN
  await db.execute({
    sql: "UPDATE items SET status = 'REQUEST_RETURN', updated_at = ? WHERE id = ?",
    args: [t, id]
  });

  // 2. Lưu yêu cầu vào DB
  await db.execute({
    sql: "INSERT INTO delete_requests (item_id, requested_by, status, created_at) VALUES (?, ?, 'PENDING', ?)",
    args: [id, req.user, t]
  });

  const { rows: reqRows } = await db.execute({
    sql: "SELECT id FROM delete_requests WHERE item_id = ? AND status = 'PENDING' ORDER BY id DESC LIMIT 1",
    args: [id]
  });
  const reqId = reqRows[0].id;

  // 3. Thông báo Telegram tới Group Return & Delete
  const tgToken = process.env.TELEGRAM_BOT_TOKEN;
  if (tgToken) {
    try {
      const returnGroupId = process.env.RETURN_GROUP_CHAT_ID || "-1003767068395";
      const taskGroupId = process.env.TASK_GROUP_CHAT_ID || returnGroupId;
      const title = "📦 <b>YÊU CẦU RETURN & XÓA</b>";

      const msg = `${title}\n\n` +
        `📦 ID: <code>${item.package_id}</code>\n` +
        `🏷️ Tên: <b>${escTg(item.name)}</b>\n` +
        `🔢 Serial: <code>${item.serial_clean || "-"}</code>\n` +
        `📍 Trạng thái: ${item.status} ➔ <b>REQUEST_RETURN</b>\n` +
        `👤 Yêu cầu bởi: <b>${escTg(req.user)}</b>\n` +
        `⏰ Thời gian: ${fmtTimeLocal(t)}`;

      const buttons = [
        { text: "✅ Duyệt xóa", callback_data: `approve_delete:${reqId}` },
        { text: "❌ Từ chối", callback_data: `reject_delete:${reqId}` }
      ];



      const tgRes = await fetch(`https://api.telegram.org/bot${tgToken}/sendMessage`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          chat_id: returnGroupId,
          text: msg,
          parse_mode: "HTML",
          reply_markup: { inline_keyboard: [buttons] }
        })
      });
      const tgData = await tgRes.json();

      if (tgData.ok && tgData.result) {
        await db.execute({
          sql: "UPDATE delete_requests SET tg_chat_id = ?, tg_msg_id = ? WHERE id = ?",
          args: [String(tgData.result.chat.id), String(tgData.result.message_id), reqId]
        });
      }

      // Gửi task message
      const taskMsg = `📝 <b>TASK: KIỂM TRA HÀNG RETURN</b>\n\n` +
        `📦 ID: <code>${item.package_id}</code>\n` +
        `🏷️ Tên: <b>${escTg(item.name)}</b>\n` +
        `🔢 Serial: <code>${item.serial_clean || "-"}</code>\n` +
        `👤 Người yêu cầu: ${escTg(req.user)}`;

      await fetch(`https://api.telegram.org/bot${tgToken}/sendMessage`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ chat_id: taskGroupId, text: taskMsg, parse_mode: "HTML" })
      });

    } catch (e) {
      console.error("Request-return notify error:", e);
    }
  }

  res.json({ ok: true });
});

app.post("/api/items/:id/delete", requireAuth, requireAdmin, async (req, res) => {
  const id = req.params.id;
  const { rows } = await db.execute({ sql: "SELECT id, package_id, name FROM items WHERE id=?", args: [id] });
  const item = rows[0];
  if (!item) return res.status(404).json({ error: "Not found" });

  const t = nowISO();
  await db.execute({
    sql: `
    UPDATE items
    SET is_deleted=1,
        status='DELETED',
        deleted_at=?,
        deleted_by=?,
        updated_at=?
    WHERE id=?
  `,
    args: [t, req.user, t, id]
  });

  // Gửi thông báo Telegram
  const msg = `🗑️ <b>SẢN PHẨM ĐÃ BỊ XÓA</b>\n\n` +
    `📦 Mã: <code>${item.package_id}</code>\n` +
    `🏷️ Tên: ${item.name}\n` +
    `👤 Người xóa: ${req.user}\n` +
    `⏰ Thời gian: ${fmtTimeLocal(t)}`;
  sendTelegramMessage(msg).catch(e => console.error("Notify delete failed:", e));

  res.json({ ok: true });
});

app.get("/api/me", requireAuth, (req, res) => {
  res.json({ user: req.user, role: req.role });
});


// ====== Category Management ======
app.get("/api/categories", requireAuth, requireSuperAdmin, async (req, res) => {
  const { rows } = await db.execute("SELECT * FROM category_rules ORDER BY id ASC");
  res.json({ rows });
});

app.post("/api/categories", requireAuth, requireSuperAdmin, async (req, res) => {
  const { id, name, keywords, priority } = req.body;
  if (!name || !keywords) return res.status(400).json({ error: "Missing name or keywords" });

  try {
    if (id) {
      await db.execute({
        sql: "UPDATE category_rules SET name = ?, keywords = ?, priority = ? WHERE id = ?",
        args: [name, keywords, priority || 0, id]
      });
    } else {
      await db.execute({
        sql: "INSERT INTO category_rules (name, keywords, priority) VALUES (?, ?, ?)",
        args: [name, keywords, priority || 0]
      });
    }
    await loadCategories(); // Reload cache
    res.json({ ok: true });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

app.delete("/api/categories/:id", requireAuth, requireAdmin, async (req, res) => {
  try {
    await db.execute({ sql: "DELETE FROM category_rules WHERE id = ?", args: [req.params.id] });
    await loadCategories(); // Reload cache
    res.json({ ok: true });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

app.post("/api/categories/reclassify", requireAuth, requireAdmin, async (req, res) => {
  try {
    const { rows: items } = await db.execute("SELECT id, name FROM items WHERE is_deleted = 0");
    const tx = await db.transaction("write");

    for (const item of items) {
      const cat = detectCategory(item.name);
      await tx.execute({
        sql: "UPDATE items SET category = ? WHERE id = ?",
        args: [cat, item.id]
      });
    }

    await tx.commit();
    res.json({ ok: true, count: items.length });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// ====== Start server ======
// Dong bo tat ca cac nut bam tren Telegram (Status, Posted, MeruLogged)
async function syncTelegramButtons(itemId) {
  try {
    const { rows } = await db.execute({
      sql: "SELECT id, package_id, name, serial_clean, condition, status, is_posted, is_meru_logged, tg_chat_id, tg_msg_id, created_at FROM items WHERE id = ?",
      args: [itemId]
    });
    const item = rows[0];
    if (!item || !item.tg_chat_id || !item.tg_msg_id) return;

    const token = process.env.TELEGRAM_BOT_TOKEN;

    // 1. Quay lai Caption don gian
    let caption = `📌 <b>ITEM MỚI (SHORTCUT)</b>\n\n` +
      `📦 ID: <code>${item.package_id}</code>\n` +
      `🏷 Tên: <b>${escTg(item.name)}</b>\n` +
      `🔢 Serial: <code>${item.serial_clean || "-"}</code>\n` +
      `📅 Ngày tạo: ${fmtTimeLocal(item.created_at)}`;

    if (process.env.APP_URL) {
      caption += `\n\n🔗 <a href="${process.env.APP_URL}/item.html?id=${item.id}">Xem chi tiết trên Web</a>`;
    }

    // 2. Nut bam Do/Xanh don gian
    const replyMarkup = {
      inline_keyboard: [
        [
          { text: `${{ READY_TO_SHIP: '🟡', SHIPPED: '🟢', RETURN: '⚫', RETURNED: '⚫', CREATED: '⬜', REQUEST_RETURN: '🟠' }[item.status] || '⬜'} ${item.status}`, callback_data: "none" },
          { text: "↩️", callback_data: `request_return_tg:${item.id}` },
          { text: "🗑️", callback_data: `request_delete_tg:${item.id}` }
        ],
        [
          item.is_posted
            ? { text: "🟢 Posted", callback_data: `posted:${item.id}` }
            : { text: "🔴 Post Meru", callback_data: `posted:${item.id}` },
          item.is_meru_logged
            ? { text: "🟢 Logged", callback_data: `meru:${item.id}` }
            : { text: "🔴 Log Meru", callback_data: `meru:${item.id}` }
        ]
      ]
    };

    const url = `https://api.telegram.org/bot${token}/editMessageCaption`;
    await fetch(url, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        chat_id: item.tg_chat_id,
        message_id: Number(item.tg_msg_id),
        caption: caption,
        parse_mode: "HTML",
        reply_markup: replyMarkup
      })
    });

  } catch (e) {
    console.error("syncTelegramButtons error:", e);
  }
}

app.listen(3000, "0.0.0.0", () => {
  console.log("WMS running:");
  console.log(" - http://localhost:3000/login.html");
});