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
};

const SESSION_SECRET = process.env.SESSION_SECRET || "dev-secret-change-me";

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
  const chatId = String(process.env.TELEGRAM_CHAT_ID);
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
app.post("/api/items", requireAuth, async (req, res) => {
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

    // ... insert ...
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
    where.push(`status IN ('HENBIN', 'RETURNED')`);
  } else if (tab === 'not_posted') {
    where.push(`is_posted = 0`);
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

app.post("/api/items/export", requireAuth, async (req, res) => {
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
app.post("/api/inventory/add", requireAuth, async (req, res) => {
  const { token } = req.body || {};
  if (!token) return res.status(400).json({ error: "Missing token" });

  const { rows: itemRows } = await db.execute({ sql: "SELECT * FROM items WHERE token = ?", args: [token] });
  const item = itemRows[0];
  if (!item) return res.status(404).json({ error: "Not found" });
  if (item.is_deleted === 1 || item.status === "DELETED") {
    return res.status(400).json({ error: "Item is deleted" });
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

app.post("/api/inventory/reset", requireAuth, requireAdmin, async (req, res) => {
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

app.post("/api/inventory/export", requireAuth, async (req, res) => {
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
app.post("/api/items/:id/status", requireAuth, async (req, res) => {
  const { id } = req.params;
  const { to_status } = req.body;

  const allowed = new Set(["READY_TO_SHIP", "SHIPPED", "HENBIN", "CREATED"]);
  if (!allowed.has(to_status)) return res.status(400).json({ error: "Invalid status" });

  const { rows } = await db.execute({ sql: "SELECT * FROM items WHERE id = ?", args: [id] });
  const item = rows[0];

  if (!item) return res.status(404).json({ error: "Not found" });
  if (item.is_deleted === 1 || item.status === "DELETED") {
    return res.status(400).json({ error: "Item is deleted" });
  }

  const from_status = item.status;
  const updated_at = nowISO();

  await db.execute({ sql: "UPDATE items SET status = ?, updated_at = ? WHERE id = ?", args: [to_status, updated_at, id] });

  // CHỈ ghi log nếu trạng thái thay đổi
  if (from_status !== to_status) {
    await db.execute({
      sql: `
      INSERT INTO status_logs(item_id, from_status, to_status, actor, created_at)
      VALUES(?, ?, ?, ?, ?)
    `,
      args: [id, from_status, to_status, req.user, updated_at]
    });
  }

  res.json({ ok: true });
});

// ====== Inventory: In stock ======
app.post("/api/items/:id/inventory", requireAuth, async (req, res) => {
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
  await db.execute({
    sql: "UPDATE items SET is_posted = ?, updated_at = ? WHERE id = ?",
    args: [is_posted ? 1 : 0, updated_at, id]
  });

  await db.execute({
    sql: `INSERT INTO edit_logs(item_id, actor, changes_json, created_at) VALUES(?,?,?,?)`,
    args: [id, req.user, JSON.stringify({ is_posted: is_posted ? 1 : 0 }), updated_at]
  });

  res.json({ ok: true });
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
  const qrDataUrl = await QRCode.toDataURL(item.token, { margin: 1, width: 600, errorCorrectionLevel: 'L' });

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

// ====== Telegram Test API ======
app.post("/api/telegram/test-all", requireAuth, requireAdmin, async (req, res) => {
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
app.get("/api/categories", requireAuth, requireAdmin, async (req, res) => {
  const { rows } = await db.execute("SELECT * FROM category_rules ORDER BY id ASC");
  res.json({ rows });
});

app.post("/api/categories", requireAuth, requireAdmin, async (req, res) => {
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
app.listen(3000, "0.0.0.0", () => {
  console.log("WMS running:");
  console.log(" - http://localhost:3000/login.html");
});