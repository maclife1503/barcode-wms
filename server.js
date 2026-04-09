// server.js
const fs = require("fs");
const path = require("path");
require("dotenv").config();
const bcrypt = require("bcryptjs");
const express = require("express");
const cookieParser = require("cookie-parser");
const QRCode = require("qrcode");
const crypto = require("crypto");
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
function nowISO() {
  return new Date().toISOString();
}
function genToken() {
  return crypto.randomBytes(24).toString("hex");
}
function yyyymmddVN(d = new Date()) {
  const parts = new Intl.DateTimeFormat("en-CA", {
    timeZone: "Asia/Ho_Chi_Minh",
    year: "numeric",
    month: "2-digit",
    day: "2-digit",
  }).formatToParts(d);

  const y = parts.find((p) => p.type === "year").value;
  const m = parts.find((p) => p.type === "month").value;
  const day = parts.find((p) => p.type === "day").value;
  return `${y}${m}${day}`;
}
function pad2(n) {
  return String(n).padStart(2, "0");
}
function todayKey() {
  const d = new Date();
  const y = d.getFullYear();
  const m = String(d.getMonth() + 1).padStart(2, "0");
  const day = String(d.getDate()).padStart(2, "0");
  return `${y}${m}${day}`;
}
function nextPackageId() {
  const key = todayKey();
  const row = db
    .prepare(
      `
    SELECT package_id
    FROM items
    WHERE package_id LIKE ?
    ORDER BY package_id DESC
    LIMIT 1
  `
    )
    .get(`${key}%`);

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

    const existed = db
      .prepare(
        `
      SELECT id, package_id, name, serial_clean
      FROM items
      WHERE serial_clean = ?
        AND is_deleted = 0
      LIMIT 1
    `
      )
      .get(fields.serial_clean);

    if (existed) {
      return res.status(409).json({
        error: "Đã có item này (serial trùng) và đang tồn tại.",
        existed,
      });
    }

    const package_id = nextPackageId();
    const token = genToken();

    const created_at = nowISO();
    const updated_at = created_at;

    try {
      db.prepare(
        `
        INSERT INTO items (
          package_id, token,
          name, serial_raw, serial_clean, condition, mvd, note, battery, coverage,
          status, inventory_status,
          created_at, updated_at,
          is_deleted, deleted_at, deleted_by
        ) VALUES (
          @package_id, @token,
          @name, @serial_raw, @serial_clean, @condition, @mvd, @note, @battery, @coverage,
          'READY_TO_SHIP', 'UNKNOWN',
          @created_at, @updated_at,
          0, NULL, NULL
        )
      `
      ).run({
        package_id,
        token,
        ...fields,
        created_at,
        updated_at,
      });
    } catch (e) {
      if (String(e.message || "").toLowerCase().includes("unique")) {
        return res.status(409).json({ error: "Đã có item này (serial trùng) và đang tồn tại." });
      }
      throw e;
    }

    const item = db.prepare("SELECT * FROM items WHERE token = ?").get(token);

    const scanUrl = `${req.protocol}://${req.get("host")}/scan.html?token=${encodeURIComponent(token)}`;
    const qrDataUrl = await QRCode.toDataURL(scanUrl, { margin: 0, width: 400 });

    res.json({ item, scanUrl, qrDataUrl });
  } catch (e) {
    res.status(400).json({ error: e.message || "Create failed" });
  }
});

// ====== List/search ======
app.get("/api/items", requireAuth, (req, res) => {
  const { q = "", status = "", inventory = "" } = req.query;
  const like = `%${q}%`;

  const where = ["is_deleted = 0"];
  const params = {};

  if (q) {
    where.push(
      `(package_id LIKE @like OR name LIKE @like OR serial_clean LIKE @like OR tracking_code LIKE @like)`
    );
    params.like = like;
  }
  if (status) {
    where.push(`status = @status`);
    params.status = status;
  }
  if (inventory) {
    where.push(`inventory_status = @inventory`);
    params.inventory = inventory;
  }

  const sql = `
    SELECT id, package_id, name, serial_clean, mvd, status, inventory_status, last_inventory_at
    FROM items
    WHERE ${where.join(" AND ")}
    ORDER BY datetime(updated_at) DESC
    LIMIT 500
  `;

  const rows = db.prepare(sql).all(params);
  res.json({ rows });
});

// ====== Scan: fetch by token ======
app.get("/api/scan/:token", requireAuth, (req, res) => {
  const { token } = req.params;
  const item = db.prepare("SELECT * FROM items WHERE token = ?").get(token);
  if (!item) return res.status(404).json({ error: "Not found" });
  res.json({ item });
});

// ====== Inventory work ======
app.post("/api/inventory/add", requireAuth, (req, res) => {
  const { token } = req.body || {};
  if (!token) return res.status(400).json({ error: "Missing token" });

  const item = db.prepare("SELECT * FROM items WHERE token = ?").get(token);
  if (!item) return res.status(404).json({ error: "Not found" });
  if (item.is_deleted === 1 || item.status === "DELETED") {
    return res.status(400).json({ error: "Item is deleted" });
  }

  const date_key = yyyymmddVN(new Date());
  const scanned_at = nowISO();

  try {
    db.prepare(
      `
      INSERT INTO inventory_work(date_key, token, item_id, package_id, name, mvd, serial, actor, scanned_at)
      VALUES(?,?,?,?,?,?,?,?,?)
    `
    ).run(
      date_key,
      token,
      item.id,
      item.package_id || "",
      item.name || "",
      item.mvd || "",
      item.serial_clean || item.serial_raw || "",
      req.user,
      scanned_at
    );

    res.json({ ok: true });
  } catch (e) {
    if (String(e.message || "").toLowerCase().includes("unique")) {
      return res.status(409).json({ error: "Mã đã nhập trong bảng hôm nay." });
    }
    res.status(500).json({ error: "DB error" });
  }
});

app.get("/api/inventory/today", requireAuth, (req, res) => {
  const date_key = yyyymmddVN(new Date());
  const rows = db
    .prepare(
      `
    SELECT package_id, name, serial, mvd, scanned_at, actor, token
    FROM inventory_work
    WHERE date_key = ?
    ORDER BY datetime(scanned_at) DESC
  `
    )
    .all(date_key);

  res.json({ date_key, rows });
});

app.delete("/api/inventory/exports/:id", requireAuth, requireAdmin, (req, res) => {
  const id = Number(req.params.id);

  const row = db.prepare(`
    SELECT id, filename
    FROM inventory_exports
    WHERE id = ?
  `).get(id);

  if (!row) return res.status(404).json({ error: "Not found" });

  const filePath = path.join(EXPORT_DIR, row.filename);

  // xoá file csv (nếu file đã bị xoá trước đó vẫn cho xoá DB)
  try {
    if (fs.existsSync(filePath)) fs.unlinkSync(filePath);
  } catch (e) {
    return res.status(500).json({ error: "Delete file failed" });
  }

  db.prepare(`DELETE FROM inventory_exports WHERE id = ?`).run(id);
  res.json({ ok: true });
});

app.post("/api/inventory/export", requireAuth, (req, res) => {
  const date_key = yyyymmddVN(new Date());

  const tx = db.transaction(() => {
    const rows = db
      .prepare(
        `
      SELECT package_id, name, serial, mvd, scanned_at, actor
      FROM inventory_work
      WHERE date_key = ?
      ORDER BY datetime(scanned_at) DESC
    `
      )
      .all(date_key);

    if (rows.length === 0) return { empty: true };

    const header = ["time", "package_id", "mvd", "serial", "name", "actor"];
    const csv = [header.join(",")]
      .concat(
        rows.map((r) =>
          [
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

    const filename = `inventory_${date_key}_${Date.now()}.csv`;
    const filePath = path.join(EXPORT_DIR, filename);

    fs.writeFileSync(filePath, csv, "utf8");

    const url = `/exports/${filename}`;
    db.prepare(
      `
      INSERT INTO inventory_exports(date_key, actor, filename, url, row_count, created_at)
      VALUES(?,?,?,?,?,?)
    `
    ).run(date_key, req.user, filename, url, rows.length, nowISO());

    db.prepare(`DELETE FROM inventory_work WHERE date_key = ?`).run(date_key);

    return { empty: false, url, count: rows.length, filename };
  });

  try {
    const out = tx();
    if (out.empty) return res.json({ ok: true, url: null, count: 0, message: "No data" });
    res.json({ ok: true, url: out.url, count: out.count });
  } catch {
    res.status(500).json({ error: "Export failed" });
  }
});

app.get("/api/inventory/exports", requireAuth, (req, res) => {
  const rows = db
    .prepare(
      `
    SELECT id, date_key, actor, filename, url, row_count, created_at
    FROM inventory_exports
    ORDER BY datetime(created_at) DESC
    LIMIT 200
  `
    )
    .all();
  res.json({ rows });
});

// ====== Update status (ship/henbin) ======
app.post("/api/items/:id/status", requireAuth, (req, res) => {
  const { id } = req.params;
  const { to_status } = req.body;

  const allowed = new Set(["READY_TO_SHIP", "SHIPPED", "HENBIN", "CREATED"]);
  if (!allowed.has(to_status)) return res.status(400).json({ error: "Invalid status" });

  const item = db.prepare("SELECT * FROM items WHERE id = ?").get(id);
  if (!item) return res.status(404).json({ error: "Not found" });
  if (item.is_deleted === 1 || item.status === "DELETED") {
    return res.status(400).json({ error: "Item is deleted" });
  }

  const from_status = item.status;
  const updated_at = nowISO();

  db.prepare("UPDATE items SET status = ?, updated_at = ? WHERE id = ?").run(to_status, updated_at, id);
  db.prepare(
    `
    INSERT INTO status_logs(item_id, from_status, to_status, actor, created_at)
    VALUES(?, ?, ?, ?, ?)
  `
  ).run(id, from_status, to_status, req.user, updated_at);

  res.json({ ok: true });
});

// ====== Inventory: In stock ======
app.post("/api/items/:id/inventory", requireAuth, (req, res) => {
  const { id } = req.params;
  const { inventory_status } = req.body;

  const allowed = new Set(["IN_STOCK", "NOT_IN_STOCK", "UNKNOWN"]);
  if (!allowed.has(inventory_status)) return res.status(400).json({ error: "Invalid inventory_status" });

  const item = db.prepare("SELECT * FROM items WHERE id = ?").get(id);
  if (!item) return res.status(404).json({ error: "Not found" });
  if (item.is_deleted === 1 || item.status === "DELETED") {
    return res.status(400).json({ error: "Item is deleted" });
  }

  const t = nowISO();
  db.prepare(
    `
    UPDATE items
    SET inventory_status = ?,
        last_inventory_at = ?,
        last_inventory_by = ?,
        updated_at = ?
    WHERE id = ?
  `
  ).run(inventory_status, t, req.user, t, id);

  if (inventory_status === "IN_STOCK" || inventory_status === "NOT_IN_STOCK") {
    db.prepare(
      `
      INSERT INTO inventory_logs(item_id, action, actor, created_at)
      VALUES(?, ?, ?, ?)
    `
    ).run(id, inventory_status, req.user, t);
  }

  res.json({ ok: true });
});

app.post("/api/items/:id", requireAuth, (req, res) => {
  const it = db.prepare("SELECT * FROM items WHERE id=?").get(req.params.id);
  if (!it) return res.status(404).json({ error: "Not found" });

  const allowed = ["name", "serial_raw", "serial_clean", "condition", "mvd", "note", "battery", "coverage"];
  const updates = {};
  for (const k of allowed) if (k in req.body) updates[k] = String(req.body[k] ?? "").trim();

  const changes = {};
  for (const k of Object.keys(updates)) {
    if ((it[k] ?? "") !== updates[k]) changes[k] = { from: it[k] ?? "", to: updates[k] };
  }

  const updated_at = nowISO();
  db.prepare(
    `
    UPDATE items SET
      name=@name,
      serial_raw=@serial_raw,
      serial_clean=@serial_clean,
      condition=@condition,
      mvd=@mvd,
      note=@note,
      battery=@battery,
      coverage=@coverage,
      updated_at=@updated_at
    WHERE id=@id
  `
  ).run({
    id: req.params.id,
    name: updates.name ?? it.name,
    serial_raw: updates.serial_raw ?? it.serial_raw,
    serial_clean: updates.serial_clean ?? it.serial_clean,
    condition: updates.condition ?? it.condition,
    mvd: updates.mvd ?? it.mvd,
    note: updates.note ?? it.note,
    battery: updates.battery ?? it.battery,
    coverage: updates.coverage ?? it.coverage,
    updated_at,
  });

  if (Object.keys(changes).length) {
    db.prepare(
      `
      INSERT INTO edit_logs(item_id, actor, changes_json, created_at)
      VALUES(?,?,?,?)
    `
    ).run(req.params.id, req.user, JSON.stringify(changes), updated_at);
  }

  res.json({ ok: true });
});

app.get("/api/items/:id", requireAuth, async (req, res) => {
  const id = req.params.id;
  const item = db.prepare("SELECT * FROM items WHERE id = ?").get(id);
  if (!item) return res.status(404).json({ error: "Not found" });

  const scanUrl = `${req.protocol}://${req.get("host")}/scan.html?token=${encodeURIComponent(item.token)}`;
  const qrDataUrl = await QRCode.toDataURL(scanUrl, { margin: 0, width: 600 });

  res.json({ item, scanUrl, qrDataUrl });
});

app.post("/api/items/:id/delete", requireAuth, requireAdmin, (req, res) => {
  const id = req.params.id;
  const item = db.prepare("SELECT id FROM items WHERE id=?").get(id);
  if (!item) return res.status(404).json({ error: "Not found" });

  const t = nowISO();
  db.prepare(
    `
    UPDATE items
    SET is_deleted=1,
        status='DELETED',
        deleted_at=?,
        deleted_by=?,
        updated_at=?
    WHERE id=?
  `
  ).run(t, req.user, t, id);

  res.json({ ok: true });
});

app.get("/api/me", requireAuth, (req, res) => {
  res.json({ user: req.user, role: req.role });
});

// ====== Backup API (Telegram) ======
app.get("/api/backup-database", async (req, res) => {
  const { key } = req.query;
  const secretKey = process.env.BACKUP_SECRET_KEY;
  if (!secretKey || key !== secretKey) {
    return res.status(403).json({ error: "Invalid or missing token" });
  }

  const botToken = process.env.TELEGRAM_BOT_TOKEN;
  const chatId = process.env.TELEGRAM_CHAT_ID;
  if (!botToken || !chatId) {
    return res.status(500).json({ error: "Telegram config missing" });
  }

  try {
    const backupFile = `backup-${Date.now()}.sqlite`;
    // Gọi lệnh backup an toàn của SQLite (gom tất cả dữ liệu từ WAL vào 1 file)
    await db.backup(backupFile);

    const fileBuffer = fs.readFileSync(backupFile);
    const blob = new Blob([fileBuffer]);
    const formData = new FormData();
    formData.append("document", blob, `wms_${new Date().toISOString().slice(0, 10)}.sqlite`);
    
    const tgUrl = `https://api.telegram.org/bot${botToken}/sendDocument?chat_id=${chatId}&caption=Database Backup ${new Date().toISOString()}`;
    
    const response = await fetch(tgUrl, {
      method: "POST",
      body: formData,
    });

    const data = await response.json();
    
    // Xoá file backup tạm
    if (fs.existsSync(backupFile)) {
      fs.unlinkSync(backupFile);
    }

    if (data.ok) {
      res.json({ ok: true, message: "Backup sent successfully" });
    } else {
      console.error("TG API error:", data);
      res.status(500).json({ error: "Telegram API error", detail: data });
    }
  } catch (err) {
    console.error("Backup error:", err);
    res.status(500).json({ error: err.message });
  }
});

// ====== Start server ======
app.listen(3000, "0.0.0.0", () => {
  console.log("WMS running:");
  console.log(" - http://localhost:3000/login.html");
});