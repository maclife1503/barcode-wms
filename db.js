// db.js
const { createClient } = require("@libsql/client");

const url = process.env.TURSO_DATABASE_URL || "file:wms.sqlite";
const authToken = process.env.TURSO_AUTH_TOKEN;

const db = createClient({
  url,
  authToken
});

async function initDb() {
  await db.executeMultiple(`
CREATE TABLE IF NOT EXISTS items (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  package_id TEXT UNIQUE NOT NULL,
  token TEXT UNIQUE NOT NULL,

  name TEXT,
  serial_raw TEXT,
  serial_clean TEXT,
  condition TEXT,
  mvd TEXT,
  note TEXT,
  battery TEXT,
  coverage TEXT,
  tracking_code TEXT,

  status TEXT NOT NULL DEFAULT 'CREATED', -- CREATED | READY_TO_SHIP | SHIPPED | HENBIN
  inventory_status TEXT NOT NULL DEFAULT 'UNKNOWN', -- UNKNOWN | IN_STOCK | NOT_IN_STOCK
  last_inventory_at TEXT,
  last_inventory_by TEXT,

  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL,
  created_by TEXT,
  category TEXT,
  is_deleted INTEGER NOT NULL DEFAULT 0,
  is_posted INTEGER NOT NULL DEFAULT 0,
  deleted_at TEXT,
  deleted_by TEXT,

  tg_chat_id TEXT,
  tg_msg_id TEXT

);

CREATE TABLE IF NOT EXISTS status_logs (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  item_id INTEGER NOT NULL,
  from_status TEXT,
  to_status TEXT,
  actor TEXT,
  created_at TEXT NOT NULL,
  FOREIGN KEY(item_id) REFERENCES items(id)
);

CREATE TABLE IF NOT EXISTS inventory_logs (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  item_id INTEGER NOT NULL,
  action TEXT NOT NULL, -- IN_STOCK | NOT_IN_STOCK
  actor TEXT,
  created_at TEXT NOT NULL,
  FOREIGN KEY(item_id) REFERENCES items(id)
);
CREATE TABLE IF NOT EXISTS inventory_work (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  date_key TEXT NOT NULL,         -- YYYYMMDD (Asia/Ho_Chi_Minh)
  token TEXT NOT NULL,
  item_id INTEGER NOT NULL,
  package_id TEXT,
  name TEXT,
  mvd TEXT,
  serial TEXT,
  actor TEXT,
  scanned_at TEXT NOT NULL,
  UNIQUE(date_key, token),
  FOREIGN KEY(item_id) REFERENCES items(id)
);

CREATE TABLE IF NOT EXISTS inventory_exports (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  date_key TEXT NOT NULL,         -- YYYYMMDD
  actor TEXT,
  filename TEXT NOT NULL,         -- ví dụ inventory_20260210_...csv
  url TEXT NOT NULL,              -- /exports/...
  row_count INTEGER NOT NULL,
  created_at TEXT NOT NULL
);
  `);

  // Migration: Thêm cột created_by và category vào bảng items nếu chưa có
  try {
    await db.execute("ALTER TABLE items ADD COLUMN created_by TEXT");
  } catch(e) { /* ignore */ }
  try {
    await db.execute("ALTER TABLE items ADD COLUMN category TEXT");
  } catch(e) { /* ignore */ }
  try {
    await db.execute("ALTER TABLE items ADD COLUMN is_posted INTEGER NOT NULL DEFAULT 0");
  } catch(e) { /* ignore */ }
  try {
    await db.execute("ALTER TABLE items ADD COLUMN tg_chat_id TEXT");
  } catch(e) { /* ignore */ }
  try {
    await db.execute("ALTER TABLE items ADD COLUMN tg_msg_id TEXT");
  } catch(e) { /* ignore */ }

  // Migration: Phân loại hàng loạt cho các máy cũ chưa có category
  try {
    await db.execute(`
      UPDATE items SET category = CASE 
        WHEN lower(name) LIKE '%ipad%' THEN 'ipad'
        WHEN lower(name) LIKE '%magic%' OR lower(name) LIKE '%keyboard%' OR lower(name) LIKE '%key%' THEN 'keyboard'
        WHEN lower(name) LIKE '%aw%' OR lower(name) LIKE '%apple watch%' THEN 'apple_watch'
        WHEN lower(name) LIKE '%pen%' OR lower(name) LIKE '%pencil%' THEN 'pencil'
        WHEN lower(name) LIKE '%mac%' OR lower(name) LIKE '%macbook%' OR lower(name) LIKE '%imac%' THEN 'macbook'
        WHEN lower(name) LIKE '%iphone%' THEN 'iphone'
        ELSE 'else'
      END 
      WHERE (category IS NULL OR category = '') 
        AND is_deleted = 0
    `);
  } catch(e) { console.error("Batch classification failed:", e); }

  await db.executeMultiple(`
CREATE TABLE IF NOT EXISTS edit_logs (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  item_id INTEGER NOT NULL,
  actor TEXT,
  changes_json TEXT NOT NULL, -- JSON string mô tả các trường bị đổi
  created_at TEXT NOT NULL,
  FOREIGN KEY(item_id) REFERENCES items(id)
);

CREATE TABLE IF NOT EXISTS kv_store (
  key TEXT PRIMARY KEY,
  value TEXT
);

CREATE TABLE IF NOT EXISTS category_rules (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  name TEXT UNIQUE NOT NULL,
  keywords TEXT NOT NULL, -- dấu phẩy cách nhau
  priority INTEGER DEFAULT 0
);
  `);

  // Migration: Thêm cột priority nếu chưa có
  try {
    await db.execute("ALTER TABLE category_rules ADD COLUMN priority INTEGER DEFAULT 0");
  } catch(e) { /* ignore */ }

  // Seed dữ liệu khởi tạo cho category_rules nếu bảng trống
  try {
    const { rows } = await db.execute("SELECT count(*) as count FROM category_rules");
    if (rows[0].count === 0) {
      const initialRules = [
        ['ipad', 'ipad', 5],
        ['keyboard', 'magic,keyboard,key', 10],
        ['apple_watch', 'aw,apple watch', 10],
        ['pencil', 'pen,pencil', 10],
        ['macbook', 'mac,macbook,imac', 5],
        ['iphone', 'iphone', 5]
      ];
      for (const [name, kw, prio] of initialRules) {
        await db.execute({
          sql: "INSERT INTO category_rules (name, keywords, priority) VALUES (?, ?, ?)",
          args: [name, kw, prio]
        });
      }
    }
  } catch(e) { console.error("Seeding categories failed:", e); }
}

initDb().catch(console.error);

module.exports = db;
