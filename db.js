// db.js
const Database = require("better-sqlite3");

const dbPath = process.env.DB_PATH || "wms.sqlite";
const db = new Database(dbPath);

db.exec(`
PRAGMA journal_mode = WAL;

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
  is_deleted INTEGER NOT NULL DEFAULT 0,
  deleted_at TEXT,
  deleted_by TEXT

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

module.exports = db;
