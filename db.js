// Freo Port - database setup (SQLite)
// Creates freo.db next to this file on first run. Safe to run repeatedly.
const Database = require('better-sqlite3');
const path = require('path');

const db = new Database(process.env.FREO_DB || path.join(__dirname, 'freo.db'));
db.pragma('journal_mode = WAL');
db.pragma('foreign_keys = ON');

db.exec(`
  CREATE TABLE IF NOT EXISTS users (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    name          TEXT NOT NULL UNIQUE COLLATE NOCASE,
    password_hash TEXT NOT NULL,
    salt          TEXT NOT NULL,
    status        TEXT NOT NULL DEFAULT 'pending',   -- pending | approved | revoked
    is_admin      INTEGER NOT NULL DEFAULT 0,
    created_at    TEXT NOT NULL DEFAULT (datetime('now'))
  );

  CREATE TABLE IF NOT EXISTS sessions (
    token_hash TEXT PRIMARY KEY,
    user_id    INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    created_at TEXT NOT NULL DEFAULT (datetime('now'))
  );

  -- Used in step 2 (created now so the schema is complete)
  CREATE TABLE IF NOT EXISTS ships (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    name       TEXT NOT NULL,
    imo        TEXT UNIQUE,            -- optional, but unique when present
    agency     TEXT,
    created_at TEXT NOT NULL DEFAULT (datetime('now'))
  );

  CREATE TABLE IF NOT EXISTS visits (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    ship_id     INTEGER NOT NULL REFERENCES ships(id) ON DELETE CASCADE,
    visit_date  TEXT NOT NULL,         -- YYYY-MM-DD
    description TEXT,
    created_by  INTEGER REFERENCES users(id) ON DELETE SET NULL,
    created_at  TEXT NOT NULL DEFAULT (datetime('now'))
  );

  CREATE INDEX IF NOT EXISTS idx_ships_name  ON ships(name);
  CREATE INDEX IF NOT EXISTS idx_visits_ship ON visits(ship_id);
`);

// Upgrade a database created before admin accounts existed
const userColumns = db.prepare('PRAGMA table_info(users)').all().map(c => c.name);
if (!userColumns.includes('is_admin')) {
  db.exec('ALTER TABLE users ADD COLUMN is_admin INTEGER NOT NULL DEFAULT 0');
}

module.exports = db;
