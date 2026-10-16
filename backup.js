// Freo Port - verified database backup
// Safe to run while the server is running (uses SQLite's online backup).
// Keeps the newest FREO_BACKUP_KEEP backups (default 14) and deletes older ones.
const Database = require('better-sqlite3');
const fs = require('fs');
const path = require('path');

const DB_PATH = process.env.FREO_DB || path.join(__dirname, 'freo.db');
const BACKUP_DIR =
  process.env.FREO_BACKUP_DIR || path.join(process.env.HOME || __dirname, 'freo-backups');
const KEEP = parseInt(process.env.FREO_BACKUP_KEEP || '14', 10);

function stamp() {
  const d = new Date();
  const p = n => String(n).padStart(2, '0');
  return `${d.getFullYear()}-${p(d.getMonth() + 1)}-${p(d.getDate())}_` +
         `${p(d.getHours())}-${p(d.getMinutes())}-${p(d.getSeconds())}`;
}

// Deletes a backup file and any leftover companion files
function removeBackup(file) {
  for (const f of [file, `${file}-wal`, `${file}-shm`]) {
    try { fs.unlinkSync(f); } catch (e) { /* not there */ }
  }
}

(async () => {
  if (!fs.existsSync(DB_PATH)) {
    throw new Error(`Database not found at ${DB_PATH}`);
  }
  fs.mkdirSync(BACKUP_DIR, { recursive: true });
  const dest = path.join(BACKUP_DIR, `freo-${stamp()}.db`);

  // 1. Take a consistent snapshot
  const source = new Database(DB_PATH, { readonly: true });
  try {
    await source.backup(dest);
  } finally {
    source.close();
  }

  // 2. Make the snapshot a single self-contained file (no -wal/-shm
  //    companions), then check it is sound before trusting it
  const check = new Database(dest);
  let counts;
  try {
    check.pragma('journal_mode = DELETE');
    const result = check.pragma('integrity_check', { simple: true });
    if (result !== 'ok') {
      throw new Error(`Integrity check failed: ${result}`);
    }
    counts = {
      users: check.prepare('SELECT COUNT(*) AS n FROM users').get().n,
      ships: check.prepare('SELECT COUNT(*) AS n FROM ships').get().n,
      visits: check.prepare('SELECT COUNT(*) AS n FROM visits').get().n,
    };
  } catch (err) {
    check.close();
    removeBackup(dest); // never keep a bad backup
    throw err;
  }
  check.close();

  // 3. Keep only the newest KEEP backups
  const files = fs.readdirSync(BACKUP_DIR)
    .filter(f => /^freo-.*\.db$/.test(f))
    .sort(); // names start with the date, so oldest first
  const old = files.slice(0, Math.max(0, files.length - KEEP));
  old.forEach(f => removeBackup(path.join(BACKUP_DIR, f)));

  console.log(
    `Backup OK: ${path.basename(dest)} ` +
    `(${counts.users} users, ${counts.ships} ships, ${counts.visits} visits). ` +
    `Kept ${files.length - old.length}, removed ${old.length}.`
  );
})().catch(err => {
  console.error('Backup FAILED:', err.message);
  process.exit(1);
});
