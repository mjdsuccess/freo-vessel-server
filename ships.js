// Freo Port - ships and visit records (all routes need a logged-in, approved volunteer)
const express = require('express');
const db = require('./db');
const { requireUser } = require('./auth');

const router = express.Router();
router.use(['/ships', '/visits'], requireUser);

// ---------- validation helpers ----------

function cleanText(value, max) {
  return String(value == null ? '' : value).trim().slice(0, max);
}

// IMO numbers are 7 digits. Accepts "IMO 9123456" or "9123456". Empty is allowed.
function parseImo(value) {
  const s = String(value == null ? '' : value).replace(/^imo\s*/i, '').replace(/\s+/g, '');
  if (s === '') return { ok: true, imo: null };
  if (!/^\d{7}$/.test(s)) return { ok: false };
  return { ok: true, imo: s };
}

// YYYY-MM-DD, a real calendar date, not more than a day ahead
function parseDate(value) {
  const s = String(value || '').trim();
  if (!/^\d{4}-\d{2}-\d{2}$/.test(s)) return null;
  const d = new Date(s + 'T00:00:00Z');
  if (isNaN(d) || d.toISOString().slice(0, 10) !== s) return null;
  if (d.getTime() > Date.now() + 36 * 3600 * 1000) return null;
  return s;
}

function shipFields(body) {
  const name = cleanText(body.name, 100);
  const agency = cleanText(body.agency, 100) || null;
  const imo = parseImo(body.imo);
  if (!name) return { error: 'Ship name is required' };
  if (!imo.ok) return { error: 'IMO number must be 7 digits' };
  return { name, agency, imo: imo.imo };
}

function likeEscape(s) {
  return s.replace(/[\\%_]/g, c => '\\' + c);
}

// ---------- ships ----------

// Search: /ships?q=text  (matches name anywhere, or IMO starting with the text)
// With no q, returns the 100 most recently visited ships.
router.get('/ships', (req, res) => {
  const q = cleanText(req.query.q, 100);
  const base = `
    SELECT s.id, s.name, s.imo, s.agency,
           COUNT(v.id) AS visit_count, MAX(v.visit_date) AS last_visit
    FROM ships s LEFT JOIN visits v ON v.ship_id = s.id`;
  let rows;
  if (q) {
    const like = likeEscape(q);
    rows = db.prepare(`${base}
      WHERE s.name LIKE ? ESCAPE '\\' OR s.imo LIKE ? ESCAPE '\\'
      GROUP BY s.id ORDER BY s.name COLLATE NOCASE LIMIT 100`).all(`%${like}%`, `${like}%`);
  } else {
    rows = db.prepare(`${base}
      GROUP BY s.id ORDER BY last_visit DESC, s.name COLLATE NOCASE LIMIT 100`).all();
  }
  res.json({ ships: rows });
});

// One ship with its full visit history, newest first
router.get('/ships/:id', (req, res) => {
  const ship = db.prepare('SELECT id, name, imo, agency FROM ships WHERE id = ?').get(req.params.id);
  if (!ship) return res.status(404).json({ error: 'Ship not found' });
  const visits = db.prepare(`
    SELECT v.id, v.visit_date, v.description, u.name AS recorded_by
    FROM visits v LEFT JOIN users u ON u.id = v.created_by
    WHERE v.ship_id = ? ORDER BY v.visit_date DESC, v.id DESC`).all(ship.id);
  res.json({ ship, visits });
});

router.post('/ships', (req, res) => {
  const f = shipFields(req.body);
  if (f.error) return res.status(400).json({ error: f.error });
  if (f.imo) {
    const dup = db.prepare('SELECT id, name FROM ships WHERE imo = ?').get(f.imo);
    if (dup) {
      return res.status(409).json({ error: 'A ship with that IMO already exists', existing: dup });
    }
  }
  const r = db.prepare('INSERT INTO ships (name, imo, agency) VALUES (?, ?, ?)')
    .run(f.name, f.imo, f.agency);
  res.status(201).json({ success: true, id: r.lastInsertRowid });
});

router.put('/ships/:id', (req, res) => {
  const f = shipFields(req.body);
  if (f.error) return res.status(400).json({ error: f.error });
  if (f.imo) {
    const dup = db.prepare('SELECT id, name FROM ships WHERE imo = ? AND id != ?').get(f.imo, req.params.id);
    if (dup) {
      return res.status(409).json({ error: 'Another ship already has that IMO', existing: dup });
    }
  }
  const r = db.prepare('UPDATE ships SET name = ?, imo = ?, agency = ? WHERE id = ?')
    .run(f.name, f.imo, f.agency, req.params.id);
  if (!r.changes) return res.status(404).json({ error: 'Ship not found' });
  res.json({ success: true });
});

// Deleting a ship also deletes all of its visits
router.delete('/ships/:id', (req, res) => {
  const count = db.prepare('SELECT COUNT(*) AS n FROM visits WHERE ship_id = ?').get(req.params.id).n;
  const r = db.prepare('DELETE FROM ships WHERE id = ?').run(req.params.id);
  if (!r.changes) return res.status(404).json({ error: 'Ship not found' });
  console.log(`Ship ${req.params.id} deleted with ${count} visit(s) by ${req.user.name}`);
  res.json({ success: true, visitsDeleted: count });
});

// ---------- visits ----------

router.post('/ships/:id/visits', (req, res) => {
  const ship = db.prepare('SELECT id FROM ships WHERE id = ?').get(req.params.id);
  if (!ship) return res.status(404).json({ error: 'Ship not found' });
  const date = parseDate(req.body.visit_date);
  if (!date) return res.status(400).json({ error: 'Visit date must be a valid date (YYYY-MM-DD), not in the future' });
  const description = cleanText(req.body.description, 5000);
  const r = db.prepare('INSERT INTO visits (ship_id, visit_date, description, created_by) VALUES (?, ?, ?, ?)')
    .run(ship.id, date, description, req.user.id);
  res.status(201).json({ success: true, id: r.lastInsertRowid });
});

router.put('/visits/:id', (req, res) => {
  const date = parseDate(req.body.visit_date);
  if (!date) return res.status(400).json({ error: 'Visit date must be a valid date (YYYY-MM-DD), not in the future' });
  const description = cleanText(req.body.description, 5000);
  const r = db.prepare('UPDATE visits SET visit_date = ?, description = ? WHERE id = ?')
    .run(date, description, req.params.id);
  if (!r.changes) return res.status(404).json({ error: 'Visit not found' });
  res.json({ success: true });
});

router.delete('/visits/:id', (req, res) => {
  const r = db.prepare('DELETE FROM visits WHERE id = ?').run(req.params.id);
  if (!r.changes) return res.status(404).json({ error: 'Visit not found' });
  res.json({ success: true });
});

module.exports = router;
