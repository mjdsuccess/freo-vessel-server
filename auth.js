// Freo Port - volunteer registration, login and admin approval
const express = require('express');
const crypto = require('crypto');
const db = require('./db');

const router = express.Router();

const SESSION_DAYS = 90;
const ADMIN_KEY = process.env.FREO_ADMIN_KEY || '';

// ---------- helpers ----------

function hashPassword(password, saltHex) {
  return crypto.scryptSync(password, Buffer.from(saltHex, 'hex'), 64).toString('hex');
}

function safeEqual(a, b) {
  const x = Buffer.from(String(a));
  const y = Buffer.from(String(b));
  return x.length === y.length && crypto.timingSafeEqual(x, y);
}

function sha256(text) {
  return crypto.createHash('sha256').update(text).digest('hex');
}

function clientIp(req) {
  return (req.headers['x-forwarded-for'] || req.socket.remoteAddress || '').split(',')[0].trim();
}

// Brute-force guards on failed logins, over a 15 minute window:
//  - per IP address: 10 failures (the forwarded address can be faked, so not enough alone)
//  - per volunteer name: 8 failures (can't be dodged by changing address)
const WINDOW_MS = 15 * 60 * 1000;
const failures = {};
function tooManyFailures(key, limit) {
  const now = Date.now();
  failures[key] = (failures[key] || []).filter(t => now - t < WINDOW_MS);
  return failures[key].length >= limit;
}
function recordFailure(key) {
  (failures[key] = failures[key] || []).push(Date.now());
}
// Tidy out old entries once an hour so memory doesn't grow
setInterval(() => {
  const now = Date.now();
  for (const k of Object.keys(failures)) {
    failures[k] = failures[k].filter(t => now - t < WINDOW_MS);
    if (!failures[k].length) delete failures[k];
  }
}, 60 * 60 * 1000).unref();

function adminLog(req, text) {
  const who = req.adminUser ? req.adminUser.name : 'admin key';
  console.log(`Admin (${who}): ${text}`);
}

// ---------- who is making this request? ----------

// Looks up the logged-in volunteer from the Bearer token.
// Returns { user } on success or { error } if not logged in.
function authenticate(req) {
  const header = req.headers['authorization'] || '';
  const token = header.startsWith('Bearer ') ? header.slice(7) : '';
  if (!token) return { error: 'Login required' };

  const row = db.prepare(`
    SELECT u.id, u.name, u.status, u.is_admin, s.created_at AS session_created
    FROM sessions s JOIN users u ON u.id = s.user_id
    WHERE s.token_hash = ?
  `).get(sha256(token));

  if (!row || row.status !== 'approved') return { error: 'Login required' };

  const ageDays = (Date.now() - new Date(row.session_created + 'Z').getTime()) / 86400000;
  if (ageDays > SESSION_DAYS) {
    db.prepare('DELETE FROM sessions WHERE token_hash = ?').run(sha256(token));
    return { error: 'Session expired, please log in again' };
  }
  return { user: { id: row.id, name: row.name, isAdmin: row.is_admin === 1 } };
}

// ---------- middleware (exported for the ships and visits routes) ----------

function requireUser(req, res, next) {
  const result = authenticate(req);
  if (result.error) return res.status(401).json({ error: result.error });
  req.user = result.user;
  next();
}

// Admin routes accept EITHER the admin key (x-admin-key header, for curl and
// emergencies) OR the login of a volunteer who has been made an admin.
function requireAdmin(req, res, next) {
  const keyHeader = req.headers['x-admin-key'];
  if (keyHeader !== undefined) {
    if (!ADMIN_KEY) {
      return res.status(503).json({ error: 'Admin key not configured on server' });
    }
    if (!safeEqual(keyHeader, ADMIN_KEY)) {
      return res.status(403).json({ error: 'Admin access denied' });
    }
    req.adminUser = null; // acting with the key, not as a particular volunteer
    return next();
  }

  const result = authenticate(req);
  if (result.error) return res.status(401).json({ error: result.error });
  if (!result.user.isAdmin) {
    return res.status(403).json({ error: 'Admin access denied' });
  }
  req.user = result.user;
  req.adminUser = result.user;
  next();
}

// True when a logged-in admin is acting on their own account
function isSelf(req) {
  return !!req.adminUser && String(req.adminUser.id) === String(req.params.id);
}

// ---------- volunteer routes ----------

// Register: creates a pending account awaiting admin approval
router.post('/auth/register', (req, res) => {
  const name = String(req.body.name || '').trim();
  const password = String(req.body.password || '');
  if (name.length < 2 || name.length > 50) {
    return res.status(400).json({ error: 'Name must be 2 to 50 characters' });
  }
  if (password.length < 6) {
    return res.status(400).json({ error: 'Password must be at least 6 characters' });
  }
  if (db.prepare('SELECT 1 FROM users WHERE name = ?').get(name)) {
    return res.status(409).json({ error: 'That name is already registered' });
  }
  const salt = crypto.randomBytes(16).toString('hex');
  db.prepare('INSERT INTO users (name, password_hash, salt) VALUES (?, ?, ?)')
    .run(name, hashPassword(password, salt), salt);
  console.log(`Registration request: ${name}`);
  res.status(201).json({ success: true, status: 'pending' });
});

// Login: returns a token once approved
router.post('/auth/login', (req, res) => {
  const ipKey = 'ip:' + clientIp(req);
  const name = String(req.body.name || '').trim();
  const password = String(req.body.password || '');
  const nameKey = 'name:' + name.toLowerCase();
  if (tooManyFailures(ipKey, 10) || tooManyFailures(nameKey, 8)) {
    return res.status(429).json({ error: 'Too many attempts. Try again in 15 minutes.' });
  }
  const user = db.prepare('SELECT * FROM users WHERE name = ?').get(name);

  if (!user || !safeEqual(hashPassword(password, user.salt), user.password_hash)) {
    recordFailure(ipKey);
    recordFailure(nameKey);
    return res.status(401).json({ error: 'Incorrect name or password' });
  }
  if (user.status === 'pending') {
    return res.status(403).json({ error: 'Waiting for approval', status: 'pending' });
  }
  if (user.status !== 'approved') {
    return res.status(403).json({ error: 'Access has been removed', status: user.status });
  }
  const token = crypto.randomBytes(32).toString('hex');
  db.prepare('INSERT INTO sessions (token_hash, user_id) VALUES (?, ?)').run(sha256(token), user.id);
  res.json({ success: true, token, name: user.name, isAdmin: user.is_admin === 1 });
});

router.get('/auth/me', requireUser, (req, res) => {
  res.json({ name: req.user.name, isAdmin: req.user.isAdmin });
});

router.post('/auth/logout', requireUser, (req, res) => {
  const token = (req.headers['authorization'] || '').slice(7);
  db.prepare('DELETE FROM sessions WHERE token_hash = ?').run(sha256(token));
  res.json({ success: true });
});

// ---------- admin routes ----------

router.get('/admin/users', requireAdmin, (req, res) => {
  const rows = db.prepare(
    'SELECT id, name, status, is_admin, created_at FROM users ORDER BY created_at DESC'
  ).all();
  const users = rows.map(u => ({
    id: u.id,
    name: u.name,
    status: u.status,
    isAdmin: u.is_admin === 1,
    created_at: u.created_at,
  }));
  res.json({ users });
});

router.post('/admin/users/:id/approve', requireAdmin, (req, res) => {
  const r = db.prepare("UPDATE users SET status = 'approved' WHERE id = ?").run(req.params.id);
  if (!r.changes) return res.status(404).json({ error: 'User not found' });
  adminLog(req, `approved user ${req.params.id}`);
  res.json({ success: true });
});

router.post('/admin/users/:id/revoke', requireAdmin, (req, res) => {
  if (isSelf(req)) {
    return res.status(400).json({ error: 'You cannot remove your own access' });
  }
  // Revoking also removes admin status, so re-approving later does not
  // quietly bring admin power back.
  const r = db.prepare("UPDATE users SET status = 'revoked', is_admin = 0 WHERE id = ?")
    .run(req.params.id);
  if (!r.changes) return res.status(404).json({ error: 'User not found' });
  db.prepare('DELETE FROM sessions WHERE user_id = ?').run(req.params.id); // log them out now
  adminLog(req, `revoked user ${req.params.id}`);
  res.json({ success: true });
});

router.post('/admin/users/:id/make-admin', requireAdmin, (req, res) => {
  const user = db.prepare('SELECT status FROM users WHERE id = ?').get(req.params.id);
  if (!user) return res.status(404).json({ error: 'User not found' });
  if (user.status !== 'approved') {
    return res.status(400).json({ error: 'Only approved volunteers can be made admins' });
  }
  db.prepare('UPDATE users SET is_admin = 1 WHERE id = ?').run(req.params.id);
  adminLog(req, `made user ${req.params.id} an admin`);
  res.json({ success: true });
});

router.post('/admin/users/:id/remove-admin', requireAdmin, (req, res) => {
  if (isSelf(req)) {
    return res.status(400).json({ error: 'You cannot remove your own admin status' });
  }
  const r = db.prepare('UPDATE users SET is_admin = 0 WHERE id = ?').run(req.params.id);
  if (!r.changes) return res.status(404).json({ error: 'User not found' });
  adminLog(req, `removed admin status from user ${req.params.id}`);
  res.json({ success: true });
});

router.post('/admin/users/:id/reset-password', requireAdmin, (req, res) => {
  const password = String(req.body.password || '');
  if (password.length < 6) {
    return res.status(400).json({ error: 'Password must be at least 6 characters' });
  }
  const salt = crypto.randomBytes(16).toString('hex');
  const r = db.prepare('UPDATE users SET password_hash = ?, salt = ? WHERE id = ?')
    .run(hashPassword(password, salt), salt, req.params.id);
  if (!r.changes) return res.status(404).json({ error: 'User not found' });
  db.prepare('DELETE FROM sessions WHERE user_id = ?').run(req.params.id);
  adminLog(req, `reset password for user ${req.params.id}`);
  res.json({ success: true });
});

// Also used to reject a pending request
router.delete('/admin/users/:id', requireAdmin, (req, res) => {
  if (isSelf(req)) {
    return res.status(400).json({ error: 'You cannot delete your own account' });
  }
  const r = db.prepare('DELETE FROM users WHERE id = ?').run(req.params.id);
  if (!r.changes) return res.status(404).json({ error: 'User not found' });
  adminLog(req, `deleted user ${req.params.id}`);
  res.json({ success: true });
});

module.exports = router;
module.exports.requireUser = requireUser;
module.exports.requireAdmin = requireAdmin;
