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

// Simple brute-force guard: 10 failed logins per IP per 15 minutes
const failures = {};
function tooManyFailures(ip) {
  const now = Date.now();
  failures[ip] = (failures[ip] || []).filter(t => now - t < 15 * 60 * 1000);
  return failures[ip].length >= 10;
}
function recordFailure(ip) {
  (failures[ip] = failures[ip] || []).push(Date.now());
}

// ---------- middleware (exported for step 2 routes) ----------

function requireUser(req, res, next) {
  const header = req.headers['authorization'] || '';
  const token = header.startsWith('Bearer ') ? header.slice(7) : '';
  if (!token) return res.status(401).json({ error: 'Login required' });

  const row = db.prepare(`
    SELECT u.id, u.name, u.status, s.created_at AS session_created
    FROM sessions s JOIN users u ON u.id = s.user_id
    WHERE s.token_hash = ?
  `).get(sha256(token));

  if (!row || row.status !== 'approved') {
    return res.status(401).json({ error: 'Login required' });
  }
  const ageDays = (Date.now() - new Date(row.session_created + 'Z').getTime()) / 86400000;
  if (ageDays > SESSION_DAYS) {
    db.prepare('DELETE FROM sessions WHERE token_hash = ?').run(sha256(token));
    return res.status(401).json({ error: 'Session expired, please log in again' });
  }
  req.user = { id: row.id, name: row.name };
  next();
}

function requireAdmin(req, res, next) {
  if (!ADMIN_KEY) {
    return res.status(503).json({ error: 'Admin key not configured on server' });
  }
  if (!safeEqual(req.headers['x-admin-key'] || '', ADMIN_KEY)) {
    return res.status(403).json({ error: 'Admin access denied' });
  }
  next();
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
  const ip = clientIp(req);
  if (tooManyFailures(ip)) {
    return res.status(429).json({ error: 'Too many attempts. Try again later.' });
  }
  const name = String(req.body.name || '').trim();
  const password = String(req.body.password || '');
  const user = db.prepare('SELECT * FROM users WHERE name = ?').get(name);

  if (!user || !safeEqual(hashPassword(password, user.salt), user.password_hash)) {
    recordFailure(ip);
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
  res.json({ success: true, token, name: user.name });
});

router.get('/auth/me', requireUser, (req, res) => {
  res.json({ name: req.user.name });
});

router.post('/auth/logout', requireUser, (req, res) => {
  const token = (req.headers['authorization'] || '').slice(7);
  db.prepare('DELETE FROM sessions WHERE token_hash = ?').run(sha256(token));
  res.json({ success: true });
});

// ---------- admin routes (need x-admin-key header) ----------

router.get('/admin/users', requireAdmin, (req, res) => {
  const users = db.prepare('SELECT id, name, status, created_at FROM users ORDER BY created_at DESC').all();
  res.json({ users });
});

router.post('/admin/users/:id/approve', requireAdmin, (req, res) => {
  const r = db.prepare("UPDATE users SET status = 'approved' WHERE id = ?").run(req.params.id);
  if (!r.changes) return res.status(404).json({ error: 'User not found' });
  res.json({ success: true });
});

router.post('/admin/users/:id/revoke', requireAdmin, (req, res) => {
  const r = db.prepare("UPDATE users SET status = 'revoked' WHERE id = ?").run(req.params.id);
  if (!r.changes) return res.status(404).json({ error: 'User not found' });
  db.prepare('DELETE FROM sessions WHERE user_id = ?').run(req.params.id); // log them out now
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
  res.json({ success: true });
});

// Also used to reject a pending request
router.delete('/admin/users/:id', requireAdmin, (req, res) => {
  const r = db.prepare('DELETE FROM users WHERE id = ?').run(req.params.id);
  if (!r.changes) return res.status(404).json({ error: 'User not found' });
  res.json({ success: true });
});

module.exports = router;
module.exports.requireUser = requireUser;
module.exports.requireAdmin = requireAdmin;
