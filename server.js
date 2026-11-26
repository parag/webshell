const express = require('express');
const http = require('http');
const { WebSocketServer } = require('ws');
const pty = require('node-pty');
const crypto = require('crypto');
const { execFileSync } = require('child_process');
const path = require('path');
const os = require('os');
const fs = require('fs');
const Database = require('better-sqlite3');
const bcrypt = require('bcryptjs');

const multer = require('multer');
const { clientKey, isLoopback } = require('./lib/client-key');
const HOME_DIR = os.homedir();
const DATA_DIR = path.join(__dirname, 'data');

// Ensure data directory exists
fs.mkdirSync(DATA_DIR, { recursive: true });

// --- SQLite setup ---
const db = new Database(path.join(DATA_DIR, 'webshell.db'));
db.pragma('journal_mode = WAL');
db.pragma('foreign_keys = ON');

db.exec(`
  CREATE TABLE IF NOT EXISTS settings (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL
  );
  CREATE TABLE IF NOT EXISTS projects (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL UNIQUE,
    created_at INTEGER NOT NULL DEFAULT (strftime('%s','now'))
  );
  CREATE TABLE IF NOT EXISTS sessions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    project_id INTEGER NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    name TEXT NOT NULL,
    tmux_name TEXT NOT NULL UNIQUE,
    created_at INTEGER NOT NULL DEFAULT (strftime('%s','now'))
  );
  CREATE TABLE IF NOT EXISTS auth_tokens (
    token TEXT PRIMARY KEY,
    created_at INTEGER NOT NULL DEFAULT (strftime('%s','now'))
  );
`);

// Migration: add directory column to projects
try {
  db.exec("ALTER TABLE projects ADD COLUMN directory TEXT DEFAULT NULL");
} catch {
  // column already exists
}

// Migration: tie each token to the password it was issued under (password-file mode)
try {
  db.exec("ALTER TABLE auth_tokens ADD COLUMN pw_fp TEXT DEFAULT NULL");
} catch {
  // column already exists
}

function getPasswordHash() {
  const row = db.prepare("SELECT value FROM settings WHERE key = 'password_hash'").get();
  return row ? row.value : null;
}

function setPasswordHash(hash) {
  db.prepare("INSERT OR REPLACE INTO settings (key, value) VALUES ('password_hash', ?)").run(hash);
}

function isSetupDone() {
  if (PASSWORD_FILE) return true;
  return getPasswordHash() !== null;
}

function getSetting(key) {
  const row = db.prepare('SELECT value FROM settings WHERE key = ?').get(key);
  return row ? row.value : null;
}

function setSetting(key, value) {
  db.prepare('INSERT OR REPLACE INTO settings (key, value) VALUES (?, ?)').run(key, value);
}

// --- Password file (WEBSHELL_PASSWORD_FILE) ---
// When set, the password lives in that file and is read fresh on every login and
// every token check. Editing the file signs out every existing token. The
// first-visit setup and in-app password change are disabled in this mode.

const PASSWORD_FILE = process.env.WEBSHELL_PASSWORD_FILE
  ? path.resolve(process.env.WEBSHELL_PASSWORD_FILE.replace(/^~(?=$|\/)/, HOME_DIR))
  : null;
const PASSWORD_PLACEHOLDER = 'CHANGE-ME-dummy-password';

// Returns { password } or { error } with a message fit to show on the login screen.
function readPasswordFile() {
  let pw;
  try {
    pw = fs.readFileSync(PASSWORD_FILE, 'utf8').trim();
  } catch {
    pw = '';
  }
  if (!pw || pw === PASSWORD_PLACEHOLDER) {
    return { error: `Login is disabled: set a password in ${PASSWORD_FILE}` };
  }
  return { password: pw };
}

// Key for fingerprinting the file password, so the DB never holds a bare hash of it.
function getFingerprintKey() {
  let key = getSetting('pw_fp_key');
  if (!key) {
    key = crypto.randomBytes(32).toString('hex');
    setSetting('pw_fp_key', key);
  }
  return key;
}

function passwordFingerprint(pw) {
  return crypto.createHmac('sha256', getFingerprintKey()).update(pw, 'utf8').digest('hex');
}

// Fingerprint of the password tokens must currently be bound to.
// null means bcrypt mode; undefined means no valid password (all tokens refused).
// Any change to the file seen since the last check (including to the placeholder and
// back) drops every token, so restoring an old password never revives old sessions.
function currentFingerprint() {
  if (!PASSWORD_FILE) return null;
  const { password } = readPasswordFile();
  const fp = password ? passwordFingerprint(password) : undefined;
  const seen = fp || 'none';
  if (getSetting('pw_fp_seen') !== seen) {
    db.prepare('DELETE FROM auth_tokens').run();
    setSetting('pw_fp_seen', seen);
  }
  return fp;
}

function sha256(s) {
  return crypto.createHash('sha256').update(String(s), 'utf8').digest();
}

function checkFilePassword(submitted) {
  currentFingerprint(); // record the file state first, so a fresh token is not dropped by it
  const { password, error } = readPasswordFile();
  if (error) return { error };
  const ok = typeof submitted === 'string' && crypto.timingSafeEqual(sha256(submitted), sha256(password));
  return ok ? { ok: true, fp: passwordFingerprint(password) } : { ok: false };
}

// --- Telegram ---

function getTelegramConfig() {
  const botToken = db.prepare("SELECT value FROM settings WHERE key = 'telegram_bot_token'").get();
  const chatId = db.prepare("SELECT value FROM settings WHERE key = 'telegram_chat_id'").get();
  return {
    bot_token: botToken?.value || '',
    chat_id: chatId?.value || '',
    configured: !!(botToken?.value && chatId?.value),
  };
}

async function sendTelegramMessage(text) {
  const config = getTelegramConfig();
  if (!config.configured) return false;
  try {
    const res = await fetch(
      `https://api.telegram.org/bot${config.bot_token}/sendMessage`,
      {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ chat_id: config.chat_id, text, parse_mode: 'HTML' }),
      }
    );
    return res.ok;
  } catch {
    return false;
  }
}

const app = express();
const server = http.createServer(app);
const wss = new WebSocketServer({ noServer: true });

const PORT = process.env.PORT || 3000;

// --- Token management (SQLite-backed) ---
const TOKEN_TTL_SECONDS = 30 * 24 * 60 * 60;

const tokens = {
  add(token, pwFp = null) {
    db.prepare('INSERT OR IGNORE INTO auth_tokens (token, pw_fp) VALUES (?, ?)').run(token, pwFp);
  },
  has(token) {
    if (!token || typeof token !== 'string') return false;
    const row = db.prepare('SELECT created_at, pw_fp FROM auth_tokens WHERE token = ?').get(token);
    if (!row) return false;
    if (row.created_at < Math.floor(Date.now() / 1000) - TOKEN_TTL_SECONDS) {
      this.delete(token);
      return false;
    }
    const fp = currentFingerprint();
    if (fp === undefined) return false; // password file missing/placeholder: refuse everything
    return row.pw_fp === fp; // bcrypt mode: both null; file mode: must match current file
  },
  prune() {
    const cutoff = Math.floor(Date.now() / 1000) - TOKEN_TTL_SECONDS;
    db.prepare('DELETE FROM auth_tokens WHERE created_at < ?').run(cutoff);
    const fp = currentFingerprint();
    if (fp) db.prepare('DELETE FROM auth_tokens WHERE pw_fp IS NOT ? ').run(fp);
  },
  delete(token) {
    db.prepare('DELETE FROM auth_tokens WHERE token = ?').run(token);
  },
  clear() {
    db.prepare('DELETE FROM auth_tokens').run();
  },
};

// Behind `tailscale serve` or nginx on the same host, take the client IP from X-Forwarded-For.
app.set('trust proxy', 'loopback');
app.use(express.json());
// Grid view: /grid -> public/grid.html (/grid.html is served by express.static)
app.get('/grid', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'grid.html'));
});
app.use(express.static(path.join(__dirname, 'public')));

// --- Auth ---

// Check if first-time setup is needed
app.get('/api/setup-status', (req, res) => {
  res.json({ setup_done: isSetupDone(), password_file: !!PASSWORD_FILE });
});

// --- Login rate limit: 5 failures per minute per client, then an escalating lockout ---
// The client is the Tailscale login (or forwarded IP) behind a local proxy, else the socket IP: see lib/client-key.js
const LOGIN_WINDOW_MS = 60 * 1000;
const LOGIN_MAX_FAILURES = 5;
const LOGIN_MAX_LOCK_MS = 15 * 60 * 1000;
const loginFailures = new Map(); // client key -> { times: number[], lockedUntil: number, lockMs: number }

function loginLockRemaining(ip) {
  const e = loginFailures.get(ip);
  if (!e) return 0;
  return Math.max(0, e.lockedUntil - Date.now());
}

function recordLoginFailure(ip) {
  const now = Date.now();
  const e = loginFailures.get(ip) || { times: [], lockedUntil: 0, lockMs: 0 };
  e.times = e.times.filter(t => now - t < LOGIN_WINDOW_MS);
  e.times.push(now);
  if (e.times.length >= LOGIN_MAX_FAILURES) {
    e.lockMs = e.lockMs ? Math.min(e.lockMs * 2, LOGIN_MAX_LOCK_MS) : LOGIN_WINDOW_MS;
    e.lockedUntil = now + e.lockMs;
    e.times = [];
    console.log(`login lockout: ${ip} for ${e.lockMs / 1000}s`);
  }
  loginFailures.set(ip, e);
}

function rateLimited(req, res) {
  const remaining = loginLockRemaining(clientKey(req));
  if (!remaining) return false;
  const secs = Math.ceil(remaining / 1000);
  res.set('Retry-After', String(secs));
  res.status(429).json({ error: `Too many failed attempts. Try again in ${secs}s.` });
  return true;
}

setInterval(() => {
  const now = Date.now();
  for (const [ip, e] of loginFailures) {
    // Forget an IP once it is unlocked and quiet for a while (lockMs decays with it)
    if (e.lockedUntil + LOGIN_MAX_LOCK_MS < now && e.times.every(t => now - t > LOGIN_WINDOW_MS)) {
      loginFailures.delete(ip);
    }
  }
  try { tokens.prune(); } catch {}
}, 10 * 60 * 1000).unref();

// First-time password setup
app.post('/api/setup', (req, res) => {
  if (PASSWORD_FILE) {
    return res.status(403).json({ error: `Password is set in ${PASSWORD_FILE}, not here.` });
  }
  if (isSetupDone()) {
    return res.status(403).json({ error: 'Password already set.' });
  }
  const { password } = req.body || {};
  if (!password || typeof password !== 'string' || password.length < 6) {
    return res.status(400).json({ error: 'Password must be at least 6 characters.' });
  }
  const hash = bcrypt.hashSync(password, 12);
  setPasswordHash(hash);
  const token = crypto.randomBytes(32).toString('hex');
  tokens.add(token);
  res.json({ token });
});

app.post('/api/login', (req, res) => {
  if (rateLimited(req, res)) return;
  const { password } = req.body || {};

  if (PASSWORD_FILE) {
    const result = checkFilePassword(password);
    if (result.error) return res.status(403).json({ error: result.error });
    if (!result.ok) {
      recordLoginFailure(clientKey(req));
      return res.status(401).json({ error: 'Wrong password' });
    }
    const token = crypto.randomBytes(32).toString('hex');
    tokens.add(token, result.fp);
    return res.json({ token });
  }

  if (!isSetupDone()) {
    return res.status(403).json({ error: 'Setup not complete.' });
  }
  if (typeof password === 'string' && bcrypt.compareSync(password, getPasswordHash())) {
    const token = crypto.randomBytes(32).toString('hex');
    tokens.add(token);
    res.json({ token });
  } else {
    recordLoginFailure(clientKey(req));
    res.status(401).json({ error: 'Wrong password' });
  }
});

app.post('/api/logout', (req, res) => {
  const token = req.headers.authorization?.replace('Bearer ', '');
  tokens.delete(token);
  res.json({ ok: true });
});

function authMiddleware(req, res, next) {
  const token = req.headers.authorization?.replace('Bearer ', '');
  if (token && tokens.has(token)) return next();
  res.status(401).json({ error: 'Unauthorized' });
}

// Change password (requires auth)
app.post('/api/change-password', authMiddleware, (req, res) => {
  if (PASSWORD_FILE) {
    return res.status(400).json({ error: `Password is managed in ${PASSWORD_FILE}. Edit that file to change it.` });
  }
  if (rateLimited(req, res)) return;
  const { current_password, new_password } = req.body || {};
  if (!current_password || !new_password) {
    return res.status(400).json({ error: 'Both current and new password required.' });
  }
  if (typeof new_password !== 'string' || new_password.length < 6) {
    return res.status(400).json({ error: 'New password must be at least 6 characters.' });
  }
  if (!bcrypt.compareSync(current_password, getPasswordHash())) {
    recordLoginFailure(clientKey(req));
    return res.status(401).json({ error: 'Current password is wrong.' });
  }
  const hash = bcrypt.hashSync(new_password, 12);
  setPasswordHash(hash);
  // Invalidate all tokens except the current one
  const currentToken = req.headers.authorization?.replace('Bearer ', '');
  tokens.clear();
  tokens.add(currentToken);
  res.json({ ok: true });
});

// --- Telegram API ---

app.get('/api/settings/telegram', authMiddleware, (req, res) => {
  const config = getTelegramConfig();
  res.json({
    bot_token: config.bot_token ? '***' + config.bot_token.slice(-4) : '',
    chat_id: config.chat_id,
    configured: config.configured,
  });
});

app.post('/api/settings/telegram', authMiddleware, (req, res) => {
  const { bot_token, chat_id } = req.body || {};
  if (bot_token !== undefined) {
    if (bot_token) {
      db.prepare("INSERT OR REPLACE INTO settings (key, value) VALUES ('telegram_bot_token', ?)").run(bot_token);
    } else {
      db.prepare("DELETE FROM settings WHERE key = 'telegram_bot_token'").run();
    }
  }
  if (chat_id !== undefined) {
    if (chat_id) {
      db.prepare("INSERT OR REPLACE INTO settings (key, value) VALUES ('telegram_chat_id', ?)").run(String(chat_id));
    } else {
      db.prepare("DELETE FROM settings WHERE key = 'telegram_chat_id'").run();
    }
  }
  res.json({ ok: true, configured: getTelegramConfig().configured });
});

app.post('/api/settings/telegram/test', authMiddleware, async (req, res) => {
  const ok = await sendTelegramMessage('🔔 Webshell test notification');
  res.json({ ok });
});

// A request made straight to the server from this machine, not relayed by a proxy.
// `tailscale serve` and nginx also connect from 127.0.0.1, so the socket address alone
// is not enough: proxied requests carry forwarding headers and a public Host.
function isDirectLocalRequest(req) {
  if (!isLoopback(req.socket.remoteAddress)) return false;
  const h = req.headers;
  if (h['x-forwarded-for'] || h['x-forwarded-host'] || h['x-forwarded-proto'] || h['x-real-ip'] || h['forwarded']) return false;
  if (Object.keys(h).some(k => k.startsWith('tailscale-'))) return false;
  const host = String(h.host || '').replace(/:\d+$/, '').replace(/^\[|\]$/g, '');
  return ['localhost', '127.0.0.1', '::1'].includes(host);
}

function escapeTelegramHtml(s) {
  return String(s).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
}

// Notify endpoint: a direct local request (e.g. a shell hook doing
// `curl http://127.0.0.1:3000/api/notify`), or any request with a valid token.
app.post('/api/notify', (req, res, next) => {
  if (isDirectLocalRequest(req)) return next();
  return authMiddleware(req, res, next);
}, async (req, res) => {
  const { message, session, command, duration } = req.body || {};
  const cmdDisplay = command ? escapeTelegramHtml(String(command).substring(0, 200)) : '';
  const text = message ||
    `✅ Task completed in <b>${escapeTelegramHtml(session || 'unknown')}</b>\n<code>${cmdDisplay}</code>\nDuration: ${escapeTelegramHtml(duration || '?')}s`;
  const ok = await sendTelegramMessage(text);
  res.json({ ok });
});

// --- Validation ---

function isValidName(name) {
  return /^[a-zA-Z0-9_-]{1,50}$/.test(name);
}

// Accept "~/x" and relative paths for a project directory; store an absolute path.
function resolveDir(dir) {
  if (!dir) return null;
  let d = String(dir).trim();
  if (d === '~') d = os.homedir();
  else if (d.startsWith('~/')) d = path.join(os.homedir(), d.slice(2));
  return path.resolve(os.homedir(), d);
}

// --- tmux helpers ---

function getTmuxSessions() {
  try {
    const output = execFileSync(
      'tmux', ['list-sessions', '-F', '#{session_name}||#{session_attached}'],
      { encoding: 'utf8', timeout: 5000, stdio: ['ignore', 'pipe', 'ignore'] }
    );
    const map = {};
    output.trim().split('\n').filter(Boolean).forEach(line => {
      const [name, attached] = line.split('||');
      map[name] = { attached: parseInt(attached, 10) > 0 };
    });
    return map;
  } catch {
    return {};
  }
}

function killTmuxSession(tmuxName) {
  try {
    execFileSync('tmux', ['kill-session', '-t', '=' + tmuxName], { timeout: 5000, stdio: 'ignore' });
  } catch {
    // session may already be dead
  }
}

// Exact-match session existence check (no shell, never creates)
function tmuxHasSession(name) {
  try {
    execFileSync('tmux', ['has-session', '-t', '=' + name], { timeout: 5000, stdio: 'ignore' });
    return true;
  } catch {
    return false;
  }
}

// --- Tmux sessions API (all sessions on the tmux server) ---

app.get('/api/tmux/sessions', authMiddleware, (req, res) => {
  let output;
  try {
    output = execFileSync('tmux', [
      'list-sessions', '-F',
      '#{session_name}\t#{session_attached}\t#{session_windows}\t#{session_activity}\t#{pane_current_path}',
    ], { encoding: 'utf8', timeout: 5000, stdio: ['ignore', 'pipe', 'pipe'] });
  } catch (e) {
    const stderr = String(e.stderr || '');
    // No tmux server running / no sessions -> empty list
    if (/no server running|no sessions|error connecting to|No such file or directory/i.test(stderr)) {
      return res.json([]);
    }
    return res.status(500).json({ error: (stderr.trim() || e.message || 'tmux failed') });
  }
  try {
    const projRows = db.prepare(`
      SELECT s.tmux_name, p.id, p.name
      FROM sessions s JOIN projects p ON p.id = s.project_id
    `).all();
    const projByTmux = new Map(projRows.map(r => [r.tmux_name, { id: r.id, name: r.name }]));
    const list = output.split('\n').filter(Boolean).map(line => {
      const [name, attached, windows, activity, ...rest] = line.split('\t');
      return {
        name,
        attached: parseInt(attached, 10) || 0,
        windows: parseInt(windows, 10) || 0,
        activity: parseInt(activity, 10) || 0,
        path: rest.join('\t'),
        project: projByTmux.get(name) || null,
      };
    });
    list.sort((a, b) => b.activity - a.activity);
    res.json(list);
  } catch (e) {
    res.status(500).json({ error: e.message || 'Failed to list sessions' });
  }
});

// --- Grid layout API (stored in settings under key 'grid') ---

const GRID_DEFAULT = () => ({ sessions: [], layout: 'auto', maximized: null, labels: {} });
const GRID_LAYOUTS = ['auto', 'columns', 'rows'];
const GRID_NAME_RE = /^[A-Za-z0-9_-]{1,100}$/;
const GRID_LABEL_MAX = 60;
const GRID_LABEL_CTRL_RE = /[\u0000-\u001f\u007f-\u009f]/;

// Grid-only nicknames for panes: { [tmuxName]: label }. The tmux session itself is never renamed.
// Returns [error, cleanLabels]; missing/null labels mean "no nicknames". Empty strings are dropped.
function normalizeGridLabels(labels, sessions) {
  if (labels === undefined || labels === null) return [null, {}];
  if (typeof labels !== 'object' || Array.isArray(labels)) return ['labels must be an object.', null];
  const out = [];
  for (const [key, value] of Object.entries(labels)) {
    if (!sessions.includes(key)) return ['labels keys must be in sessions.', null];
    if (typeof value !== 'string') return ['labels values must be strings.', null];
    const v = value.trim();
    if (!v) continue;
    if (v.length > GRID_LABEL_MAX) return [`labels must be at most ${GRID_LABEL_MAX} characters.`, null];
    if (GRID_LABEL_CTRL_RE.test(v)) return ['labels must not contain control characters.', null];
    out.push([key, v]);
  }
  return [null, Object.fromEntries(out)];
}

function validateGrid(g) {
  if (!g || typeof g !== 'object' || Array.isArray(g)) return 'Body must be an object.';
  const { sessions, layout, maximized } = g;
  if (!Array.isArray(sessions)) return 'sessions must be an array.';
  if (sessions.length > 50) return 'At most 50 sessions.';
  for (const n of sessions) {
    if (typeof n !== 'string' || !GRID_NAME_RE.test(n)) return 'Invalid session name.';
  }
  if (new Set(sessions).size !== sessions.length) return 'Duplicate session names.';
  if (!GRID_LAYOUTS.includes(layout)) return 'layout must be one of auto, columns, rows.';
  if (maximized !== null && maximized !== undefined && !sessions.includes(maximized)) {
    return 'maximized must be null or one of sessions.';
  }
  return normalizeGridLabels(g.labels, sessions)[0];
}

function getGrid() {
  const raw = getSetting('grid');
  if (!raw) return GRID_DEFAULT();
  try {
    const g = JSON.parse(raw);
    if (validateGrid(g)) return GRID_DEFAULT();
    return { sessions: g.sessions, layout: g.layout, maximized: g.maximized ?? null, labels: normalizeGridLabels(g.labels, g.sessions)[1] };
  } catch {
    return GRID_DEFAULT();
  }
}

app.get('/api/grid', authMiddleware, (req, res) => {
  res.json(getGrid());
});

app.put('/api/grid', authMiddleware, (req, res) => {
  const err = validateGrid(req.body);
  if (err) return res.status(400).json({ error: err });
  const { sessions, layout } = req.body;
  const g = { sessions, layout, maximized: req.body.maximized ?? null, labels: normalizeGridLabels(req.body.labels, sessions)[1] };
  setSetting('grid', JSON.stringify(g));
  res.json(g);
});

// --- Projects API ---

app.get('/api/projects', authMiddleware, (req, res) => {
  const projects = db.prepare(`
    SELECT p.id, p.name, p.directory, p.created_at,
           COUNT(s.id) as session_count
    FROM projects p
    LEFT JOIN sessions s ON s.project_id = p.id
    GROUP BY p.id
    ORDER BY p.created_at DESC
  `).all();
  res.json(projects);
});

app.post('/api/projects', authMiddleware, (req, res) => {
  const { name } = req.body || {};
  const directory = resolveDir((req.body || {}).directory);
  if (!name || !isValidName(name)) {
    return res.status(400).json({ error: 'Name can use letters, numbers, - and _ only (no spaces).' });
  }
  if (directory && !fs.existsSync(directory)) {
    return res.status(400).json({ error: `Folder not found: ${directory}` });
  }
  try {
    const result = db.prepare('INSERT INTO projects (name, directory) VALUES (?, ?)').run(name, directory || null);
    res.json({ id: result.lastInsertRowid, name, directory: directory || null });
  } catch {
    res.status(400).json({ error: 'Project already exists.' });
  }
});

app.put('/api/projects/:id', authMiddleware, (req, res) => {
  const id = parseInt(req.params.id, 10);
  if (isNaN(id)) return res.status(400).json({ error: 'Invalid project id.' });
  const project = db.prepare('SELECT * FROM projects WHERE id = ?').get(id);
  if (!project) return res.status(404).json({ error: 'Project not found.' });
  const raw = (req.body || {}).directory;
  if (raw !== undefined) {
    const directory = resolveDir(raw);
    if (directory && !fs.existsSync(directory)) {
      return res.status(400).json({ error: `Folder not found: ${directory}` });
    }
    db.prepare('UPDATE projects SET directory = ? WHERE id = ?').run(directory || null, id);
  }
  res.json({ ok: true });
});

app.delete('/api/projects/:id', authMiddleware, (req, res) => {
  const id = parseInt(req.params.id, 10);
  if (isNaN(id)) return res.status(400).json({ error: 'Invalid project id.' });

  // Kill all tmux sessions for this project
  const sessions = db.prepare('SELECT tmux_name FROM sessions WHERE project_id = ?').all(id);
  for (const s of sessions) {
    killTmuxSession(s.tmux_name);
  }

  const result = db.prepare('DELETE FROM projects WHERE id = ?').run(id);
  if (result.changes === 0) return res.status(404).json({ error: 'Project not found.' });
  res.json({ ok: true });
});

// --- Sessions API (project-scoped) ---

app.get('/api/projects/:id/sessions', authMiddleware, (req, res) => {
  const projectId = parseInt(req.params.id, 10);
  if (isNaN(projectId)) return res.status(400).json({ error: 'Invalid project id.' });

  const sessions = db.prepare(
    'SELECT id, name, tmux_name, created_at FROM sessions WHERE project_id = ? ORDER BY created_at DESC'
  ).all(projectId);

  const tmux = getTmuxSessions();
  const result = sessions.map(s => ({
    ...s,
    attached: tmux[s.tmux_name]?.attached || false,
    alive: s.tmux_name in tmux,
  }));
  res.json(result);
});

app.post('/api/projects/:id/sessions', authMiddleware, (req, res) => {
  const projectId = parseInt(req.params.id, 10);
  if (isNaN(projectId)) return res.status(400).json({ error: 'Invalid project id.' });

  const project = db.prepare('SELECT name, directory FROM projects WHERE id = ?').get(projectId);
  if (!project) return res.status(404).json({ error: 'Project not found.' });

  const name = req.body.name || `s-${Date.now()}`;
  if (!isValidName(name)) {
    return res.status(400).json({ error: 'Invalid name. Use alphanumeric, dash, underscore only.' });
  }

  const tmuxName = `${project.name}--${name}`;
  const cwd = project.directory || HOME_DIR;

  try {
    const result = db.prepare(
      'INSERT INTO sessions (project_id, name, tmux_name) VALUES (?, ?, ?)'
    ).run(projectId, name, tmuxName);

    execFileSync('tmux', ['new-session', '-d', '-s', tmuxName, '-c', cwd], { timeout: 5000, stdio: 'ignore' });
    res.json({ id: result.lastInsertRowid, name, tmux_name: tmuxName });
  } catch (e) {
    // Clean up DB row if tmux failed
    db.prepare('DELETE FROM sessions WHERE tmux_name = ?').run(tmuxName);
    res.status(400).json({ error: 'Session already exists or failed to create.' });
  }
});

app.delete('/api/sessions/:id', authMiddleware, (req, res) => {
  const id = parseInt(req.params.id, 10);
  if (isNaN(id)) return res.status(400).json({ error: 'Invalid session id.' });

  const session = db.prepare('SELECT tmux_name FROM sessions WHERE id = ?').get(id);
  if (!session) return res.status(404).json({ error: 'Session not found.' });

  killTmuxSession(session.tmux_name);
  db.prepare('DELETE FROM sessions WHERE id = ?').run(id);
  res.json({ ok: true });
});

// --- Files API ---

const upload = multer({ dest: path.join(DATA_DIR, 'uploads_tmp'), limits: { fileSize: 100 * 1024 * 1024 } });

function safePath(base, rel) {
  const resolved = path.resolve(base, rel || '');
  if (!resolved.startsWith(base)) return null;
  return resolved;
}

app.get('/api/files', authMiddleware, (req, res) => {
  const dir = req.query.dir;
  if (!dir) return res.status(400).json({ error: 'dir is required' });
  try {
    const resolved = path.resolve(dir);
    const entries = fs.readdirSync(resolved, { withFileTypes: true });
    const items = [];
    for (const e of entries) {
      if (e.name.startsWith('.')) continue; // skip hidden by default
      try {
        const fullPath = path.join(resolved, e.name);
        const stat = fs.statSync(fullPath);
        items.push({
          name: e.name,
          type: e.isDirectory() ? 'dir' : 'file',
          size: e.isDirectory() ? null : stat.size,
          modified: Math.floor(stat.mtimeMs / 1000),
        });
      } catch { /* skip inaccessible */ }
    }
    // Sort: dirs first, then files, alphabetical
    items.sort((a, b) => {
      if (a.type !== b.type) return a.type === 'dir' ? -1 : 1;
      return a.name.localeCompare(b.name, undefined, { sensitivity: 'base' });
    });
    res.json({ path: resolved, items, showHidden: false });
  } catch (e) {
    res.status(400).json({ error: 'Cannot read directory.' });
  }
});

app.get('/api/files/read', authMiddleware, (req, res) => {
  const filePath = req.query.path;
  if (!filePath) return res.status(400).json({ error: 'path is required' });
  try {
    const resolved = path.resolve(filePath);
    const stat = fs.statSync(resolved);
    if (stat.size > 2 * 1024 * 1024) {
      return res.status(413).json({ error: 'File too large to preview (>2MB). Use download.' });
    }
    // Check if binary
    const buf = Buffer.alloc(512);
    const fd = fs.openSync(resolved, 'r');
    const bytesRead = fs.readSync(fd, buf, 0, 512, 0);
    fs.closeSync(fd);
    let isBinary = false;
    for (let i = 0; i < bytesRead; i++) {
      if (buf[i] === 0) { isBinary = true; break; }
    }
    if (isBinary) {
      return res.json({ binary: true, size: stat.size });
    }
    const content = fs.readFileSync(resolved, 'utf8');
    res.json({ content, size: stat.size });
  } catch {
    res.status(400).json({ error: 'Cannot read file.' });
  }
});

// The client fetches with the Authorization header and builds a blob URL,
// so the token never appears in a URL, server log or browser history.
app.get('/api/files/download', authMiddleware, (req, res) => {
  const filePath = req.query.path;
  if (!filePath) return res.status(400).json({ error: 'path is required' });
  try {
    const resolved = path.resolve(filePath);
    if (!fs.existsSync(resolved) || fs.statSync(resolved).isDirectory()) {
      return res.status(404).json({ error: 'File not found.' });
    }
    res.download(resolved);
  } catch {
    res.status(400).json({ error: 'Cannot download file.' });
  }
});

app.post('/api/files/upload', authMiddleware, upload.array('files', 20), (req, res) => {
  const targetDir = req.body.dir;
  if (!targetDir) {
    // Clean up temp files
    (req.files || []).forEach(f => { try { fs.unlinkSync(f.path); } catch {} });
    return res.status(400).json({ error: 'dir is required' });
  }
  try {
    const resolved = path.resolve(targetDir);
    if (!fs.existsSync(resolved) || !fs.statSync(resolved).isDirectory()) {
      (req.files || []).forEach(f => { try { fs.unlinkSync(f.path); } catch {} });
      return res.status(400).json({ error: 'Target directory does not exist.' });
    }
    const uploaded = [];
    for (const f of (req.files || [])) {
      const dest = path.join(resolved, f.originalname);
      fs.renameSync(f.path, dest);
      uploaded.push(f.originalname);
    }
    res.json({ ok: true, uploaded });
  } catch (e) {
    (req.files || []).forEach(f => { try { fs.unlinkSync(f.path); } catch {} });
    res.status(500).json({ error: 'Upload failed.' });
  }
});

// --- WebSocket terminal ---

server.on('upgrade', (req, socket, head) => {
  const url = new URL(req.url, 'http://localhost');

  if (url.pathname !== '/ws') {
    socket.destroy();
    return;
  }

  const token = url.searchParams.get('token');
  if (!token || !tokens.has(token)) {
    socket.write('HTTP/1.1 401 Unauthorized\r\n\r\n');
    socket.destroy();
    return;
  }

  wss.handleUpgrade(req, socket, head, (ws) => {
    ws.authToken = token;
    wss.emit('connection', ws, req);
  });
});

// Close open terminals whose token has expired or whose password changed
// (password-file mode: editing the file signs every open terminal out).
setInterval(() => {
  for (const ws of wss.clients) {
    if (!tokens.has(ws.authToken)) ws.close(4401, 'Signed out');
  }
}, 15 * 1000).unref();

// Spawn a pty attached to a tmux target and wire it to the WebSocket.
// onExit is called when the pty exits (defaults to closing the WS normally).
function bridgePty(ws, target, onExit) {
  const term = pty.spawn('tmux', ['attach-session', '-t', target], {
    name: 'xterm-256color',
    cols: 80,
    rows: 24,
    cwd: HOME_DIR,
    env: { ...process.env, TERM: 'xterm-256color' },
  });


  term.onData((data) => {
    if (ws.readyState === 1) {
      ws.send(JSON.stringify({ type: 'output', data }));
    }
  });

  ws.on('message', (raw) => {
    try {
      const msg = JSON.parse(raw);
      if (msg.type === 'ping') {
        if (ws.readyState === 1) ws.send(JSON.stringify({ type: 'pong' }));
      } else if (msg.type === 'input') {
        term.write(msg.data);
      } else if (msg.type === 'resize' && msg.cols > 0 && msg.rows > 0) {
        term.resize(Math.min(msg.cols, 500), Math.min(msg.rows, 200));
      }
    } catch {
      // ignore malformed messages
    }
  });

  const cleanup = () => {
    try { term.kill(); } catch {}
  };

  ws.on('close', cleanup);
  ws.on('error', cleanup);
  term.onExit(() => {
    if (onExit) return onExit();
    if (ws.readyState === 1) ws.close();
  });
}

wss.on('connection', (ws, req) => {
  const url = new URL(req.url, 'http://localhost');
  const tmuxName = url.searchParams.get('session');

  // Attach-only mode: attach to an existing tmux session by exact name, never create
  if (url.searchParams.get('attach') === '1') {
    if (!tmuxName || !/^[A-Za-z0-9_-]{1,100}$/.test(tmuxName)) {
      ws.close(1008, 'Invalid session');
      return;
    }
    if (!tmuxHasSession(tmuxName)) {
      ws.close(4404, 'session not found');
      return;
    }
    bridgePty(ws, '=' + tmuxName, () => {
      if (ws.readyState !== 1) return;
      if (!tmuxHasSession(tmuxName)) ws.close(4404, 'session ended');
      else ws.close();
    });
    return;
  }

  // Validate: tmux_name format is "project--session", allow double dash
  if (!tmuxName || !/^[a-zA-Z0-9_-]{1,50}--[a-zA-Z0-9_-]{1,50}$/.test(tmuxName)) {
    ws.close(1008, 'Invalid session');
    return;
  }

  // Ensure tmux session exists
  if (!tmuxHasSession(tmuxName)) {
    try {
      execFileSync('tmux', ['new-session', '-d', '-s', tmuxName, '-c', HOME_DIR], { timeout: 5000, stdio: 'ignore' });
    } catch {
      ws.close(1011, 'Failed to create session');
      return;
    }
  }

  bridgePty(ws, tmuxName);
});

server.listen(PORT, '127.0.0.1', () => {
  console.log(`Terminal server running on http://127.0.0.1:${PORT}`);
});
