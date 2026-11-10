const express = require('express');
const http = require('http');
const { WebSocketServer } = require('ws');
const pty = require('node-pty');
const crypto = require('crypto');
const { execSync, execFileSync } = require('child_process');
const path = require('path');
const os = require('os');
const fs = require('fs');
const Database = require('better-sqlite3');
const bcrypt = require('bcryptjs');

const multer = require('multer');
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

function getPasswordHash() {
  const row = db.prepare("SELECT value FROM settings WHERE key = 'password_hash'").get();
  return row ? row.value : null;
}

function setPasswordHash(hash) {
  db.prepare("INSERT OR REPLACE INTO settings (key, value) VALUES ('password_hash', ?)").run(hash);
}

function isSetupDone() {
  return getPasswordHash() !== null;
}

function getSetting(key) {
  const row = db.prepare('SELECT value FROM settings WHERE key = ?').get(key);
  return row ? row.value : null;
}

function setSetting(key, value) {
  db.prepare('INSERT OR REPLACE INTO settings (key, value) VALUES (?, ?)').run(key, value);
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
const tokens = {
  add(token) {
    db.prepare('INSERT OR IGNORE INTO auth_tokens (token) VALUES (?)').run(token);
  },
  has(token) {
    return !!db.prepare('SELECT 1 FROM auth_tokens WHERE token = ?').get(token);
  },
  delete(token) {
    db.prepare('DELETE FROM auth_tokens WHERE token = ?').run(token);
  },
  clear() {
    db.prepare('DELETE FROM auth_tokens').run();
  },
};

app.use(express.json());
// Grid view: /grid -> public/grid.html (/grid.html is served by express.static)
app.get('/grid', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'grid.html'));
});
app.use(express.static(path.join(__dirname, 'public')));

// --- Auth ---

// Check if first-time setup is needed
app.get('/api/setup-status', (req, res) => {
  res.json({ setup_done: isSetupDone() });
});

// First-time password setup
app.post('/api/setup', (req, res) => {
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
  if (!isSetupDone()) {
    return res.status(403).json({ error: 'Setup not complete.' });
  }
  const { password } = req.body || {};
  if (typeof password === 'string' && bcrypt.compareSync(password, getPasswordHash())) {
    const token = crypto.randomBytes(32).toString('hex');
    tokens.add(token);
    res.json({ token });
  } else {
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
  const { current_password, new_password } = req.body || {};
  if (!current_password || !new_password) {
    return res.status(400).json({ error: 'Both current and new password required.' });
  }
  if (typeof new_password !== 'string' || new_password.length < 6) {
    return res.status(400).json({ error: 'New password must be at least 6 characters.' });
  }
  if (!bcrypt.compareSync(current_password, getPasswordHash())) {
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

// Notify endpoint (no auth — only accessible from localhost)
app.post('/api/notify', async (req, res) => {
  const { message, session, command, duration } = req.body || {};
  const cmdDisplay = command ? command.substring(0, 200) : '';
  const text = message ||
    `✅ Task completed in <b>${session || 'unknown'}</b>\n<code>${cmdDisplay}</code>\nDuration: ${duration || '?'}s`;
  const ok = await sendTelegramMessage(text);
  res.json({ ok });
});

// --- Validation ---

function isValidName(name) {
  return /^[a-zA-Z0-9_-]{1,50}$/.test(name);
}

// --- tmux helpers ---

function getTmuxSessions() {
  try {
    const output = execSync(
      'tmux list-sessions -F "#{session_name}||#{session_attached}"',
      { encoding: 'utf8', timeout: 5000 }
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
    execSync(`tmux kill-session -t '${tmuxName}'`, { timeout: 5000 });
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
  const { name, directory } = req.body || {};
  if (!name || !isValidName(name)) {
    return res.status(400).json({ error: 'Invalid name. Use alphanumeric, dash, underscore only.' });
  }
  if (directory && !fs.existsSync(directory)) {
    return res.status(400).json({ error: 'Directory does not exist.' });
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
  const { directory } = req.body || {};
  if (directory !== undefined) {
    if (directory && !fs.existsSync(directory)) {
      return res.status(400).json({ error: 'Directory does not exist.' });
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

    execSync(`tmux new-session -d -s '${tmuxName}' -c '${cwd}'`, { timeout: 5000 });
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

app.get('/api/files/download', (req, res, next) => {
  // Allow token via query param for direct links (img src, download)
  const t = req.query.token || req.headers.authorization?.replace('Bearer ', '');
  if (t && tokens.has(t)) return next();
  res.status(401).json({ error: 'Unauthorized' });
}, (req, res) => {
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
    wss.emit('connection', ws, req);
  });
});

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
  try {
    execSync(`tmux has-session -t '${tmuxName}'`, { timeout: 5000 });
  } catch {
    try {
      execSync(`tmux new-session -d -s '${tmuxName}' -c '${HOME_DIR}'`, { timeout: 5000 });
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
