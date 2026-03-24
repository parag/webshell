const express = require('express');
const http = require('http');
const { WebSocketServer } = require('ws');
const pty = require('node-pty');
const crypto = require('crypto');
const { execSync } = require('child_process');
const path = require('path');
const os = require('os');
const fs = require('fs');
const Database = require('better-sqlite3');
const bcrypt = require('bcryptjs');

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
`);

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

const app = express();
const server = http.createServer(app);
const wss = new WebSocketServer({ noServer: true });

const PORT = process.env.PORT || 3000;
const tokens = new Set();

app.use(express.json());
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

// --- Projects API ---

app.get('/api/projects', authMiddleware, (req, res) => {
  const projects = db.prepare(`
    SELECT p.id, p.name, p.created_at,
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
  if (!name || !isValidName(name)) {
    return res.status(400).json({ error: 'Invalid name. Use alphanumeric, dash, underscore only.' });
  }
  try {
    const result = db.prepare('INSERT INTO projects (name) VALUES (?)').run(name);
    res.json({ id: result.lastInsertRowid, name });
  } catch {
    res.status(400).json({ error: 'Project already exists.' });
  }
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

  const project = db.prepare('SELECT name FROM projects WHERE id = ?').get(projectId);
  if (!project) return res.status(404).json({ error: 'Project not found.' });

  const name = req.body.name || `s-${Date.now()}`;
  if (!isValidName(name)) {
    return res.status(400).json({ error: 'Invalid name. Use alphanumeric, dash, underscore only.' });
  }

  const tmuxName = `${project.name}--${name}`;

  try {
    const result = db.prepare(
      'INSERT INTO sessions (project_id, name, tmux_name) VALUES (?, ?, ?)'
    ).run(projectId, name, tmuxName);

    execSync(`tmux new-session -d -s '${tmuxName}' -c '${HOME_DIR}'`, { timeout: 5000 });
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

wss.on('connection', (ws, req) => {
  const url = new URL(req.url, 'http://localhost');
  const tmuxName = url.searchParams.get('session');

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

  const term = pty.spawn('tmux', ['attach-session', '-t', tmuxName], {
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
      if (msg.type === 'input') {
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
    if (ws.readyState === 1) ws.close();
  });
});

server.listen(PORT, '127.0.0.1', () => {
  console.log(`Terminal server running on http://127.0.0.1:${PORT}`);
});
