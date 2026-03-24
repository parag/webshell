const express = require('express');
const http = require('http');
const { WebSocketServer } = require('ws');
const pty = require('node-pty');
const crypto = require('crypto');
const { execSync } = require('child_process');
const path = require('path');
const os = require('os');

const HOME_DIR = os.homedir();

const app = express();
const server = http.createServer(app);
const wss = new WebSocketServer({ noServer: true });

const PASSWORD = process.env.TERM_PASSWORD || 'changeme';
const PORT = process.env.PORT || 3000;
const tokens = new Set();

app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

// --- Auth ---

function timingSafeEqual(a, b) {
  const bufA = Buffer.from(a);
  const bufB = Buffer.from(b);
  if (bufA.length !== bufB.length) {
    // Compare against self to keep constant time, then return false
    crypto.timingSafeEqual(bufA, bufA);
    return false;
  }
  return crypto.timingSafeEqual(bufA, bufB);
}

app.post('/api/login', (req, res) => {
  const { password } = req.body || {};
  if (typeof password === 'string' && timingSafeEqual(password, PASSWORD)) {
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

// --- Session name validation ---

function isValidName(name) {
  return /^[a-zA-Z0-9_-]{1,50}$/.test(name);
}

// --- tmux session management ---

app.get('/api/sessions', authMiddleware, (req, res) => {
  try {
    const output = execSync(
      'tmux list-sessions -F "#{session_name}||#{session_windows}||#{session_created}||#{session_attached}"',
      { encoding: 'utf8', timeout: 5000 }
    );
    const sessions = output.trim().split('\n').filter(Boolean).map(line => {
      const [name, windows, created, attached] = line.split('||');
      return {
        name,
        windows: parseInt(windows, 10),
        created: parseInt(created, 10) * 1000,
        attached: parseInt(attached, 10) > 0,
      };
    });
    res.json(sessions);
  } catch {
    res.json([]);
  }
});

app.post('/api/sessions', authMiddleware, (req, res) => {
  const name = req.body.name || `s-${Date.now()}`;
  if (!isValidName(name)) {
    return res.status(400).json({ error: 'Invalid name. Use alphanumeric, dash, underscore only.' });
  }
  try {
    execSync(`tmux new-session -d -s '${name}' -c '${HOME_DIR}'`, { timeout: 5000 });
    res.json({ name });
  } catch (e) {
    res.status(400).json({ error: 'Session already exists or failed to create.' });
  }
});

app.delete('/api/sessions/:name', authMiddleware, (req, res) => {
  const { name } = req.params;
  if (!isValidName(name)) {
    return res.status(400).json({ error: 'Invalid session name.' });
  }
  try {
    execSync(`tmux kill-session -t '${name}'`, { timeout: 5000 });
    res.json({ ok: true });
  } catch {
    res.status(400).json({ error: 'Session not found.' });
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

wss.on('connection', (ws, req) => {
  const url = new URL(req.url, 'http://localhost');
  const session = url.searchParams.get('session');

  if (!session || !isValidName(session)) {
    ws.close(1008, 'Invalid session');
    return;
  }

  // Ensure session exists
  try {
    execSync(`tmux has-session -t '${session}'`, { timeout: 5000 });
  } catch {
    try {
      execSync(`tmux new-session -d -s '${session}'`, { timeout: 5000 });
    } catch {
      ws.close(1011, 'Failed to create session');
      return;
    }
  }

  const term = pty.spawn('tmux', ['attach-session', '-t', session], {
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
