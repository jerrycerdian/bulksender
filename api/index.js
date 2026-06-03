import express from 'express';
import cors from 'cors';
import session from 'express-session';
import { fileURLToPath } from 'url';
import path from 'path';
import fs from 'fs';

const app = express();
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const ROOT_DIR = path.join(__dirname, '..');
const STORE_PATH = path.join(ROOT_DIR, 'backend', 'adminStore.json');

app.set('trust proxy', 1);

function logError(label, err) {
  console.error(`[${label}]`, err?.stack || err || 'Unknown error');
}

function readStore() {
  try {
    if (!fs.existsSync(STORE_PATH)) return { admins: [] };
    const raw = fs.readFileSync(STORE_PATH, 'utf8');
    const parsed = JSON.parse(raw || '{"admins":[]}');
    if (!parsed || !Array.isArray(parsed.admins)) return { admins: [] };
    return parsed;
  } catch (err) {
    logError('READ_STORE', err);
    return { admins: [] };
  }
}

function safeAdmin(admin) {
  return {
    username: admin?.username || '',
    role: admin?.role || 'admin'
  };
}

function requireAdmin(req, res, next) {
  try {
    if (req.session?.admin && req.session.admin.role === 'admin') return next();
    return res.status(401).json({
      success: false,
      loggedIn: false,
      error: 'Unauthorized',
      message: 'Admin login required'
    });
  } catch (err) {
    logError('REQUIRE_ADMIN', err);
    return res.status(500).json({ success: false, error: 'Internal error' });
  }
}

const allowedOrigin =
  process.env.FRONTEND_ORIGIN ||
  (process.env.VERCEL_URL ? `https://${process.env.VERCEL_URL}` : 'http://localhost:3000');

app.use(cors({
  origin: allowedOrigin,
  credentials: true
}));

app.use(express.json({ limit: '2mb' }));
app.use(express.urlencoded({ extended: true }));

app.use(session({
  secret: process.env.SESSION_SECRET || 'change-this-secret',
  resave: false,
  saveUninitialized: false,
  proxy: true,
  name: 'connect.sid',
  cookie: {
    httpOnly: true,
    sameSite: 'lax',
    secure: process.env.NODE_ENV === 'production'
  }
}));

function renderLoginPage() {
  return `<!doctype html>
<html lang="id">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Login Admin</title>
  <style>
    body{font-family:Arial,sans-serif;background:#f4f4f4;margin:0;display:flex;min-height:100vh;align-items:center;justify-content:center}
    .card{background:#fff;padding:24px;border-radius:12px;box-shadow:0 8px 24px rgba(0,0,0,.08);width:100%;max-width:360px}
    input,button{width:100%;padding:12px;margin-top:10px;box-sizing:border-box}
    button{cursor:pointer;border:0;border-radius:8px;background:#111;color:#fff}
    .msg{margin-top:12px;color:#c00;min-height:20px}
  </style>
</head>
<body>
  <div class="card">
    <h2>Admin Login</h2>
    <form id="f">
      <input name="username" placeholder="Username" autocomplete="username" required>
      <input name="password" type="password" placeholder="Password" autocomplete="current-password" required>
      <button type="submit">Login</button>
      <div class="msg" id="m"></div>
    </form>
  </div>
  <script>
    const f = document.getElementById('f');
    const m = document.getElementById('m');
    f.addEventListener('submit', async (e) => {
      e.preventDefault();
      m.textContent = 'Loading...';
      const form = new FormData(f);
      const body = Object.fromEntries(form.entries());
      try {
        const r = await fetch('/auth/login', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          credentials: 'include',
          body: JSON.stringify(body)
        });
        const j = await r.json().catch(() => ({}));
        if (!r.ok || !j.success) {
          m.textContent = j.error || 'Login gagal';
          return;
        }
        location.href = '/';
      } catch (err) {
        m.textContent = 'Network error';
      }
    });
  </script>
</body>
</html>`;
}

function renderHomePage(admin) {
  return `<!doctype html>
<html lang="id">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Bulksender</title>
  <style>
    body{font-family:Arial,sans-serif;background:#f6f7fb;margin:0;padding:24px}
    .card{max-width:800px;margin:40px auto;background:#fff;border-radius:12px;padding:24px;box-shadow:0 8px 24px rgba(0,0,0,.08)}
    button{padding:10px 14px;border:0;border-radius:8px;background:#111;color:#fff;cursor:pointer}
    pre{background:#f4f4f4;padding:16px;border-radius:8px;overflow:auto}
  </style>
</head>
<body>
  <div class="card">
    <h1>Bulksender</h1>
    <p>Login sebagai: <strong>${admin.username}</strong> (${admin.role})</p>
    <p>Server berjalan dengan aman di Vercel.</p>
    <button id="logout">Logout</button>
    <pre id="out"></pre>
  </div>
  <script>
    document.getElementById('logout').onclick = async () => {
      await fetch('/auth/logout', { method: 'POST', credentials: 'include' });
      location.href = '/login';
    };
    fetch('/auth/me', { credentials: 'include' })
      .then(r => r.json())
      .then(j => document.getElementById('out').textContent = JSON.stringify(j, null, 2))
      .catch(() => document.getElementById('out').textContent = 'Failed to load session');
  </script>
</body>
</html>`;
}

app.get('/health', (req, res) => {
  res.status(200).json({ success: true, message: 'ok' });
});

app.get('/login', (req, res) => {
  try {
    if (req.session?.admin) return res.redirect('/');
    res.setHeader('Content-Type', 'text/html; charset=utf-8');
    return res.status(200).send(renderLoginPage());
  } catch (err) {
    logError('GET_LOGIN', err);
    return res.status(500).json({ success: false, error: 'Failed to load login page' });
  }
});

app.post('/auth/login', (req, res) => {
  try {
    const { username, password } = req.body || {};
    if (!username || !password) {
      return res.status(400).json({ success: false, error: 'Username dan password wajib diisi' });
    }

    const store = readStore();
    const admin = store.admins.find(a => a.username === username && a.password === password);

    if (!admin) {
      return res.status(401).json({ success: false, error: 'Username atau password salah' });
    }

    req.session.admin = safeAdmin(admin);
    return res.status(200).json({ success: true, message: 'Login berhasil', admin: req.session.admin });
  } catch (err) {
    logError('AUTH_LOGIN', err);
    return res.status(500).json({ success: false, error: 'Login failed' });
  }
});

app.get('/auth/me', (req, res) => {
  try {
    if (!req.session?.admin) {
      return res.status(401).json({
        success: false,
        loggedIn: false,
        error: 'Unauthorized',
        message: 'Admin login required'
      });
    }

    return res.status(200).json({
      success: true,
      loggedIn: true,
      admin: req.session.admin
    });
  } catch (err) {
    logError('AUTH_ME', err);
    return res.status(500).json({ success: false, error: 'Failed to get session' });
  }
});

app.post('/auth/logout', (req, res) => {
  try {
    if (!req.session) {
      return res.status(200).json({ success: true, message: 'Logout berhasil' });
    }

    req.session.destroy((err) => {
      if (err) {
        logError('AUTH_LOGOUT_DESTROY', err);
        return res.status(500).json({ success: false, error: 'Logout gagal' });
      }
      res.clearCookie('connect.sid');
      return res.status(200).json({ success: true, message: 'Logout berhasil' });
    });
  } catch (err) {
    logError('AUTH_LOGOUT', err);
    return res.status(500).json({ success: false, error: 'Logout failed' });
  }
});

app.get('/', (req, res) => {
  try {
    if (!req.session?.admin) return res.redirect('/login');
    res.setHeader('Content-Type', 'text/html; charset=utf-8');
    return res.status(200).send(renderHomePage(req.session.admin));
  } catch (err) {
    logError('GET_HOME', err);
    return res.status(500).json({ success: false, error: 'Failed to load home page' });
  }
});

app.get('/api/ping', (req, res) => {
  try {
    return res.json({ success: true, message: 'ok' });
  } catch (err) {
    logError('API_PING', err);
    return res.status(500).json({ success: false, error: 'Ping failed' });
  }
});

app.get('/api/accounts', requireAdmin, (req, res) => {
  try {
    return res.json({ success: true, accounts: [] });
  } catch (err) {
    logError('API_ACCOUNTS', err);
    return res.status(500).json({ success: false, error: 'Accounts failed' });
  }
});

app.use((req, res) => {
  console.warn('[404]', req.method, req.originalUrl);
  res.status(404).json({ success: false, error: 'Route not found' });
});

app.use((err, req, res, next) => {
  logError('EXPRESS_ERROR_HANDLER', err);
  res.status(500).json({ success: false, error: 'Internal server error' });
});

export default app;