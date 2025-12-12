import express from 'express';
import session from 'express-session';
import helmet from 'helmet';
import compression from 'compression';
import rateLimit from 'express-rate-limit';
import cookieParser from 'cookie-parser';
import dotenv from 'dotenv';
import path from 'path';
import fs from 'fs';
import { fileURLToPath } from 'url';
import sqlite3 from 'sqlite3';
import { open } from 'sqlite';
import PDFDocument from 'pdfkit';
import bcrypt from 'bcryptjs';
import * as XLSX from 'xlsx';

dotenv.config();

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const app = express();
const PORT = process.env.PORT || 3000;
const NODE_ENV = process.env.NODE_ENV || 'development';
const IS_PROD = NODE_ENV === 'production';
const COOKIE_SECURE_ENV = process.env.COOKIE_SECURE === '1';
const USE_SECURE_COOKIES = COOKIE_SECURE_ENV && IS_PROD;

// Si usamos cookies seguras detrás de un proxy (nginx, etc.), hay que confiar en el proxy
if (USE_SECURE_COOKIES) {
  app.set('trust proxy', 1);
}

// -----------------------------------------------------------------------------
// Directorio de datos (BD) – OWASP A05: evitar rutas débiles y asegurar permisos
// -----------------------------------------------------------------------------
const DATA_DIR = path.join(__dirname, 'Data');

// Compatibilidad: si existe carpeta antigua "data", migrar a "Data"
const LEGACY_DATA_DIR = path.join(__dirname, 'data');
try {
  if (!fs.existsSync(DATA_DIR) && fs.existsSync(LEGACY_DATA_DIR)) {
    fs.renameSync(LEGACY_DATA_DIR, DATA_DIR);
  }
} catch (e) {
  // Si falla el rename (permisos/FS), seguimos creando DATA_DIR
}

if (!fs.existsSync(DATA_DIR)) {
  fs.mkdirSync(DATA_DIR, { recursive: true });
}

// -----------------------------------------------------------------------------
// Conexión SQLite – OWASP A03: siempre usar parámetros, nunca concatenar SQL
// -----------------------------------------------------------------------------
const db = await open({
  filename: path.join(DATA_DIR, 'brumapp.db'),
  driver: sqlite3.Database
});

// -----------------------------------------------------------------------------
// Esquema base (para instalaciones nuevas)
// -----------------------------------------------------------------------------
await db.exec(`
CREATE TABLE IF NOT EXISTS users(
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  username TEXT UNIQUE NOT NULL,
  password TEXT NOT NULL,
  role TEXT NOT NULL CHECK(role IN ('operario','supervisor','administrador'))
);
CREATE TABLE IF NOT EXISTS login_lock(
  username TEXT PRIMARY KEY,
  attempts INTEGER NOT NULL DEFAULT 0,
  locked_until INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE IF NOT EXISTS recepciones(
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  tipo TEXT NOT NULL,
  cantidad INTEGER NOT NULL,
  fecha TEXT NOT NULL,
  unidad TEXT,
  created_at TEXT DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS produccion(
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  fecha_ini TEXT NOT NULL,
  fecha_fin TEXT NOT NULL,
  tipo TEXT,
  cantidad INTEGER NOT NULL,
  unidad TEXT,
  created_at TEXT DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS defectuosos(
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  tipo TEXT NOT NULL,
  cantidad INTEGER NOT NULL,
  razon TEXT,
  fecha TEXT NOT NULL,
  unidad TEXT,
  created_at TEXT DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS envios(
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  cantidad INTEGER NOT NULL,
  tipo TEXT NOT NULL,
  descripcion TEXT,
  cliente TEXT NOT NULL,
  fecha TEXT NOT NULL,
  unidad TEXT,
  created_at TEXT DEFAULT CURRENT_TIMESTAMP
);
`);

// -----------------------------------------------------------------------------
// Migraciones simples: añadir columnas si faltan (para BD viejas)
// -----------------------------------------------------------------------------
async function ensureColumn(table, column, typeDef) {
  const info = await db.all(`PRAGMA table_info(${table})`);
  if (!info.some(c => c.name === column)) {
    await db.exec(`ALTER TABLE ${table} ADD COLUMN ${column} ${typeDef}`);
  }
}

// Añadimos unidad y tipo donde toque (si no existen aún)
await ensureColumn('recepciones', 'unidad', 'TEXT');
await ensureColumn('produccion',  'tipo',   'TEXT');
await ensureColumn('produccion',  'unidad', 'TEXT');
await ensureColumn('defectuosos', 'unidad', 'TEXT');
await ensureColumn('envios',      'unidad', 'TEXT');

// -----------------------------------------------------------------------------
// Seed de usuarios – OWASP A07: credenciales hash con bcrypt, roles bien definidos
// -----------------------------------------------------------------------------
const countUsers = await db.get(`SELECT COUNT(*) as c FROM users`);
if (!countUsers || countUsers.c === 0) {
  const hp = await bcrypt.hash('admin', 10);
  await db.run(
    "INSERT INTO users(username,password,role) VALUES(?,?,?)",
    ['operario', hp, 'operario']
  );
  await db.run(
    "INSERT INTO users(username,password,role) VALUES(?,?,?)",
    ['supervisor', hp, 'supervisor']
  );
  await db.run(
    "INSERT INTO users(username,password,role) VALUES(?,?,?)",
    ['administrador', hp, 'administrador']
  );
  console.log('Seeded users (bcrypt): operario/supervisor/administrador -> admin');
}

// -----------------------------------------------------------------------------
// Helpers de formato de fecha (string helpers)
// -----------------------------------------------------------------------------
function formatDateYmdToDmy(s) {
  if (!s) return '';
  const datePart = String(s).split(/[T ]/)[0];
  const parts = datePart.split('-');
  if (parts.length !== 3) return s;
  const [y, m, d] = parts;
  return `${d}-${m}-${y}`;
}

function formatDateTimeYmdToDmy(s) {
  if (!s) return '';
  const [datePartRaw, timeRaw] = String(s).split(/[T ]/);
  const parts = (datePartRaw || '').split('-');
  if (parts.length !== 3) return s;
  const [y, m, d] = parts;
  const date = `${d}-${m}-${y}`;
  if (!timeRaw) return date;
  const time = timeRaw.slice(0, 5); // HH:MM
  return `${date} ${time}`;
}

// -----------------------------------------------------------------------------
// Filtros por rango de fechas (YYYY-MM-DD) para listados y exportaciones
//  - from / to son inclusivos
//  - el campo puede ser DATE (YYYY-MM-DD) o DATETIME (YYYY-MM-DDTHH:MM)
// -----------------------------------------------------------------------------
function normalizeYmd(v) {
  const s = String(v || '').trim();
  if (!s) return '';
  const m = s.match(/^\d{4}-\d{2}-\d{2}/);
  return m ? m[0] : '';
}

function buildDateWhere({ field, from, to }) {
  const f = normalizeYmd(from);
  const t = normalizeYmd(to);
  const dateExpr = `date(substr(${field},1,10))`;
  if (f && t) {
    return {
      where: `WHERE ${dateExpr} BETWEEN date(?) AND date(?)`,
      params: [f, t]
    };
  }
  if (f) {
    return {
      where: `WHERE ${dateExpr} >= date(?)`,
      params: [f]
    };
  }
  if (t) {
    return {
      where: `WHERE ${dateExpr} <= date(?)`,
      params: [t]
    };
  }
  return { where: '', params: [] };
}


function buildTextSearchWhere(q, fields) {
  const qq = String(q || '').trim().toLowerCase();
  if (!qq) return { clause: '', params: [] };
  const like = `%${qq}%`;
  const parts = (fields || []).map(f => `LOWER(COALESCE(${f},'')) LIKE ?`);
  if (!parts.length) return { clause: '', params: [] };
  return { clause: `(${parts.join(' OR ')})`, params: Array(parts.length).fill(like) };
}

function buildQtyWhere(minQty, maxQty, field = 'cantidad') {
  const min = minQty !== undefined && minQty !== null && String(minQty).trim() !== '' ? Number(minQty) : null;
  const max = maxQty !== undefined && maxQty !== null && String(maxQty).trim() !== '' ? Number(maxQty) : null;
  const expr = `CAST(${field} AS REAL)`;
  if (Number.isFinite(min) && Number.isFinite(max)) {
    return { clause: `(${expr} BETWEEN ? AND ?)`, params: [min, max] };
  }
  if (Number.isFinite(min)) {
    return { clause: `(${expr} >= ?)`, params: [min] };
  }
  if (Number.isFinite(max)) {
    return { clause: `(${expr} <= ?)`, params: [max] };
  }
  return { clause: '', params: [] };
}

function mergeWhere(baseWhere, baseParams, extraClauses, extraParams) {
  const clauses = [];
  if (baseWhere && baseWhere.trim()) {
    // baseWhere can be 'WHERE ...' or ''
    clauses.push(baseWhere.trim().replace(/^WHERE\s+/i, ''));
  }
  (extraClauses || []).forEach(c => {
    if (c && String(c).trim()) clauses.push(String(c).trim());
  });
  const where = clauses.length ? `WHERE ${clauses.join(' AND ')}` : '';
  return { where, params: [...(baseParams || []), ...(extraParams || [])] };
}

// -----------------------------------------------------------------------------
// Seguridad global – OWASP A05 (Security Misconfiguration) y A06 (Vulnerable & Outdated)
// -----------------------------------------------------------------------------
app.disable('x-powered-by');

// -----------------------------------------------------------------------------
// Helmet y cabeceras de seguridad
//  - En producción: CSP sin "upgrade-insecure-requests"
//  - En desarrollo: CSP desactivada para no romper HTTP simple en el VPS
// -----------------------------------------------------------------------------
if (IS_PROD) {
  app.use(helmet({
    contentSecurityPolicy: {
      // NO usamos los defaults para evitar "upgrade-insecure-requests"
      useDefaults: false,
      directives: {
        "default-src": ["'self'"],
        "script-src": ["'self'"],
        "style-src": ["'self'", "'unsafe-inline'"],
        "img-src": ["'self'", "data:"],
        "font-src": ["'self'", "data:"],
        "object-src": ["'none'"],
        "frame-ancestors": ["'none'"],
        "base-uri": ["'self'"],
        "form-action": ["'self'"]
      }
    },
    referrerPolicy: { policy: "no-referrer" },
    crossOriginEmbedderPolicy: false
  }));
} else {
  // Desarrollo: sin CSP, solo referrerPolicy y demás protecciones ligeras
  app.use(helmet({
    contentSecurityPolicy: false,
    referrerPolicy: { policy: "no-referrer" },
    crossOriginEmbedderPolicy: false
  }));
}

// Compresión – mejora rendimiento
app.use(compression());

// Body parsers – OWASP A04: limitar tamaño de petición para evitar DOS
app.use(express.json({ limit: "100kb" }));
app.use(express.urlencoded({ extended: false, limit: "100kb" }));

app.use(cookieParser());

// OWASP A07: configuración robusta de sesión
const SESSION_SECRET = process.env.SESSION_SECRET;
if (!SESSION_SECRET && IS_PROD) {
  console.warn(
    '[WARN] SESSION_SECRET no está definido en producción. ' +
    'Define una variable de entorno segura para evitar secretos débiles.'
  );
}

app.use(session({
  name: 'brumapp.sid',
  secret: SESSION_SECRET || 'dev_secret_change_me',
  resave: false,
  saveUninitialized: false,
  cookie: {
    httpOnly: true,
    sameSite: 'lax',
    secure: USE_SECURE_COOKIES ? 'auto' : false,
    maxAge: 1000 * 60 * 60 * 8 // 8 horas
  }
}));

// -----------------------------------------------------------------------------
// Rate limits – OWASP A05/A10: protección básica frente a fuerza bruta y DOS
// -----------------------------------------------------------------------------
const apiLimiter = rateLimit({
  windowMs: 60 * 1000,
  max: 200,
  standardHeaders: true,
  legacyHeaders: false
});
app.use('/api/', apiLimiter);

const loginLimiter = rateLimit({
  windowMs: 60 * 1000,
  max: 20,
  standardHeaders: true,
  legacyHeaders: false
});
app.use(['/api/auth/login', '/login'], loginLimiter);

// -----------------------------------------------------------------------------
// CSRF simple con excepción login – OWASP A05/A01
// -----------------------------------------------------------------------------
function ensureCsrf(req, res, next) {
  if (!req.session.csrf) {
    req.session.csrf =
      Math.random().toString(36).slice(2) +
      Math.random().toString(36).slice(2);
  }
  next();
}

function csrfProtect(req, res, next) {
  const m = (req.method || 'GET').toUpperCase();
  if (['POST', 'PUT', 'PATCH', 'DELETE'].includes(m)) {
    if (req.path === '/api/auth/login' || req.path === '/login') return next();
    const token = req.get('x-csrf-token');
    if (!token || token !== req.session.csrf) {
      return res.status(403).json({ error: 'bad-csrf' });
    }
  }
  next();
}

app.get('/csrf', ensureCsrf, (req, res) =>
  res.json({ token: req.session.csrf || '' })
);

app.use(csrfProtect);

// -----------------------------------------------------------------------------
// Static – sirve todo lo de /public (HTML, CSS, JS, imágenes)
// -----------------------------------------------------------------------------
const PUBLIC_DIR = path.join(__dirname, 'public');
const LOGO_PATH = path.join(PUBLIC_DIR, 'assets', 'img', 'logo.png');

app.use(express.static(PUBLIC_DIR, {
  extensions: ['html'],
  setHeaders(res, p) {
    if (p.endsWith('.html')) {
      res.setHeader('Cache-Control', 'no-store');
    } else {
      res.setHeader('Cache-Control', 'public, max-age=31536000, immutable');
    }
  }
}));

// -----------------------------------------------------------------------------
// Auth helpers – OWASP A01: Broken Access Control (chequeos SIEMPRE en backend)
// -----------------------------------------------------------------------------
function requireAuth(req, res, next) {
  if (!req.session.user) {
    return res.status(401).json({ error: 'unauthenticated' });
  }
  next();
}

function requireRole(...roles) {
  return (req, res, next) => {
    if (!req.session.user) {
      return res.status(401).json({ error: 'unauthenticated' });
    }
    if (!roles.includes(req.session.user.role)) {
      return res.status(403).json({ error: 'forbidden' });
    }
    next();
  };
}

// -----------------------------------------------------------------------------
// Lock helpers – OWASP A07: bloqueo escalonado ante intentos de login fallidos
// -----------------------------------------------------------------------------
async function getLock(u) {
  const r = await db.get(
    "SELECT username, attempts, locked_until FROM login_lock WHERE username = ?",
    [u]
  );
  return r || { username: u, attempts: 0, locked_until: 0 };
}

async function saveLock(rec) {
  await db.run(
    "INSERT INTO login_lock(username,attempts,locked_until) VALUES(?,?,?) " +
    "ON CONFLICT(username) DO UPDATE SET attempts=excluded.attempts, locked_until=excluded.locked_until",
    [rec.username, rec.attempts, rec.locked_until]
  );
}

function lockDuration(stage) {
  if (stage <= 1) return 60;
  if (stage === 2) return 180;
  if (stage === 3) return 900;
  if (stage === 4) return 1800;
  return 3600;
}

// -----------------------------------------------------------------------------
// Login handler – OWASP A07 (auth), A02 (bcrypt), A05 (errores genéricos)
// -----------------------------------------------------------------------------
async function loginHandler(req, res) {
  const { username, password } = req.body || {};
  const uname = String(username || '').toLowerCase().trim();
  const isJson = !!req.is('application/json');

  const now = Math.floor(Date.now() / 1000);
  let lock = await getLock(uname);
  if (lock.locked_until && lock.locked_until > now) {
    const waitSec = lock.locked_until - now;
    if (isJson) {
      return res.status(429).json({ error: 'locked', waitSec });
    }
    return res.redirect('/?locked=1&waitSec=' + waitSec);
  }

  const user = await db.get("SELECT * FROM users WHERE username = ?", [uname]);
  let ok = false;
  if (user) {
    ok = await bcrypt.compare(String(password || ''), user.password);
  }

  if (!user || !ok) {
    lock.attempts = (lock.attempts || 0) + 1;
    if (lock.attempts % 3 === 0) {
      const stage = Math.floor(lock.attempts / 3);
      lock.locked_until = now + lockDuration(stage);
    }
    await saveLock(lock);
    if (isJson) {
      return res.status(401).json({
        error: 'bad-credentials',
        attempts: lock.attempts,
        lockedUntil: lock.locked_until
      });
    }
    return res.redirect(
      '/?error=1&attempts=' +
      lock.attempts +
      '&lockedUntil=' +
      (lock.locked_until || 0)
    );
  }

  lock.attempts = 0;
  lock.locked_until = 0;
  await saveLock(lock);

  req.session.user = { id: user.id, username: user.username, role: user.role };
  if (isJson) {
    return res.json({ ok: true, user: req.session.user });
  }
  return res.redirect('/panel.html');
}

app.post('/api/auth/login', loginHandler);
app.post('/login', loginHandler);

app.post('/api/auth/logout', requireAuth, (req, res) => {
  req.session.destroy(() => res.json({ ok: true }));
});

app.get('/me', (req, res) => {
  res.json({ user: req.session.user || null });
});

// -----------------------------------------------------------------------------
// Recepciones
// -----------------------------------------------------------------------------
app.get('/api/recepciones', requireAuth, async (req, res) => {
  const { from, to, q, min, max } = req.query || {};
  const f = buildDateWhere({ field: 'fecha', from, to });
  const s = buildTextSearchWhere(q, ['tipo','unidad']);
  const qty = buildQtyWhere(min, max, 'cantidad');
  const mw = mergeWhere(f.where, f.params, [s.clause, qty.clause], [...s.params, ...qty.params]);
  const list = await db.all(
    `SELECT * FROM recepciones ${mw.where} ORDER BY created_at DESC`,
    mw.params
  );
  res.json({ items: list });
});

app.post('/api/recepciones', requireRole('supervisor', 'administrador'), async (req, res) => {
  const { tipo, cantidad, fecha, unidad } = req.body || {};
  const c = parseInt(cantidad, 10);
  const t = String(tipo || '').slice(0, 64);
  const f = String(fecha || '').slice(0, 32);
  const u = String(unidad || '').slice(0, 16);

  if (!t || !Number.isFinite(c) || c <= 0 || !f) {
    return res.status(400).json({ error: 'invalid' });
  }

  await db.run(
    "INSERT INTO recepciones(tipo,cantidad,fecha,unidad) VALUES(?,?,?,?)",
    [t, c, f, u]
  );
  res.json({ ok: true });
});

app.put('/api/recepciones/:id', requireRole('supervisor', 'administrador'), async (req, res) => {
  const id = parseInt(req.params.id, 10);
  const { tipo, cantidad, fecha, unidad } = req.body || {};
  const c = parseInt(cantidad, 10);
  const t = String(tipo || '').slice(0, 64);
  const f = String(fecha || '').slice(0, 32);
  const u = String(unidad || '').slice(0, 16);

  if (!id || !t || !Number.isFinite(c) || c <= 0 || !f) {
    return res.status(400).json({ error: 'invalid' });
  }

  await db.run(
    "UPDATE recepciones SET tipo=?, cantidad=?, fecha=?, unidad=? WHERE id=?",
    [t, c, f, u, id]
  );
  res.json({ ok: true });
});

app.delete('/api/recepciones/:id', requireRole('supervisor', 'administrador'), async (req, res) => {
  const id = parseInt(req.params.id, 10);
  if (!id) return res.status(400).json({ error: 'invalid' });
  await db.run("DELETE FROM recepciones WHERE id=?", [id]);
  res.json({ ok: true });
});

// -----------------------------------------------------------------------------
// Producción
// -----------------------------------------------------------------------------
app.get('/api/produccion', requireAuth, async (req, res) => {
  const { from, to, q, min, max } = req.query || {};
  const f = buildDateWhere({ field: 'fecha_ini', from, to });
  const s = buildTextSearchWhere(q, ['tipo','unidad']);
  const qty = buildQtyWhere(min, max, 'cantidad');
  const mw = mergeWhere(f.where, f.params, [s.clause, qty.clause], [...s.params, ...qty.params]);
  const list = await db.all(
    `SELECT * FROM produccion ${mw.where} ORDER BY created_at DESC`,
    mw.params
  );
  res.json({ items: list });
});

app.post('/api/produccion', requireRole('supervisor', 'administrador'), async (req, res) => {
  const { fecha_ini, fecha_fin, cantidad, tipo, unidad } = req.body || {};
  const c = parseInt(cantidad, 10);
  const fi = String(fecha_ini || '').slice(0, 32);
  const ff = String(fecha_fin || fecha_ini || '').slice(0, 32);
  const tp = String(tipo || '').slice(0, 64);
  const u = String(unidad || '').slice(0, 16);

  if (!Number.isFinite(c) || c <= 0 || !fi || !ff || !tp) {
    return res.status(400).json({ error: 'invalid' });
  }

  await db.run(
    "INSERT INTO produccion(fecha_ini,fecha_fin,tipo,cantidad,unidad) VALUES(?,?,?,?,?)",
    [fi, ff, tp, c, u]
  );
  res.json({ ok: true });
});

app.put('/api/produccion/:id', requireRole('supervisor', 'administrador'), async (req, res) => {
  const id = parseInt(req.params.id, 10);
  const { fecha_ini, fecha_fin, cantidad, tipo, unidad } = req.body || {};
  const c = parseInt(cantidad, 10);
  const fi = String(fecha_ini || '').slice(0, 32);
  const ff = String(fecha_fin || fecha_ini || '').slice(0, 32);
  const tp = String(tipo || '').slice(0, 64);
  const u = String(unidad || '').slice(0, 16);

  if (!id || !Number.isFinite(c) || c <= 0 || !fi || !ff || !tp) {
    return res.status(400).json({ error: 'invalid' });
  }

  await db.run(
    "UPDATE produccion SET fecha_ini=?, fecha_fin=?, tipo=?, cantidad=?, unidad=? WHERE id=?",
    [fi, ff, tp, c, u, id]
  );
  res.json({ ok: true });
});

app.delete('/api/produccion/:id', requireRole('supervisor', 'administrador'), async (req, res) => {
  const id = parseInt(req.params.id, 10);
  if (!id) return res.status(400).json({ error: 'invalid' });
  await db.run("DELETE FROM produccion WHERE id=?", [id]);
  res.json({ ok: true });
});

// -----------------------------------------------------------------------------
// Defectuosos
// -----------------------------------------------------------------------------
app.get('/api/defectuosos', requireAuth, async (req, res) => {
  const { from, to, q, min, max } = req.query || {};
  const f = buildDateWhere({ field: 'fecha', from, to });
  const s = buildTextSearchWhere(q, ['tipo','razon','unidad']);
  const qty = buildQtyWhere(min, max, 'cantidad');
  const mw = mergeWhere(f.where, f.params, [s.clause, qty.clause], [...s.params, ...qty.params]);
  const list = await db.all(
    `SELECT * FROM defectuosos ${mw.where} ORDER BY created_at DESC`,
    mw.params
  );
  res.json({ items: list });
});

app.post('/api/defectuosos', requireRole('supervisor', 'administrador'), async (req, res) => {
  const { tipo, cantidad, razon, fecha, unidad } = req.body || {};
  const c = parseInt(cantidad, 10);
  const t = String(tipo || '').slice(0, 64);
  const r = String(razon || '').slice(0, 256);
  const f = String(fecha || '').slice(0, 32);
  const u = String(unidad || '').slice(0, 16);

  if (!Number.isFinite(c) || c <= 0 || !t || !f) {
    return res.status(400).json({ error: 'invalid' });
  }

  await db.run(
    "INSERT INTO defectuosos(tipo,cantidad,razon,fecha,unidad) VALUES(?,?,?,?,?)",
    [t, c, r, f, u]
  );
  res.json({ ok: true });
});

app.put('/api/defectuosos/:id', requireRole('supervisor', 'administrador'), async (req, res) => {
  const id = parseInt(req.params.id, 10);
  const { tipo, cantidad, razon, fecha, unidad } = req.body || {};
  const c = parseInt(cantidad, 10);
  const t = String(tipo || '').slice(0, 64);
  const r = String(razon || '').slice(0, 256);
  const f = String(fecha || '').slice(0, 32);
  const u = String(unidad || '').slice(0, 16);

  if (!id || !Number.isFinite(c) || c <= 0 || !t || !f) {
    return res.status(400).json({ error: 'invalid' });
  }

  await db.run(
    "UPDATE defectuosos SET tipo=?, cantidad=?, razon=?, fecha=?, unidad=? WHERE id=?",
    [t, c, r, f, u, id]
  );
  res.json({ ok: true });
});

app.delete('/api/defectuosos/:id', requireRole('supervisor', 'administrador'), async (req, res) => {
  const id = parseInt(req.params.id, 10);
  if (!id) return res.status(400).json({ error: 'invalid' });
  await db.run("DELETE FROM defectuosos WHERE id=?", [id]);
  res.json({ ok: true });
});

// -----------------------------------------------------------------------------
// Envíos
// -----------------------------------------------------------------------------
app.get('/api/envios', requireAuth, async (req, res) => {
  const { from, to, q, min, max } = req.query || {};
  const f = buildDateWhere({ field: 'fecha', from, to });
  const s = buildTextSearchWhere(q, ['cliente','tipo','descripcion','unidad']);
  const qty = buildQtyWhere(min, max, 'cantidad');
  const mw = mergeWhere(f.where, f.params, [s.clause, qty.clause], [...s.params, ...qty.params]);
  const list = await db.all(
    `SELECT * FROM envios ${mw.where} ORDER BY created_at DESC`,
    mw.params
  );
  res.json({ items: list });
});

app.post('/api/envios', requireRole('supervisor', 'administrador'), async (req, res) => {
  const { cantidad, tipo, descripcion = '', cliente, fecha, unidad } = req.body || {};
  const c = parseInt(cantidad, 10);
  const t = String(tipo || '').slice(0, 64);
  const d = String(descripcion || '').slice(0, 256);
  const cl = String(cliente || '').slice(0, 128);
  const f = String(fecha || '').slice(0, 32);
  const u = String(unidad || '').slice(0, 16);

  if (!Number.isFinite(c) || c <= 0 || !t || !cl || !f) {
    return res.status(400).json({ error: 'invalid' });
  }

  await db.run(
    "INSERT INTO envios(cantidad,tipo,descripcion,cliente,fecha,unidad) VALUES(?,?,?,?,?,?)",
    [c, t, d, cl, f, u]
  );
  res.json({ ok: true });
});

app.put('/api/envios/:id', requireRole('supervisor', 'administrador'), async (req, res) => {
  const id = parseInt(req.params.id, 10);
  const { cantidad, tipo, descripcion = '', cliente, fecha, unidad } = req.body || {};
  const c = parseInt(cantidad, 10);
  const t = String(tipo || '').slice(0, 64);
  const d = String(descripcion || '').slice(0, 256);
  const cl = String(cliente || '').slice(0, 128);
  const f = String(fecha || '').slice(0, 32);
  const u = String(unidad || '').slice(0, 16);

  if (!id || !Number.isFinite(c) || c <= 0 || !t || !cl || !f) {
    return res.status(400).json({ error: 'invalid' });
  }

  await db.run(
    "UPDATE envios SET cantidad=?, tipo=?, descripcion=?, cliente=?, fecha=?, unidad=? WHERE id=?",
    [c, t, d, cl, f, u, id]
  );
  res.json({ ok: true });
});

app.delete('/api/envios/:id', requireRole('supervisor', 'administrador'), async (req, res) => {
  const id = parseInt(req.params.id, 10);
  if (!id) return res.status(400).json({ error: 'invalid' });
  await db.run("DELETE FROM envios WHERE id=?", [id]);
  res.json({ ok: true });
});

// -----------------------------------------------------------------------------
// PDFs BONITOS
// -----------------------------------------------------------------------------
function formatPdfDateOnly(s) {
  if (!s) return '';
  return formatDateYmdToDmy(s);
}

function formatPdfDateTime(s) {
  if (!s) return '';
  return formatDateTimeYmdToDmy(s);
}

function startPdf(res, filename, title) {
  res.setHeader('Content-Type', 'application/pdf');
  res.setHeader('Content-Disposition', `attachment; filename="${filename}"`);

  const doc = new PDFDocument({ size: 'A4', margin: 36 });
  doc.pipe(res);

  try {
    if (fs.existsSync(LOGO_PATH)) {
      doc.image(LOGO_PATH, 36, 24, { fit: [60, 60] });
    }
  } catch (e) {
    // Si falla el logo, seguimos igual
  }

  doc
    .fillColor('#ff8c1a')
    .fontSize(22)
    .text('BRUMAP', 110, 32);

  doc
    .moveDown()
    .fillColor('#000000')
    .fontSize(14)
    .text(title, { align: 'center' });

  const now = new Date();
  const nowStr = now.toLocaleString('es-PE', {
    timeZone: 'America/Lima'
  });

  doc
    .moveDown(0.5)
    .fontSize(9)
    .fillColor('#555555')
    .text(`Generado: ${nowStr}`, { align: 'right' });

  doc.moveDown(1);
  return doc;
}

function drawTable(doc, headers, widths, rowValues) {
  const marginX = doc.page.margins.left;
  const marginRight = doc.page.margins.right;
  const tableWidth = doc.page.width - marginX - marginRight;

  // Asegura que widths sume aproximadamente el ancho disponible
  // (si no coincide, PDFKit igual respeta los widths declarados)
  const headerH = 20;
  const minRowH = 18;

  let y = doc.y;

  function drawHeader() {
    doc
      .save()
      .fillColor('#ff8c1a')
      .rect(marginX, y, tableWidth, headerH)
      .fill();

    doc.fillColor('#181818').fontSize(10).font('Helvetica-Bold');
    let x = marginX + 4;
    headers.forEach((h, i) => {
      doc.text(String(h), x, y + 5, { width: widths[i] - 8 });
      x += widths[i];
    });
    doc.restore();
    doc.font('Helvetica');
    y += headerH;
  }

  const bottomLimit = () => doc.page.height - doc.page.margins.bottom;

  drawHeader();
  doc.fontSize(10).fillColor('#000000');

  for (const cols of rowValues) {
    // Calcula altura dinámica por contenido (wrap)
    let maxH = 0;
    for (let i = 0; i < cols.length; i++) {
      const txt = cols[i] === null || cols[i] === undefined ? '' : String(cols[i]);
      const w = Math.max(20, (widths[i] || 0) - 8);
      const h = doc.heightOfString(txt, { width: w, lineBreak: true });
      if (h > maxH) maxH = h;
    }
    const rowH = Math.max(minRowH, Math.ceil(maxH) + 8);

    // Salto de página si no entra
    if (y + rowH > bottomLimit()) {
      doc.addPage();
      y = doc.page.margins.top;
      drawHeader();
      doc.fontSize(10).fillColor('#000000');
    }

    // Dibuja celdas (texto con wrap)
    let x = marginX + 4;
    for (let i = 0; i < cols.length; i++) {
      const txt = cols[i] === null || cols[i] === undefined ? '' : String(cols[i]);
      doc.text(txt, x, y + 4, {
        width: widths[i] - 8,
        lineBreak: true
      });
      x += widths[i];
    }

    // Línea inferior de la fila
    doc
      .moveTo(marginX, y + rowH - 1)
      .lineTo(marginX + tableWidth, y + rowH - 1)
      .strokeColor('#3a3d44')
      .lineWidth(0.5)
      .stroke();

    y += rowH;
  }

  doc.moveDown();
  doc.y = y + 4;
}


// -----------------------------------------------------------------------------
// Exportación XLSX (Excel)
// -----------------------------------------------------------------------------
function sendXlsx(res, filename, sheets) {
  // sheets: Array<{ name: string, aoa: any[][] }>
  const wb = XLSX.utils.book_new();
  for (const s of sheets) {
    const ws = XLSX.utils.aoa_to_sheet(s.aoa);
    XLSX.utils.book_append_sheet(wb, ws, s.name);
  }

  const buf = XLSX.write(wb, { bookType: 'xlsx', type: 'buffer' });
  res.setHeader(
    'Content-Type',
    'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet'
  );
  res.setHeader('Content-Disposition', `attachment; filename="${filename}"`);
  res.end(buf);
}

function safeSheetName(name) {
  const s = String(name || 'Sheet').replace(/[\\/\?\*\[\]]/g, '-');
  return s.length > 31 ? s.slice(0, 31) : s;
}

// PDFs por módulo
app.get('/api/recepciones.pdf', requireAuth, async (req, res) => {
  const { from, to, q, min, max } = req.query || {};
  const f = buildDateWhere({ field: 'fecha', from, to });
  const s = buildTextSearchWhere(q, ['tipo','unidad']);
  const qty = buildQtyWhere(min, max, 'cantidad');
  const mw = mergeWhere(f.where, f.params, [s.clause, qty.clause], [...s.params, ...qty.params]);
  const list = await db.all(
    `SELECT * FROM recepciones ${mw.where} ORDER BY created_at DESC`,
    mw.params
  );
  const doc = startPdf(res, 'recepciones.pdf', 'Recepción de Materiales');

  const headers = ['Fecha', 'Tipo', 'Cantidad', 'Unidad'];
  const widths = [90, 270, 70, 60];

  const rows = list.map(r => [
    formatPdfDateTime(r.fecha),
    r.tipo,
    r.cantidad,
    r.unidad || ''
  ]);

  drawTable(doc, headers, widths, rows);
  doc.end();
});
app.get('/api/produccion.pdf', requireAuth, async (req, res) => {
  const { from, to, q, min, max } = req.query || {};
  const f = buildDateWhere({ field: 'fecha_ini', from, to });
  const s = buildTextSearchWhere(q, ['tipo','unidad']);
  const qty = buildQtyWhere(min, max, 'cantidad');
  const mw = mergeWhere(f.where, f.params, [s.clause, qty.clause], [...s.params, ...qty.params]);
  const list = await db.all(
    `SELECT * FROM produccion ${mw.where} ORDER BY created_at DESC`,
    mw.params
  );
  const doc = startPdf(res, 'produccion.pdf', 'Producción');

  const headers = ['Fecha', 'Tipo de producto', 'Cantidad', 'Unidad'];
  const widths = [90, 270, 70, 60];

  const rows = list.map(r => [
    formatPdfDateTime(r.fecha_ini),
    r.tipo || '',
    r.cantidad,
    r.unidad || ''
  ]);

  drawTable(doc, headers, widths, rows);
  doc.end();
});
app.get('/api/defectuosos.pdf', requireAuth, async (req, res) => {
  const { from, to, q, min, max } = req.query || {};
  const f = buildDateWhere({ field: 'fecha', from, to });
  const s = buildTextSearchWhere(q, ['tipo','razon','unidad']);
  const qty = buildQtyWhere(min, max, 'cantidad');
  const mw = mergeWhere(f.where, f.params, [s.clause, qty.clause], [...s.params, ...qty.params]);
  const list = await db.all(
    `SELECT * FROM defectuosos ${mw.where} ORDER BY created_at DESC`,
    mw.params
  );
  const doc = startPdf(res, 'defectuosos.pdf', 'Manejo de Material Defectuoso');

  const headers = ['Fecha', 'Tipo', 'Cantidad', 'Unidad', 'Razón'];
  const widths = [80, 200, 60, 60, 120];

  const rows = list.map(r => [
    formatPdfDateOnly(r.fecha),
    r.tipo,
    r.cantidad,
    r.unidad || '',
    r.razon || ''
  ]);

  drawTable(doc, headers, widths, rows);
  doc.end();
});
app.get('/api/envios.pdf', requireAuth, async (req, res) => {
  const { from, to, q, min, max } = req.query || {};
  const f = buildDateWhere({ field: 'fecha', from, to });
  const s = buildTextSearchWhere(q, ['cliente','tipo','descripcion','unidad']);
  const qty = buildQtyWhere(min, max, 'cantidad');
  const mw = mergeWhere(f.where, f.params, [s.clause, qty.clause], [...s.params, ...qty.params]);
  const list = await db.all(
    `SELECT * FROM envios ${mw.where} ORDER BY created_at DESC`,
    mw.params
  );
  const doc = startPdf(res, 'envios.pdf', 'Envío de Productos Terminados');

  const headers = ['Fecha', 'Cliente', 'Tipo', 'Detalle', 'Cantidad', 'Unidad'];
  const widths = [80, 120, 140, 160, 60, 60];

  const rows = list.map(r => [
    formatPdfDateOnly(r.fecha),
    r.cliente,
    r.tipo,
    r.descripcion || '',
    r.cantidad,
    r.unidad || ''
  ]);

  drawTable(doc, headers, widths, rows);
  doc.end();
});
// XLSX por módulo (respeta filtros from/to)
app.get('/api/recepciones.xlsx', requireAuth, async (req, res) => {
  const { from, to, q, min, max } = req.query || {};
  const f = buildDateWhere({ field: 'fecha', from, to });
  const s = buildTextSearchWhere(q, ['tipo','unidad']);
  const qty = buildQtyWhere(min, max, 'cantidad');
  const mw = mergeWhere(f.where, f.params, [s.clause, qty.clause], [...s.params, ...qty.params]);
  const list = await db.all(
    `SELECT * FROM recepciones ${mw.where} ORDER BY created_at DESC`,
    mw.params
  );
  const aoa = [
    ['Fecha', 'Tipo', 'Cantidad', 'Unidad'],
    ...list.map(r => [formatPdfDateTime(r.fecha), r.tipo, r.cantidad, r.unidad || ''])
  ];
  sendXlsx(res, 'recepciones.xlsx', [{ name: safeSheetName('Recepciones'), aoa }]);
});
app.get('/api/produccion.xlsx', requireAuth, async (req, res) => {
  const { from, to, q, min, max } = req.query || {};
  const f = buildDateWhere({ field: 'fecha_ini', from, to });
  const s = buildTextSearchWhere(q, ['tipo','unidad']);
  const qty = buildQtyWhere(min, max, 'cantidad');
  const mw = mergeWhere(f.where, f.params, [s.clause, qty.clause], [...s.params, ...qty.params]);
  const list = await db.all(
    `SELECT * FROM produccion ${mw.where} ORDER BY created_at DESC`,
    mw.params
  );
  const aoa = [
    ['Fecha', 'Tipo de producto', 'Cantidad', 'Unidad'],
    ...list.map(r => [formatPdfDateTime(r.fecha_ini), r.tipo || '', r.cantidad, r.unidad || ''])
  ];
  sendXlsx(res, 'produccion.xlsx', [{ name: safeSheetName('Produccion'), aoa }]);
});
app.get('/api/defectuosos.xlsx', requireAuth, async (req, res) => {
  const { from, to, q, min, max } = req.query || {};
  const f = buildDateWhere({ field: 'fecha', from, to });
  const s = buildTextSearchWhere(q, ['tipo','razon','unidad']);
  const qty = buildQtyWhere(min, max, 'cantidad');
  const mw = mergeWhere(f.where, f.params, [s.clause, qty.clause], [...s.params, ...qty.params]);
  const list = await db.all(
    `SELECT * FROM defectuosos ${mw.where} ORDER BY created_at DESC`,
    mw.params
  );
  const aoa = [
    ['Fecha', 'Tipo', 'Cantidad', 'Unidad', 'Razón'],
    ...list.map(r => [formatPdfDateOnly(r.fecha), r.tipo, r.cantidad, r.unidad || '', r.razon || ''])
  ];
  sendXlsx(res, 'defectuosos.xlsx', [{ name: safeSheetName('Defectuosos'), aoa }]);
});
app.get('/api/envios.xlsx', requireAuth, async (req, res) => {
  const { from, to, q, min, max } = req.query || {};
  const f = buildDateWhere({ field: 'fecha', from, to });
  const s = buildTextSearchWhere(q, ['cliente','tipo','descripcion','unidad']);
  const qty = buildQtyWhere(min, max, 'cantidad');
  const mw = mergeWhere(f.where, f.params, [s.clause, qty.clause], [...s.params, ...qty.params]);
  const list = await db.all(
    `SELECT * FROM envios ${mw.where} ORDER BY created_at DESC`,
    mw.params
  );
  const aoa = [
    ['Fecha', 'Cliente', 'Tipo', 'Detalle', 'Cantidad', 'Unidad'],
    ...list.map(r => [
      formatPdfDateOnly(r.fecha),
      r.cliente,
      r.tipo,
      r.descripcion || '',
      r.cantidad,
      r.unidad || ''
    ])
  ];
  sendXlsx(res, 'envios.xlsx', [{ name: safeSheetName('Envios'), aoa }]);
});
app.get('/api/registros.pdf', requireAuth, async (req, res) => {
  const doc = startPdf(res, 'registros_completos.pdf', 'Registro Completo de Operaciones');

  const { from, to } = req.query || {};

  const sections = [
    {
      titulo: 'Recepción de Materiales',
      table: 'recepciones',
      field: 'fecha',
      headers: ['Fecha', 'Tipo', 'Cantidad', 'Unidad'],
      widths: [100, 210, 80, 60],
      map: r => [
        formatPdfDateTime(r.fecha),
        r.tipo,
        r.cantidad,
        r.unidad || ''
      ]
    },
    {
      titulo: 'Producción',
      table: 'produccion',
      field: 'fecha_ini',
      headers: ['Fecha', 'Tipo de producto', 'Cantidad', 'Unidad'],
      widths: [100, 210, 80, 60],
      map: r => [
        formatPdfDateTime(r.fecha_ini),
        r.tipo || '',
        r.cantidad,
        r.unidad || ''
      ]
    },
    {
      titulo: 'Manejo de Material Defectuoso',
      table: 'defectuosos',
      field: 'fecha',
      headers: ['Fecha', 'Tipo', 'Cantidad', 'Unidad', 'Razón'],
      widths: [80, 130, 60, 60, 140],
      map: r => [
        formatPdfDateOnly(r.fecha),
        r.tipo,
        r.cantidad,
        r.unidad || '',
        r.razon || ''
      ]
    },
    {
      titulo: 'Envío de Productos Terminados',
      table: 'envios',
      field: 'fecha',
      headers: ['Fecha', 'Cliente', 'Tipo', 'Detalle', 'Cantidad', 'Unidad'],
      widths: [80, 120, 80, 120, 60, 60],
      map: r => [
        formatPdfDateOnly(r.fecha),
        r.cliente,
        r.tipo,
        r.descripcion || '',
        r.cantidad,
        r.unidad || ''
      ]
    }
  ];

  let first = true;
  for (const s of sections) {
    const f = buildDateWhere({ field: s.field, from, to });
    const list = await db.all(
      `SELECT * FROM ${s.table} ${f.where} ORDER BY created_at DESC`,
      f.params
    );
    if (!first) {
      doc.addPage();
    } else {
      first = false;
    }

    doc
      .fontSize(13)
      .fillColor('#000000')
      .text(s.titulo, { align: 'left' })
      .moveDown(0.5);

    const rows = list.map(s.map);
    drawTable(doc, s.headers, s.widths, rows);
  }

  doc.end();
});

app.get('/api/registros.xlsx', requireAuth, async (req, res) => {
  const { from, to } = req.query || {};

  const def = [
    {
      sheet: 'Recepciones',
      table: 'recepciones',
      field: 'fecha',
      headers: ['Fecha', 'Tipo', 'Cantidad', 'Unidad'],
      map: r => [formatPdfDateTime(r.fecha), r.tipo, r.cantidad, r.unidad || '']
    },
    {
      sheet: 'Produccion',
      table: 'produccion',
      field: 'fecha_ini',
      headers: ['Fecha', 'Tipo de producto', 'Cantidad', 'Unidad'],
      map: r => [formatPdfDateTime(r.fecha_ini), r.tipo || '', r.cantidad, r.unidad || '']
    },
    {
      sheet: 'Defectuosos',
      table: 'defectuosos',
      field: 'fecha',
      headers: ['Fecha', 'Tipo', 'Cantidad', 'Unidad', 'Razón'],
      map: r => [formatPdfDateOnly(r.fecha), r.tipo, r.cantidad, r.unidad || '', r.razon || '']
    },
    {
      sheet: 'Envios',
      table: 'envios',
      field: 'fecha',
      headers: ['Fecha', 'Cliente', 'Tipo', 'Detalle', 'Cantidad', 'Unidad'],
      map: r => [
        formatPdfDateOnly(r.fecha),
        r.cliente,
        r.tipo,
        r.descripcion || '',
        r.cantidad,
        r.unidad || ''
      ]
    }
  ];

  const sheets = [];
  for (const s of def) {
    const f = buildDateWhere({ field: s.field, from, to });
    const list = await db.all(
      `SELECT * FROM ${s.table} ${f.where} ORDER BY created_at DESC`,
      f.params
    );
    const aoa = [s.headers, ...list.map(s.map)];
    sheets.push({ name: safeSheetName(s.sheet), aoa });
  }

  sendXlsx(res, 'registros_completos.xlsx', sheets);
});

// -----------------------------------------------------------------------------
// Users – gestión de roles y contraseñas
// -----------------------------------------------------------------------------
app.get('/api/users', requireRole('supervisor'), async (req, res) => {
  const u = await db.all("SELECT id,username,role FROM users ORDER BY username");
  res.json({ items: u });
});

app.post('/api/users', requireRole('supervisor'), async (req, res) => {
  const { username, password, role } = req.body || {};
  const uname = String(username || '').toLowerCase();
  if (!/^[a-z0-9._-]{3,32}$/.test(uname)) {
    return res.status(400).json({ error: 'invalid-username' });
  }
  if (!['operario', 'supervisor', 'administrador'].includes(role)) {
    return res.status(400).json({ error: 'invalid-role' });
  }
  const hp = await bcrypt.hash(String(password || 'admin'), 10);
  await db.run(
    "INSERT INTO users(username,password,role) VALUES(?,?,?)",
    [uname, hp, role]
  );
  res.json({ ok: true });
});

app.put('/api/users/:id', requireRole('supervisor'), async (req, res) => {
  const id = parseInt(req.params.id, 10);
  const { role } = req.body || {};
  if (!['operario', 'supervisor', 'administrador'].includes(role)) {
    return res.status(400).json({ error: 'invalid-role' });
  }
  await db.run("UPDATE users SET role=? WHERE id=?", [role, id]);
  res.json({ ok: true });
});

app.delete('/api/users/:id', requireRole('supervisor'), async (req, res) => {
  const id = parseInt(req.params.id, 10);
  await db.run("DELETE FROM users WHERE id=?", [id]);
  res.json({ ok: true });
});

app.patch('/api/users/:id/password', requireRole('supervisor'), async (req, res) => {
  const id = parseInt(req.params.id, 10);
  const { password } = req.body || {};
  const hp = await bcrypt.hash(String(password || 'admin'), 10);
  await db.run("UPDATE users SET password=? WHERE id=?", [hp, id]);
  res.json({ ok: true });
});

// -----------------------------------------------------------------------------
// Healthcheck simple
// -----------------------------------------------------------------------------
app.get('/healthz', (req, res) => res.json({ ok: true }));

// -----------------------------------------------------------------------------
// Manejador global de errores
// -----------------------------------------------------------------------------
app.use((err, req, res, next) => {
  console.error('Unhandled error', err);
  if (res.headersSent) {
    return next(err);
  }
  res.status(500).json({ error: 'internal-error' });
});

// -----------------------------------------------------------------------------
// Inicio del servidor
// -----------------------------------------------------------------------------
app.listen(PORT, () => {
  console.log(`Brumap running at http://localhost:${PORT} (NODE_ENV=${NODE_ENV})`);
});
