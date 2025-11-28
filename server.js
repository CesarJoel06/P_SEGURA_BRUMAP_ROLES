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

// OWASP A05 – Configuración centralizada de entorno para evitar errores de configuración
dotenv.config();

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const app = express();
const PORT = process.env.PORT || 3000;
const COOKIE_SECURE = process.env.COOKIE_SECURE === '1';
const NODE_ENV = process.env.NODE_ENV || 'development';
const IS_PROD = NODE_ENV === 'production';

// OWASP A05 – Uso de rutas internas controladas para datos, sin entrada del usuario
const DATA_DIR = path.join(__dirname, 'data');
if (!fs.existsSync(DATA_DIR)) {
  fs.mkdirSync(DATA_DIR, { recursive: true });
}

// OWASP A03 – Configuración de base de datos para usar siempre consultas parametrizadas
const db = await open({
  filename: path.join(DATA_DIR, 'brumap.db'),
  driver: sqlite3.Database
});

// OWASP A03 – Definición de esquema; todas las operaciones posteriores usan parámetros en SQL
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

// OWASP A03 – Migraciones controladas: solo se alteran tablas conocidas sin datos del usuario en el SQL
async function ensureColumn(table, column, typeDef) {
  const info = await db.all(`PRAGMA table_info(${table})`);
  if (!info.some(c => c.name === column)) {
    await db.exec(`ALTER TABLE ${table} ADD COLUMN ${column} ${typeDef}`);
  }
}

await ensureColumn('recepciones', 'unidad', 'TEXT');
await ensureColumn('produccion',  'tipo',   'TEXT');
await ensureColumn('produccion',  'unidad', 'TEXT');
await ensureColumn('defectuosos', 'unidad', 'TEXT');
await ensureColumn('envios',      'unidad', 'TEXT');

// OWASP A02/A07 – Credenciales hash con bcrypt y roles definidos para control de acceso
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
  const time = timeRaw.slice(0, 5);
  return `${date} ${time}`;
}

// OWASP A05 – Ocultar tecnología usada en la cabecera HTTP
app.disable('x-powered-by');

// OWASP A05 – Cabeceras de seguridad (CSP, referrerPolicy) para reducir XSS, clickjacking y fugas de info
// OWASP A05 – Cabeceras de seguridad (CSP, referrerPolicy) para reducir XSS, clickjacking y fugas de info
// Ajustado para que el navegador NO fuerce HTTP→HTTPS (upgrade-insecure-requests)
// y para permitir estilos inline básicos si los hubiera.
app.use(helmet({
  contentSecurityPolicy: {
    useDefaults: true,
    directives: {
      "default-src": ["'self'"],
      "script-src": ["'self'"],
      "img-src": ["'self'", "data:"],
      "style-src": ["'self'", "'unsafe-inline'"],
      "object-src": ["'none'"],
      "frame-ancestors": ["'none'"],
      "base-uri": ["'self'"],
      "form-action": ["'self'"],
      // Desactivar upgrade-insecure-requests que Helmet pone por defecto con useDefaults
      "upgrade-insecure-requests": null
    }
  },
  referrerPolicy: { policy: "no-referrer" }
}));


app.use(compression());

// OWASP A05 – Limitación del tamaño de la petición para reducir impacto de ataques DoS
app.use(express.json({ limit: "100kb" }));
app.use(express.urlencoded({ extended: false, limit: "100kb" }));

app.use(cookieParser());

// OWASP A07 – Uso de secreto de sesión; advertencia si falta en producción
const SESSION_SECRET = process.env.SESSION_SECRET;
if (!SESSION_SECRET && IS_PROD) {
  console.warn(
    '[WARN] SESSION_SECRET no está definido en producción. ' +
    'Define una variable de entorno segura para evitar secretos débiles.'
  );
}

// OWASP A07 – Configuración segura de sesión (cookies httpOnly, sameSite, secure, expiración)
app.use(session({
  name: 'brumap.sid',
  secret: SESSION_SECRET || 'dev_secret_change_me',
  resave: false,
  saveUninitialized: false,
  cookie: {
    httpOnly: true,
    sameSite: 'lax',
    secure: COOKIE_SECURE,
    maxAge: 1000 * 60 * 60 * 8
  }
}));

// OWASP A07 – Rate limiting para mitigar fuerza bruta y abusos de la API
const apiLimiter = rateLimit({
  windowMs: 60 * 1000,
  max: 200,
  standardHeaders: true,
  legacyHeaders: false
});
app.use('/api/', apiLimiter);

// OWASP A07 – Rate limiting específico en rutas de autenticación para frenar ataques de contraseña
const loginLimiter = rateLimit({
  windowMs: 60 * 1000,
  max: 20,
  standardHeaders: true,
  legacyHeaders: false
});
app.use(['/api/auth/login', '/login'], loginLimiter);

// OWASP A05/A01 – Generación de token CSRF por sesión para peticiones de cambio de estado
function ensureCsrf(req, res, next) {
  if (!req.session.csrf) {
    req.session.csrf =
      Math.random().toString(36).slice(2) +
      Math.random().toString(36).slice(2);
  }
  next();
}

// OWASP A05/A01 – Validación de token CSRF en métodos POST/PUT/PATCH/DELETE (excepto login)
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

const PUBLIC_DIR = path.join(__dirname, 'public');
const LOGO_PATH = path.join(PUBLIC_DIR, 'assets', 'img', 'logo.png');

// OWASP A05 – Servir estáticos con cache-control apropiado para HTML y assets
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

// OWASP A01/A04 – Funciones de ayuda para control de acceso por sesión y por rol en el backend
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

// OWASP A07 – Registro de intentos de login y bloqueo progresivo en tabla login_lock
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

// OWASP A07 – Proceso de autenticación con bcrypt, bloqueo por intentos fallidos y errores genéricos
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

// OWASP A07 – Logout destruye la sesión en el servidor
app.post('/api/auth/logout', requireAuth, (req, res) => {
  req.session.destroy(() => res.json({ ok: true }));
});

app.get('/me', (req, res) => {
  res.json({ user: req.session.user || null });
});

// OWASP A01/A03 – Endpoints de recepciones protegidos por sesión/rol y SQL parametrizado
app.get('/api/recepciones', requireAuth, async (req, res) => {
  const list = await db.all("SELECT * FROM recepciones ORDER BY created_at DESC");
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

// OWASP A01/A03 – Endpoints de producción con control de rol y validación de entrada
app.get('/api/produccion', requireAuth, async (req, res) => {
  const list = await db.all("SELECT * FROM produccion ORDER BY created_at DESC");
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

// OWASP A01/A03 – Endpoints de defectuosos con validación de datos y SQL seguro
app.get('/api/defectuosos', requireAuth, async (req, res) => {
  const list = await db.all("SELECT * FROM defectuosos ORDER BY created_at DESC");
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

// OWASP A01/A03 – Endpoints de envíos: control de rol, validación de entradas y SQL parametrizado
app.get('/api/envios', requireAuth, async (req, res) => {
  const list = await db.all("SELECT * FROM envios ORDER BY created_at DESC");
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

function formatPdfDateOnly(s) {
  if (!s) return '';
  const d = new Date(s);
  if (!isNaN(d.getTime())) {
    const dd = String(d.getDate()).padStart(2, '0');
    const mm = String(d.getMonth() + 1).padStart(2, '0');
    const yy = d.getFullYear();
    return `${dd}-${mm}-${yy}`;
  }
  return formatDateYmdToDmy(s);
}

function formatPdfDateTime(s) {
  if (!s) return '';
  const d = new Date(s);
  if (!isNaN(d.getTime())) {
    const dd = String(d.getDate()).padStart(2, '0');
    const mm = String(d.getMonth() + 1).padStart(2, '0');
    const yy = d.getFullYear();
    const hh = String(d.getHours()).padStart(2, '0');
    const mi = String(d.getMinutes()).padStart(2, '0');
    if (hh === '00' && mi === '00') return `${dd}-${mm}-${yy}`;
    return `${dd}-${mm}-${yy} ${hh}:${mi}`;
  }
  return formatDateTimeYmdToDmy(s);
}

// OWASP A05 – Generación de PDFs usando solo recursos locales (logo) y sin cargar contenido remoto
function startPdf(res, filename, title) {
  res.setHeader('Content-Type', 'application/pdf');
  res.setHeader('Content-Disposition', `attachment; filename="${filename}"`);

  const doc = new PDFDocument({ size: 'A4', margin: 36 });
  doc.pipe(res);

  try {
    if (fs.existsSync(LOGO_PATH)) {
      doc.image(LOGO_PATH, 36, 24, { fit: [60, 60] });
    }
  } catch (e) {}

  doc
    .fillColor('#ff8c1a')
    .fontSize(22)
    .text('BRUMAP', 110, 32);

  doc
    .moveDown()
    .fillColor('#000000')
    .fontSize(14)
    .text(title, { align: 'center' });

  const nowStr = new Date().toLocaleString('es-PE');
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
  const rowHeight = 18;
  const bottomLimit = doc.page.height - doc.page.margins.bottom - rowHeight * 2;

  let y = doc.y;

  function drawHeader() {
    doc
      .save()
      .fillColor('#ff8c1a')
      .rect(marginX, y, tableWidth, rowHeight)
      .fill();

    doc.fillColor('#181818').fontSize(10);
    let x = marginX + 4;
    headers.forEach((h, i) => {
      doc.text(String(h), x, y + 4, {
        width: widths[i] - 8
      });
      x += widths[i];
    });
    doc.restore();
    y += rowHeight;
  }

  drawHeader();
  doc.fontSize(10).fillColor('#000000');

  rowValues.forEach(cols => {
    if (y > bottomLimit) {
      doc.addPage();
      y = doc.page.margins.top;
      drawHeader();
      doc.fontSize(10).fillColor('#000000');
    }

    let x = marginX + 4;
    cols.forEach((val, i) => {
      doc.text(String(val ?? ''), x, y + 4, {
        width: widths[i] - 8
      });
      x += widths[i];
    });

    doc
      .moveTo(marginX, y + rowHeight - 1)
      .lineTo(marginX + tableWidth, y + rowHeight - 1)
      .strokeColor('#3a3d44')
      .lineWidth(0.5)
      .stroke();

    y += rowHeight;
  });

  doc.moveDown();
  doc.y = y + 4;
}

// OWASP A01/A03 – Exportar datos a PDF desde consultas parametrizadas ya validadas
app.get('/api/recepciones.pdf', requireAuth, async (req, res) => {
  const list = await db.all("SELECT * FROM recepciones ORDER BY created_at DESC");
  const doc = startPdf(res, 'recepciones.pdf', 'Recepción de Materiales');

  const headers = ['Fecha', 'Tipo', 'Cantidad', 'Unidad'];
  const widths = [100, 210, 80, 60];

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
  const list = await db.all("SELECT * FROM produccion ORDER BY created_at DESC");
  const doc = startPdf(res, 'produccion.pdf', 'Producción de Productos');

  const headers = ['Fecha', 'Tipo de producto', 'Cantidad', 'Unidad'];
  const widths = [100, 210, 80, 60];

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
  const list = await db.all("SELECT * FROM defectuosos ORDER BY created_at DESC");
  const doc = startPdf(res, 'defectuosos.pdf', 'Manejo de Material Defectuoso');

  const headers = ['Fecha', 'Tipo', 'Cantidad', 'Unidad', 'Razón'];
  const widths = [80, 130, 60, 60, 140];

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
  const list = await db.all("SELECT * FROM envios ORDER BY created_at DESC");
  const doc = startPdf(res, 'envios.pdf', 'Envío de Productos Terminados');

  const headers = ['Fecha', 'Cliente', 'Tipo', 'Detalle', 'Cantidad', 'Unidad'];
  const widths = [80, 120, 80, 120, 60, 60];

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

app.get('/api/registros.pdf', requireAuth, async (req, res) => {
  const doc = startPdf(res, 'registros_completos.pdf', 'Registro Completo de Operaciones');

  const sections = [
    {
      titulo: 'Recepción de Materiales',
      query: 'SELECT * FROM recepciones ORDER BY created_at DESC',
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
      titulo: 'Producción de Productos',
      query: 'SELECT * FROM produccion ORDER BY created_at DESC',
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
      query: 'SELECT * FROM defectuosos ORDER BY created_at DESC',
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
      query: 'SELECT * FROM envios ORDER BY created_at DESC',
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
    const list = await db.all(s.query);
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

// OWASP A01/A07 – Gestión de usuarios y roles restringida a supervisor, con contraseñas hash
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

// OWASP A05 – Healthcheck simple sin exponer información sensible de la aplicación
app.get('/healthz', (req, res) => res.json({ ok: true }));

// OWASP A09 – Manejador global de errores: log en servidor y respuesta genérica al cliente
app.use((err, req, res, next) => {
  console.error('Unhandled error', err);
  if (res.headersSent) {
    return next(err);
  }
  res.status(500).json({ error: 'internal-error' });
});

app.listen(PORT, () => {
  console.log(`BRUMAP v7-reloaded running at http://localhost:${PORT} (NODE_ENV=${NODE_ENV})`);
});
