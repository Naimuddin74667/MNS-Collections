// MNS Collections — Inventory Manager API
// Cloudflare Worker + D1. Deployed by .github/workflows/deploy-inventory.yml
//
// All calls: https://<worker>/?action=<name>
//   GET  ?action=setupStatus           → { needsSetup }
//   POST ?action=setup                 → create first admin (only when no users exist)
//   POST ?action=login                 → { token, user }
// Everything else needs header:  Authorization: Bearer <token>
//
// Stock is never stored directly: it is the SUM of `delta` in the movements table.
//   stock-in (purchase)  → delta > 0
//   stock-out (sale etc) → delta < 0
//   adjust               → either sign (stock count corrections)

const SESSION_DAYS = 30;
const PBKDF2_ITERATIONS = 100000; // Workers' max for PBKDF2
const CHANNELS = ['Amazon', 'Flipkart', 'Instagram', 'WhatsApp', 'Offline', 'Damage', 'Other'];

// ---------- schema (auto-created on first request) ----------
let tablesReady = false;
async function ensureTables(db) {
  if (tablesReady) return;
  await db.batch([
    db.prepare(`CREATE TABLE IF NOT EXISTS users (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      username TEXT UNIQUE NOT NULL,
      pass_hash TEXT NOT NULL,
      salt TEXT NOT NULL,
      role TEXT NOT NULL DEFAULT 'staff',
      created_at TEXT NOT NULL DEFAULT (datetime('now')))`),
    db.prepare(`CREATE TABLE IF NOT EXISTS sessions (
      token TEXT PRIMARY KEY,
      user_id INTEGER NOT NULL,
      expires_at TEXT NOT NULL)`),
    db.prepare(`CREATE TABLE IF NOT EXISTS products (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      sku TEXT UNIQUE NOT NULL,
      name TEXT NOT NULL,
      category TEXT,
      image TEXT,
      cost_price REAL DEFAULT 0,
      sell_price REAL DEFAULT 0,
      mrp REAL DEFAULT 0,
      low_stock_at INTEGER DEFAULT 3,
      amazon_asin TEXT,
      flipkart_fsn TEXT,
      active INTEGER DEFAULT 1,
      created_at TEXT NOT NULL DEFAULT (datetime('now')),
      updated_at TEXT NOT NULL DEFAULT (datetime('now')))`),
    db.prepare(`CREATE TABLE IF NOT EXISTS movements (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      product_id INTEGER NOT NULL,
      type TEXT NOT NULL,
      delta INTEGER NOT NULL,
      channel TEXT,
      unit_price REAL DEFAULT 0,
      note TEXT,
      move_date TEXT NOT NULL,
      created_by TEXT,
      created_at TEXT NOT NULL DEFAULT (datetime('now')))`),
    db.prepare(`CREATE INDEX IF NOT EXISTS idx_mov_product ON movements(product_id)`),
    db.prepare(`CREATE INDEX IF NOT EXISTS idx_mov_date ON movements(move_date)`),
  ]);
  tablesReady = true;
}

// ---------- helpers ----------
const CORS = {
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
  'Access-Control-Allow-Headers': 'Content-Type, Authorization',
};
function json(data, status = 200) {
  return new Response(JSON.stringify(data), { status, headers: { 'Content-Type': 'application/json', ...CORS } });
}
function fail(message, status = 400) { return json({ ok: false, error: message }, status); }

function toHex(bytes) { return [...bytes].map(b => b.toString(16).padStart(2, '0')).join(''); }
function fromHex(hex) { return new Uint8Array(hex.match(/.{2}/g).map(h => parseInt(h, 16))); }

async function hashPassword(password, saltHex) {
  const salt = saltHex ? fromHex(saltHex) : crypto.getRandomValues(new Uint8Array(16));
  const key = await crypto.subtle.importKey('raw', new TextEncoder().encode(password), 'PBKDF2', false, ['deriveBits']);
  const bits = await crypto.subtle.deriveBits({ name: 'PBKDF2', hash: 'SHA-256', salt, iterations: PBKDF2_ITERATIONS }, key, 256);
  return { hash: toHex(new Uint8Array(bits)), salt: toHex(salt) };
}
// Compare without leaking timing info
function safeEqual(a, b) {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return diff === 0;
}
function cleanUsername(u) { return String(u || '').trim().toLowerCase(); }
function validCredentials(username, password) {
  if (!/^[a-z0-9._-]{3,30}$/.test(username)) return 'Username: 3–30 letters, numbers, . _ -';
  if (String(password || '').length < 8) return 'Password must be at least 8 characters';
  return null;
}
function num(v, def = 0) {
  if (v === null || v === undefined || v === '') return def;
  const n = Number(v);
  return Number.isFinite(n) ? n : def;
}
function text(v, max = 500) { return v == null ? null : String(v).trim().slice(0, max) || null; }
function today() { return new Date().toISOString().slice(0, 10); }

async function createSession(db, user) {
  const token = toHex(crypto.getRandomValues(new Uint8Array(32)));
  const expires = new Date(Date.now() + SESSION_DAYS * 864e5).toISOString();
  await db.prepare('INSERT INTO sessions (token, user_id, expires_at) VALUES (?, ?, ?)').bind(token, user.id, expires).run();
  // Housekeeping: drop expired sessions
  await db.prepare('DELETE FROM sessions WHERE expires_at < ?').bind(new Date().toISOString()).run();
  return token;
}

async function currentUser(db, request) {
  const auth = request.headers.get('Authorization') || '';
  const token = auth.startsWith('Bearer ') ? auth.slice(7) : '';
  if (!token) return null;
  return db.prepare(`SELECT u.id, u.username, u.role FROM sessions s JOIN users u ON u.id = s.user_id
                     WHERE s.token = ? AND s.expires_at > ?`).bind(token, new Date().toISOString()).first();
}

async function productStock(db, productId) {
  const r = await db.prepare('SELECT COALESCE(SUM(delta),0) AS stock FROM movements WHERE product_id = ?').bind(productId).first();
  return r.stock;
}

// ---------- public actions ----------
async function setupStatus(db) {
  const r = await db.prepare('SELECT COUNT(*) AS n FROM users').first();
  return json({ ok: true, needsSetup: r.n === 0 });
}

async function setup(db, body) {
  const r = await db.prepare('SELECT COUNT(*) AS n FROM users').first();
  if (r.n > 0) return fail('Setup already done — please log in', 403);
  const username = cleanUsername(body.username);
  const err = validCredentials(username, body.password);
  if (err) return fail(err);
  const { hash, salt } = await hashPassword(body.password);
  const res = await db.prepare("INSERT INTO users (username, pass_hash, salt, role) VALUES (?, ?, ?, 'admin')").bind(username, hash, salt).run();
  const user = { id: res.meta.last_row_id, username, role: 'admin' };
  return json({ ok: true, token: await createSession(db, user), user });
}

async function login(db, body) {
  const username = cleanUsername(body.username);
  const row = await db.prepare('SELECT * FROM users WHERE username = ?').bind(username).first();
  // Hash even when user is missing so response time doesn't reveal which usernames exist
  const { hash } = await hashPassword(String(body.password || ''), row ? row.salt : '00'.repeat(16));
  if (!row || !safeEqual(hash, row.pass_hash)) return fail('Wrong username or password', 401);
  const user = { id: row.id, username: row.username, role: row.role };
  return json({ ok: true, token: await createSession(db, user), user });
}

// ---------- authenticated actions ----------
async function listProducts(db) {
  const { results } = await db.prepare(`
    SELECT p.*, COALESCE(SUM(m.delta),0) AS stock
    FROM products p LEFT JOIN movements m ON m.product_id = p.id
    GROUP BY p.id ORDER BY p.active DESC, p.sku`).all();
  return json({ ok: true, products: results, channels: CHANNELS });
}

async function saveProduct(db, body) {
  const sku = text(body.sku, 60);
  const name = text(body.name, 200);
  if (!sku || !name) return fail('SKU and name are required');
  const fields = [sku.toUpperCase(), name, text(body.category, 60), body.image ? String(body.image).slice(0, 400000) : null,
    num(body.cost_price), num(body.sell_price), num(body.mrp), Math.max(0, Math.round(num(body.low_stock_at, 3))),
    text(body.amazon_asin, 20), text(body.flipkart_fsn, 30), body.active === 0 || body.active === false ? 0 : 1];
  try {
    if (body.id) {
      await db.prepare(`UPDATE products SET sku=?, name=?, category=?, image=?, cost_price=?, sell_price=?, mrp=?,
        low_stock_at=?, amazon_asin=?, flipkart_fsn=?, active=?, updated_at=datetime('now') WHERE id=?`).bind(...fields, body.id).run();
      return json({ ok: true, id: body.id });
    }
    const res = await db.prepare(`INSERT INTO products (sku, name, category, image, cost_price, sell_price, mrp,
      low_stock_at, amazon_asin, flipkart_fsn, active) VALUES (?,?,?,?,?,?,?,?,?,?,?)`).bind(...fields).run();
    const id = res.meta.last_row_id;
    // Optional opening stock when creating a product
    const opening = Math.round(num(body.opening_stock));
    if (opening > 0) {
      await db.prepare(`INSERT INTO movements (product_id, type, delta, unit_price, note, move_date, created_by)
        VALUES (?, 'in', ?, ?, 'Opening stock', ?, ?)`).bind(id, opening, num(body.cost_price), today(), body._user).run();
    }
    return json({ ok: true, id });
  } catch (e) {
    if (String(e).includes('UNIQUE')) return fail('This SKU already exists');
    throw e;
  }
}

async function deleteProduct(db, body) {
  const used = await db.prepare('SELECT COUNT(*) AS n FROM movements WHERE product_id = ?').bind(body.id).first();
  if (used.n > 0) return fail('This product has stock history — mark it inactive instead of deleting');
  await db.prepare('DELETE FROM products WHERE id = ?').bind(body.id).run();
  return json({ ok: true });
}

async function listMovements(db, url) {
  const productId = url.searchParams.get('product_id');
  const limit = Math.min(2000, Math.max(1, num(url.searchParams.get('limit'), 500)));
  const sql = `SELECT m.*, p.sku, p.name FROM movements m JOIN products p ON p.id = m.product_id
               ${productId ? 'WHERE m.product_id = ?' : ''} ORDER BY m.move_date DESC, m.id DESC LIMIT ?`;
  const stmt = productId ? db.prepare(sql).bind(productId, limit) : db.prepare(sql).bind(limit);
  const { results } = await stmt.all();
  return json({ ok: true, movements: results });
}

async function addMovement(db, body, user) {
  const product = await db.prepare('SELECT id, cost_price FROM products WHERE id = ?').bind(body.product_id).first();
  if (!product) return fail('Product not found');
  const type = body.type;
  const qty = Math.round(num(body.qty));
  if (!['in', 'out', 'adjust'].includes(type)) return fail('Type must be in, out or adjust');
  if (qty === 0 || (type !== 'adjust' && qty < 0)) return fail('Enter a valid quantity');

  let delta = type === 'out' ? -qty : qty;
  const stock = await productStock(db, product.id);
  if (stock + delta < 0) return fail(`Only ${stock} in stock — cannot go below zero`);

  const channel = type === 'out' ? (CHANNELS.includes(body.channel) ? body.channel : 'Other') : null;
  const unitPrice = type === 'in' ? num(body.unit_price, product.cost_price) : num(body.unit_price);
  const moveDate = /^\d{4}-\d{2}-\d{2}$/.test(body.move_date || '') ? body.move_date : today();

  await db.prepare(`INSERT INTO movements (product_id, type, delta, channel, unit_price, note, move_date, created_by)
    VALUES (?,?,?,?,?,?,?,?)`).bind(product.id, type, delta, channel, unitPrice, text(body.note), moveDate, user.username).run();
  // A purchase at a new price becomes the product's current cost price
  if (type === 'in' && body.update_cost && unitPrice > 0) {
    await db.prepare("UPDATE products SET cost_price=?, updated_at=datetime('now') WHERE id=?").bind(unitPrice, product.id).run();
  }
  return json({ ok: true, stock: stock + delta });
}

async function deleteMovement(db, body) {
  const m = await db.prepare('SELECT * FROM movements WHERE id = ?').bind(body.id).first();
  if (!m) return fail('Entry not found');
  const stock = await productStock(db, m.product_id);
  if (stock - m.delta < 0) return fail('Deleting this entry would make stock negative');
  await db.prepare('DELETE FROM movements WHERE id = ?').bind(body.id).run();
  return json({ ok: true });
}

async function listUsers(db) {
  const { results } = await db.prepare('SELECT id, username, role, created_at FROM users ORDER BY id').all();
  return json({ ok: true, users: results });
}

async function addUser(db, body) {
  const username = cleanUsername(body.username);
  const err = validCredentials(username, body.password);
  if (err) return fail(err);
  const role = body.role === 'admin' ? 'admin' : 'staff';
  const { hash, salt } = await hashPassword(body.password);
  try {
    await db.prepare('INSERT INTO users (username, pass_hash, salt, role) VALUES (?,?,?,?)').bind(username, hash, salt, role).run();
  } catch (e) {
    if (String(e).includes('UNIQUE')) return fail('Username already taken');
    throw e;
  }
  return json({ ok: true });
}

async function deleteUser(db, body, user) {
  if (Number(body.id) === user.id) return fail("You can't delete yourself");
  await db.batch([
    db.prepare('DELETE FROM sessions WHERE user_id = ?').bind(body.id),
    db.prepare('DELETE FROM users WHERE id = ?').bind(body.id),
  ]);
  return json({ ok: true });
}

async function changePassword(db, body, user) {
  const row = await db.prepare('SELECT * FROM users WHERE id = ?').bind(user.id).first();
  const { hash } = await hashPassword(String(body.old_password || ''), row.salt);
  if (!safeEqual(hash, row.pass_hash)) return fail('Current password is wrong', 401);
  const err = validCredentials(user.username, body.new_password);
  if (err) return fail(err);
  const next = await hashPassword(body.new_password);
  await db.prepare('UPDATE users SET pass_hash=?, salt=? WHERE id=?').bind(next.hash, next.salt, user.id).run();
  return json({ ok: true });
}

async function logout(db, request) {
  const token = (request.headers.get('Authorization') || '').slice(7);
  await db.prepare('DELETE FROM sessions WHERE token = ?').bind(token).run();
  return json({ ok: true });
}

// ---------- router ----------
export default {
  async fetch(request, env) {
    if (request.method === 'OPTIONS') return new Response(null, { headers: CORS });
    const url = new URL(request.url);
    const action = url.searchParams.get('action') || '';
    const db = env.DB;
    try {
      await ensureTables(db);
      const body = request.method === 'POST' ? await request.json().catch(() => ({})) : {};

      // Public
      if (action === 'setupStatus') return setupStatus(db);
      if (action === 'setup') return setup(db, body);
      if (action === 'login') return login(db, body);
      if (!action) return json({ ok: true, service: 'mns-inventory' });

      // Logged in
      const user = await currentUser(db, request);
      if (!user) return fail('Please log in again', 401);
      body._user = user.username;

      switch (action) {
        case 'me': return json({ ok: true, user });
        case 'logout': return logout(db, request);
        case 'listProducts': return listProducts(db);
        case 'saveProduct': return saveProduct(db, body);
        case 'deleteProduct': return deleteProduct(db, body);
        case 'listMovements': return listMovements(db, url);
        case 'addMovement': return addMovement(db, body, user);
        case 'deleteMovement': return deleteMovement(db, body);
        case 'changePassword': return changePassword(db, body, user);
      }

      // Admin only
      if (user.role !== 'admin') return fail('Admin only', 403);
      switch (action) {
        case 'listUsers': return listUsers(db);
        case 'addUser': return addUser(db, body);
        case 'deleteUser': return deleteUser(db, body, user);
      }
      return fail('Unknown action: ' + action, 404);
    } catch (e) {
      return fail('Server error: ' + (e.message || e), 500);
    }
  },
};
