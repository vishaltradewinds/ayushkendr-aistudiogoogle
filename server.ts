import express from 'express';
import { createServer as createViteServer } from 'vite';
import Database from 'better-sqlite3';
import path from 'path';
import { fileURLToPath } from 'url';
import jwt from 'jsonwebtoken';
import bcrypt from 'bcryptjs';
import PDFDocument from 'pdfkit';
import crypto from 'crypto';
import helmet from 'helmet';
import cors from 'cors';
import rateLimit from 'express-rate-limit';
import fs from 'fs';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const app = express();
app.set('trust proxy', 1);
const PORT = 3000;

// Generate RS256 keys if they don't exist
if (!fs.existsSync('private.pem') || !fs.existsSync('public.pem')) {
  const { publicKey, privateKey } = crypto.generateKeyPairSync('rsa', {
    modulusLength: 2048,
    publicKeyEncoding: { type: 'spki', format: 'pem' },
    privateKeyEncoding: { type: 'pkcs8', format: 'pem' }
  });
  fs.writeFileSync('public.pem', publicKey);
  fs.writeFileSync('private.pem', privateKey);
}

const publicKey = fs.readFileSync('public.pem', 'utf8');
const privateKey = fs.readFileSync('private.pem', 'utf8');

app.use(helmet({ contentSecurityPolicy: false }));
app.use(cors());
app.use(express.json({ limit: '1mb' }));

const apiLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 1000,
  message: 'Too many requests from this IP, please try again later.'
});
app.use('/api/', apiLimiter);

const db = new Database('enterprise.db');
db.pragma('journal_mode = WAL');
db.pragma('foreign_keys = ON');

db.exec(`
  CREATE TABLE IF NOT EXISTS organizations (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    type TEXT NOT NULL,
    gstin TEXT,
    is_active BOOLEAN DEFAULT 1,
    kyc_status TEXT DEFAULT 'PENDING',
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
  );

  CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    org_id INTEGER,
    email TEXT UNIQUE NOT NULL,
    password TEXT NOT NULL,
    role TEXT NOT NULL,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY(org_id) REFERENCES organizations(id)
  );

  CREATE TABLE IF NOT EXISTS products (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    vendor_id INTEGER NOT NULL,
    name TEXT NOT NULL,
    category TEXT NOT NULL,
    price REAL NOT NULL,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY(vendor_id) REFERENCES organizations(id)
  );

  CREATE TABLE IF NOT EXISTS orders (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    facility_id INTEGER NOT NULL,
    vendor_id INTEGER NOT NULL,
    product_id INTEGER NOT NULL,
    amount INTEGER NOT NULL,
    total REAL NOT NULL,
    cgst REAL NOT NULL,
    sgst REAL NOT NULL,
    igst REAL NOT NULL,
    status TEXT DEFAULT 'PENDING',
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY(facility_id) REFERENCES organizations(id),
    FOREIGN KEY(vendor_id) REFERENCES organizations(id),
    FOREIGN KEY(product_id) REFERENCES products(id)
  );

  CREATE TABLE IF NOT EXISTS audit_logs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    actor_id INTEGER,
    role TEXT,
    action TEXT NOT NULL,
    object_type TEXT NOT NULL,
    object_id INTEGER,
    ip_address TEXT,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
  );
`);

// Seed Admin
const adminExists = db.prepare('SELECT * FROM users WHERE email = ?').get('admin@ayushkendra.com');
if (!adminExists) {
  const hash = bcrypt.hashSync('admin123', 10);
  const orgInfo = db.prepare("INSERT INTO organizations (name, type, kyc_status) VALUES ('AyushKendra HQ', 'INTERNAL', 'VERIFIED')").run();
  db.prepare("INSERT INTO users (org_id, email, password, role) VALUES (?, ?, ?, 'SUPER_ADMIN')").run(orgInfo.lastInsertRowid, 'admin@ayushkendra.com', hash);
}

function logAudit(actor_id: number | null, role: string | null, action: string, object_type: string, object_id: number | null, ip_address: string) {
  db.prepare(`
    INSERT INTO audit_logs (actor_id, role, action, object_type, object_id, ip_address)
    VALUES (?, ?, ?, ?, ?, ?)
  `).run(actor_id, role, action, object_type, object_id, ip_address);
}

const authenticate = (req: express.Request, res: express.Response, next: express.NextFunction) => {
  const token = req.headers.authorization?.split(' ')[1];
  if (!token) return res.status(401).json({ error: 'Unauthorized' });

  try {
    const decoded = jwt.verify(token, publicKey, { algorithms: ['RS256'] }) as any;
    (req as any).user = decoded;
    next();
  } catch (err) {
    res.status(403).json({ error: 'Invalid token' });
  }
};

const authorize = (roles: string[]) => {
  return (req: express.Request, res: express.Response, next: express.NextFunction) => {
    const userRole = (req as any).user.role;
    if (!roles.includes(userRole)) {
      logAudit((req as any).user.id, userRole, 'UNAUTHORIZED_ACCESS_ATTEMPT', 'ROUTE', null, req.ip || '');
      return res.status(403).json({ error: 'Forbidden: Insufficient permissions' });
    }
    next();
  };
};

const authRouter = express.Router();

authRouter.post('/register', (req, res) => {
  const { email, password, role, org_name, org_type, gstin } = req.body;
  if (!['VENDOR_ADMIN', 'FACILITY_ADMIN', 'GOVERNMENT_VIEW', 'ADMIN_VIEW'].includes(role)) {
    return res.status(400).json({ error: 'Invalid role' });
  }
  try {
    db.prepare('BEGIN').run();
    const orgInfo = db.prepare('INSERT INTO organizations (name, type, gstin) VALUES (?, ?, ?)').run(org_name, org_type, gstin || null);
    const hash = bcrypt.hashSync(password, 10);
    const userInfo = db.prepare('INSERT INTO users (org_id, email, password, role) VALUES (?, ?, ?, ?)').run(orgInfo.lastInsertRowid, email, hash, role);
    db.prepare('COMMIT').run();
    
    const token = jwt.sign({ id: userInfo.lastInsertRowid, org_id: orgInfo.lastInsertRowid, email, role }, privateKey, { algorithm: 'RS256', expiresIn: '24h' });
    logAudit(userInfo.lastInsertRowid as number, role, 'USER_REGISTERED', 'USER', userInfo.lastInsertRowid as number, req.ip || '');
    res.json({ access_token: token, role, org_id: orgInfo.lastInsertRowid });
  } catch (err: any) {
    db.prepare('ROLLBACK').run();
    res.status(400).json({ error: err.message });
  }
});

authRouter.post('/login', (req, res) => {
  const { email, password } = req.body;
  const user: any = db.prepare('SELECT * FROM users WHERE email = ?').get(email);
  if (!user || !bcrypt.compareSync(password, user.password)) {
    return res.status(401).json({ error: 'Invalid credentials' });
  }
  const token = jwt.sign({ id: user.id, org_id: user.org_id, email: user.email, role: user.role }, privateKey, { algorithm: 'RS256', expiresIn: '24h' });
  logAudit(user.id, user.role, 'USER_LOGIN', 'USER', user.id, req.ip || '');
  res.json({ access_token: token, role: user.role, org_id: user.org_id });
});

app.use('/api/auth', authRouter);

app.get('/api/status', (req, res) => {
  res.json({ service: 'AYUSHKENDRA', issuer: 'ALLIANCEVENTURES', auth: 'RS256', status: 'Active' });
});

app.get('/api/products', authenticate, (req, res) => {
  const products = db.prepare('SELECT * FROM products').all();
  res.json(products);
});

app.post('/api/products', authenticate, authorize(['SUPER_ADMIN', 'COMPANY_ADMIN', 'VENDOR_ADMIN']), (req, res) => {
  const { name, category, price } = req.body;
  const vendor_id = (req as any).user.org_id;
  const info = db.prepare('INSERT INTO products (vendor_id, name, category, price) VALUES (?, ?, ?, ?)').run(vendor_id, name, category, price);
  logAudit((req as any).user.id, (req as any).user.role, 'PRODUCT_CREATED', 'PRODUCT', info.lastInsertRowid as number, req.ip || '');
  res.json({ id: info.lastInsertRowid });
});

app.get('/api/orders', authenticate, (req, res) => {
  const user = (req as any).user;
  let orders;
  if (['SUPER_ADMIN', 'COMPANY_ADMIN', 'GOVERNMENT_VIEW', 'ADMIN_VIEW'].includes(user.role)) {
    orders = db.prepare('SELECT * FROM orders ORDER BY created_at DESC').all();
  } else if (user.role === 'VENDOR_ADMIN') {
    orders = db.prepare('SELECT * FROM orders WHERE vendor_id = ? ORDER BY created_at DESC').all(user.org_id);
  } else {
    orders = db.prepare('SELECT * FROM orders WHERE facility_id = ? ORDER BY created_at DESC').all(user.org_id);
  }
  res.json(orders);
});

app.post('/api/orders', authenticate, authorize(['FACILITY_ADMIN', 'SUPER_ADMIN']), (req, res) => {
  const { product_id, amount } = req.body;
  const facility_id = (req as any).user.org_id;
  
  const product: any = db.prepare('SELECT * FROM products WHERE id = ?').get(product_id);
  if (!product) return res.status(404).json({ error: 'Product not found' });

  const baseTotal = product.price * amount;
  const cgst = baseTotal * 0.09;
  const sgst = baseTotal * 0.09;
  const igst = 0;
  const total = baseTotal + cgst + sgst + igst;

  const info = db.prepare(`
    INSERT INTO orders (facility_id, vendor_id, product_id, amount, total, cgst, sgst, igst)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?)
  `).run(facility_id, product.vendor_id, product_id, amount, total, cgst, sgst, igst);
  
  logAudit((req as any).user.id, (req as any).user.role, 'ORDER_CREATED', 'ORDER', info.lastInsertRowid as number, req.ip || '');
  res.json({ id: info.lastInsertRowid, total });
});

app.put('/api/orders/:id/status', authenticate, authorize(['SUPER_ADMIN', 'VENDOR_ADMIN']), (req, res) => {
  const { status } = req.body;
  db.prepare('UPDATE orders SET status = ? WHERE id = ?').run(status, req.params.id);
  logAudit((req as any).user.id, (req as any).user.role, 'ORDER_STATUS_UPDATED', 'ORDER', Number(req.params.id), req.ip || '');
  res.json({ success: true });
});

app.get('/api/orders/invoice/:id', authenticate, (req, res) => {
  const order: any = db.prepare('SELECT * FROM orders WHERE id = ?').get(req.params.id);
  if (!order) return res.status(404).json({ error: 'Order not found' });
  
  const doc = new PDFDocument();
  res.setHeader('Content-Type', 'application/pdf');
  res.setHeader('Content-Disposition', `attachment; filename=invoice_${order.id}.pdf`);
  doc.pipe(res);
  
  doc.fontSize(20).text('AyushKendra Invoice', { align: 'center' });
  doc.moveDown();
  doc.fontSize(12).text(`Order ID: ${order.id}`);
  doc.text(`Date: ${order.created_at}`);
  doc.text(`Status: ${order.status}`);
  doc.moveDown();
  doc.text(`Total Amount: Rs. ${order.total.toFixed(2)}`);
  doc.text(`CGST: Rs. ${order.cgst.toFixed(2)}`);
  doc.text(`SGST: Rs. ${order.sgst.toFixed(2)}`);
  
  doc.end();
});

app.get('/api/analytics/summary', authenticate, (req, res) => {
  const user = (req as any).user;
  let totalOrders, totalRevenue, totalGst, statusDist, revenueTrend;

  if (['SUPER_ADMIN', 'COMPANY_ADMIN', 'GOVERNMENT_VIEW', 'ADMIN_VIEW'].includes(user.role)) {
    totalOrders = (db.prepare('SELECT COUNT(*) as count FROM orders').get() as any).count;
    totalRevenue = (db.prepare("SELECT SUM(total) as sum FROM orders WHERE status != 'DRAFT' AND status != 'CANCELLED'").get() as any).sum || 0;
    totalGst = (db.prepare("SELECT SUM(cgst + sgst + igst) as sum FROM orders WHERE status != 'DRAFT' AND status != 'CANCELLED'").get() as any).sum || 0;
    statusDist = db.prepare('SELECT status as name, COUNT(*) as value FROM orders GROUP BY status').all();
    revenueTrend = db.prepare("SELECT date(created_at) as name, SUM(total) as revenue FROM orders GROUP BY date(created_at) ORDER BY date(created_at) DESC LIMIT 7").all().reverse();
  } else if (user.role === 'VENDOR_ADMIN') {
    totalOrders = (db.prepare('SELECT COUNT(*) as count FROM orders WHERE vendor_id = ?').get(user.org_id) as any).count;
    totalRevenue = (db.prepare("SELECT SUM(total) as sum FROM orders WHERE vendor_id = ? AND status != 'DRAFT' AND status != 'CANCELLED'").get(user.org_id) as any).sum || 0;
    totalGst = (db.prepare("SELECT SUM(cgst + sgst + igst) as sum FROM orders WHERE vendor_id = ? AND status != 'DRAFT' AND status != 'CANCELLED'").get(user.org_id) as any).sum || 0;
    statusDist = db.prepare('SELECT status as name, COUNT(*) as value FROM orders WHERE vendor_id = ? GROUP BY status').all(user.org_id);
    revenueTrend = db.prepare("SELECT date(created_at) as name, SUM(total) as revenue FROM orders WHERE vendor_id = ? GROUP BY date(created_at) ORDER BY date(created_at) DESC LIMIT 7").all(user.org_id).reverse();
  } else {
    totalOrders = (db.prepare('SELECT COUNT(*) as count FROM orders WHERE facility_id = ?').get(user.org_id) as any).count;
    totalRevenue = (db.prepare("SELECT SUM(total) as sum FROM orders WHERE facility_id = ? AND status != 'DRAFT' AND status != 'CANCELLED'").get(user.org_id) as any).sum || 0;
    totalGst = (db.prepare("SELECT SUM(cgst + sgst + igst) as sum FROM orders WHERE facility_id = ? AND status != 'DRAFT' AND status != 'CANCELLED'").get(user.org_id) as any).sum || 0;
    statusDist = db.prepare('SELECT status as name, COUNT(*) as value FROM orders WHERE facility_id = ? GROUP BY status').all(user.org_id);
    revenueTrend = db.prepare("SELECT date(created_at) as name, SUM(total) as revenue FROM orders WHERE facility_id = ? GROUP BY date(created_at) ORDER BY date(created_at) DESC LIMIT 7").all(user.org_id).reverse();
  }

  res.json({
    total_orders: totalOrders,
    total_revenue: totalRevenue,
    gst_collected: totalGst,
    status_distribution: statusDist,
    revenue_trend: revenueTrend
  });
});

app.get('/api/audit', authenticate, authorize(['SUPER_ADMIN', 'GOVERNMENT_VIEW']), (req, res) => {
  const logs = db.prepare('SELECT * FROM audit_logs ORDER BY created_at DESC LIMIT 100').all();
  res.json(logs);
});

async function startServer() {
  if (process.env.NODE_ENV !== 'production') {
    const vite = await createViteServer({
      server: { middlewareMode: true },
      appType: 'spa',
    });
    app.use(vite.middlewares);
  } else {
    app.use(express.static('dist'));
  }

  app.listen(PORT, '0.0.0.0', () => {
    console.log(`Server running on port ${PORT}`);
  });
}

startServer();
