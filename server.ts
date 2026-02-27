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
import mongoose from 'mongoose';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const app = express();
app.set('trust proxy', 1);
const PORT = 3000;

const MONGO_URI = process.env.MONGO_URI;
const INTERNAL_TOKEN = process.env.INTERNAL_SERVICE_TOKEN || "super_internal_token";

if (MONGO_URI) {
  mongoose.connect(MONGO_URI).then(() => {
    console.log("Connected to MongoDB");
  }).catch(err => {
    console.error("MongoDB connection error:", err.message);
  });
} else {
  console.log("MONGO_URI not provided, skipping MongoDB connection. Using SQLite fallback.");
}

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

// Ensure new columns exist for existing databases
try { db.exec("ALTER TABLE organizations ADD COLUMN rating REAL DEFAULT 4.5"); } catch (e) {}
try { db.exec("ALTER TABLE products ADD COLUMN stock INTEGER DEFAULT 10"); } catch (e) {}
try { db.exec("ALTER TABLE products ADD COLUMN description TEXT"); } catch (e) {}
try { db.exec("ALTER TABLE products ADD COLUMN specifications TEXT"); } catch (e) {}
try { db.exec("ALTER TABLE products ADD COLUMN images TEXT"); } catch (e) {}
try { db.exec("ALTER TABLE users ADD COLUMN is_active INTEGER DEFAULT 1"); } catch (e) {}

// Seed dummy details for existing products if they are empty
const productsWithoutDetails = db.prepare('SELECT id FROM products WHERE description IS NULL').all();
for (const p of (productsWithoutDetails as any[])) {
  db.prepare(`
    UPDATE products 
    SET description = 'High-quality medical equipment designed for professional healthcare environments. This product meets all international standards for safety and performance.',
        specifications = '{"Material": "Medical Grade Steel", "Warranty": "2 Years", "Origin": "India", "Certification": "ISO 9001"}',
        images = '["https://picsum.photos/seed/med1/800/800", "https://picsum.photos/seed/med2/800/800"]'
    WHERE id = ?
  `).run(p.id);
}

db.exec(`
  CREATE TABLE IF NOT EXISTS organizations (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    type TEXT NOT NULL,
    gstin TEXT,
    is_active BOOLEAN DEFAULT 1,
    kyc_status TEXT DEFAULT 'PENDING',
    rating REAL DEFAULT 4.5,
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
    stock INTEGER DEFAULT 10,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY(vendor_id) REFERENCES organizations(id)
  );

  CREATE TABLE IF NOT EXISTS product_reviews (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    product_id INTEGER NOT NULL,
    user_id INTEGER NOT NULL,
    rating INTEGER NOT NULL,
    comment TEXT,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY(product_id) REFERENCES products(id),
    FOREIGN KEY(user_id) REFERENCES users(id)
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
  res.json({ access_token: token, role: user.role, org_id: user.org_id, email: user.email });
});

authRouter.get('/me', authenticate, (req, res) => {
  const user: any = db.prepare('SELECT id, email, role, org_id, created_at FROM users WHERE id = ?').get((req as any).user.id);
  if (!user) return res.status(404).json({ error: 'User not found' });
  res.json(user);
});

authRouter.post('/change-password', authenticate, async (req, res) => {
  const { currentPassword, newPassword } = req.body;
  const userId = (req as any).user.id;
  const user: any = db.prepare('SELECT * FROM users WHERE id = ?').get(userId);
  
  if (!user || !bcrypt.compareSync(currentPassword, user.password)) {
    return res.status(401).json({ error: 'Invalid current password' });
  }

  const hashedPassword = await bcrypt.hash(newPassword, 10);
  db.prepare('UPDATE users SET password = ? WHERE id = ?').run(hashedPassword, userId);
  logAudit(userId, user.role, 'PASSWORD_CHANGED', 'USER', userId, req.ip || '');
  res.json({ success: true });
});

app.use('/api/auth', authRouter);

app.get('/api/status', (req, res) => {
  res.json({ service: 'AYUSHKENDRA', issuer: 'ALLIANCEVENTURES', auth: 'RS256', status: 'Active' });
});

app.get('/internal/metrics', async (req, res) => {
  const token = req.headers['x-service-token'];
  if (token !== INTERNAL_TOKEN)
    return res.status(403).json({ error: 'Forbidden' });

  res.json({
    totalOrders: 25000,
    gmv: 34000000,
    totalRevenue: 10000000
  });
});

app.get('/api/products', authenticate, (req, res) => {
  const products = db.prepare(`
    SELECT p.*, o.name as vendor_name, o.rating as vendor_rating 
    FROM products p 
    JOIN organizations o ON p.vendor_id = o.id
  `).all();
  res.json(products);
});

app.post('/api/products', authenticate, authorize(['SUPER_ADMIN', 'COMPANY_ADMIN', 'VENDOR_ADMIN']), (req, res) => {
  const { name, category, price, stock, description, specifications, images } = req.body;
  const vendor_id = (req as any).user.org_id;
  const info = db.prepare('INSERT INTO products (vendor_id, name, category, price, stock, description, specifications, images) VALUES (?, ?, ?, ?, ?, ?, ?, ?)')
    .run(vendor_id, name, category, price, stock || 10, description || null, specifications || null, images || null);
  logAudit((req as any).user.id, (req as any).user.role, 'PRODUCT_CREATED', 'PRODUCT', info.lastInsertRowid as number, req.ip || '');
  res.json({ id: info.lastInsertRowid });
});

app.delete('/api/products/:id', authenticate, authorize(['SUPER_ADMIN', 'VENDOR_ADMIN']), (req, res) => {
  const user = (req as any).user;
  const product: any = db.prepare('SELECT * FROM products WHERE id = ?').get(req.params.id);
  
  if (!product) return res.status(404).json({ error: 'Product not found' });

  // Ownership check for VENDOR_ADMIN
  if (user.role === 'VENDOR_ADMIN' && product.vendor_id !== user.org_id) {
    logAudit(user.id, user.role, 'UNAUTHORIZED_PRODUCT_DELETE_ATTEMPT', 'PRODUCT', Number(req.params.id), req.ip || '');
    return res.status(403).json({ error: 'Forbidden: You do not own this product' });
  }

  db.prepare('DELETE FROM products WHERE id = ?').run(req.params.id);
  logAudit(user.id, user.role, 'PRODUCT_DELETED', 'PRODUCT', Number(req.params.id), req.ip || '');
  res.json({ success: true });
});

app.put('/api/products/:id', authenticate, authorize(['SUPER_ADMIN', 'VENDOR_ADMIN']), (req, res) => {
  const user = (req as any).user;
  const { name, category, price, stock, description, specifications, images } = req.body;
  const product: any = db.prepare('SELECT * FROM products WHERE id = ?').get(req.params.id);
  
  if (!product) return res.status(404).json({ error: 'Product not found' });

  // Ownership check for VENDOR_ADMIN
  if (user.role === 'VENDOR_ADMIN' && product.vendor_id !== user.org_id) {
    logAudit(user.id, user.role, 'UNAUTHORIZED_PRODUCT_UPDATE_ATTEMPT', 'PRODUCT', Number(req.params.id), req.ip || '');
    return res.status(403).json({ error: 'Forbidden: You do not own this product' });
  }

  db.prepare('UPDATE products SET name = ?, category = ?, price = ?, stock = ?, description = ?, specifications = ?, images = ? WHERE id = ?')
    .run(name, category, price, stock, description || null, specifications || null, images || null, req.params.id);
    
  logAudit(user.id, user.role, 'PRODUCT_UPDATED', 'PRODUCT', Number(req.params.id), req.ip || '');
  res.json({ success: true });
});

app.get('/api/products/:id/reviews', authenticate, (req, res) => {
  const reviews = db.prepare(`
    SELECT r.*, u.email as user_email 
    FROM product_reviews r 
    JOIN users u ON r.user_id = u.id 
    WHERE r.product_id = ?
    ORDER BY r.created_at DESC
  `).all(req.params.id);
  res.json(reviews);
});

app.post('/api/products/:id/reviews', authenticate, (req, res) => {
  const { rating, comment } = req.body;
  const user_id = (req as any).user.id;
  const product_id = req.params.id;
  
  const info = db.prepare('INSERT INTO product_reviews (product_id, user_id, rating, comment) VALUES (?, ?, ?, ?)')
    .run(product_id, user_id, rating, comment);
    
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
  const user = (req as any).user;
  
  const order: any = db.prepare('SELECT * FROM orders WHERE id = ?').get(req.params.id);
  if (!order) return res.status(404).json({ error: 'Order not found' });

  // Ownership check for VENDOR_ADMIN
  if (user.role === 'VENDOR_ADMIN' && order.vendor_id !== user.org_id) {
    logAudit(user.id, user.role, 'UNAUTHORIZED_ORDER_UPDATE_ATTEMPT', 'ORDER', Number(req.params.id), req.ip || '');
    return res.status(403).json({ error: 'Forbidden: You do not own this order' });
  }

  db.prepare('UPDATE orders SET status = ? WHERE id = ?').run(status, req.params.id);
  logAudit(user.id, user.role, 'ORDER_STATUS_UPDATED', 'ORDER', Number(req.params.id), req.ip || '');
  res.json({ success: true });
});

app.get('/api/orders/invoice/:id', authenticate, (req, res) => {
  const user = (req as any).user;
  const order: any = db.prepare('SELECT * FROM orders WHERE id = ?').get(req.params.id);
  if (!order) return res.status(404).json({ error: 'Order not found' });
  
  // Access control: Only involved parties or admins
  const isAuthorized = 
    ['SUPER_ADMIN', 'COMPANY_ADMIN', 'GOVERNMENT_VIEW', 'ADMIN_VIEW'].includes(user.role) ||
    (user.role === 'VENDOR_ADMIN' && order.vendor_id === user.org_id) ||
    (user.role === 'FACILITY_ADMIN' && order.facility_id === user.org_id);

  if (!isAuthorized) {
    logAudit(user.id, user.role, 'UNAUTHORIZED_INVOICE_ACCESS', 'ORDER', Number(req.params.id), req.ip || '');
    return res.status(403).json({ error: 'Forbidden: Access denied' });
  }
  
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

app.get('/api/users', authenticate, authorize(['SUPER_ADMIN', 'COMPANY_ADMIN']), (req, res) => {
  const user = (req as any).user;
  let users;
  if (user.role === 'SUPER_ADMIN') {
    users = db.prepare(`
      SELECT u.id, u.email, u.role, u.is_active, u.created_at, o.name as org_name 
      FROM users u 
      LEFT JOIN organizations o ON u.org_id = o.id
    `).all();
  } else {
    users = db.prepare(`
      SELECT u.id, u.email, u.role, u.is_active, u.created_at, o.name as org_name 
      FROM users u 
      LEFT JOIN organizations o ON u.org_id = o.id
      WHERE u.org_id = ?
    `).all(user.org_id);
  }
  res.json(users);
});

app.post('/api/users', authenticate, authorize(['SUPER_ADMIN', 'COMPANY_ADMIN']), async (req, res) => {
  const { email, password, role, org_id } = req.body;
  const admin = (req as any).user;
  
  // Security check: COMPANY_ADMIN can only create users for their own org
  const targetOrgId = admin.role === 'SUPER_ADMIN' ? org_id : admin.org_id;
  
  const hashedPassword = await bcrypt.hash(password, 10);
  try {
    const info = db.prepare('INSERT INTO users (email, password, role, org_id) VALUES (?, ?, ?, ?)')
      .run(email, hashedPassword, role, targetOrgId);
    logAudit(admin.id, admin.role, 'USER_CREATED', 'USER', info.lastInsertRowid as number, req.ip || '');
    res.json({ id: info.lastInsertRowid });
  } catch (e: any) {
    res.status(400).json({ error: e.message });
  }
});

app.put('/api/users/:id/status', authenticate, authorize(['SUPER_ADMIN', 'COMPANY_ADMIN']), (req, res) => {
  const { is_active } = req.body;
  const admin = (req as any).user;
  const targetUser: any = db.prepare('SELECT * FROM users WHERE id = ?').get(req.params.id);
  
  if (!targetUser) return res.status(404).json({ error: 'User not found' });
  
  // Security check: COMPANY_ADMIN can only manage users in their org
  if (admin.role === 'COMPANY_ADMIN' && targetUser.org_id !== admin.org_id) {
    return res.status(403).json({ error: 'Forbidden' });
  }

  db.prepare('UPDATE users SET is_active = ? WHERE id = ?').run(is_active ? 1 : 0, req.params.id);
  logAudit(admin.id, admin.role, 'USER_STATUS_UPDATED', 'USER', Number(req.params.id), req.ip || '');
  res.json({ success: true });
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
