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

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const app = express();
const PORT = 3000;
const SECRET_KEY = process.env.SECRET_KEY || 'SOVEREIGN_SECRET_KEY';
const RAZORPAY_SECRET = process.env.RAZORPAY_SECRET || 'rzp_test_secret';

// ==========================================
// SECURITY & HARDENING (Enterprise Edition)
// ==========================================
app.use(helmet({
  contentSecurityPolicy: false, // Disabled for Vite dev server compatibility
}));
app.use(cors({ origin: process.env.NODE_ENV === 'production' ? process.env.APP_URL : '*' }));
app.use(express.json({ limit: '1mb' })); // Prevent large payload attacks

const apiLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 1000, // Limit each IP to 1000 requests per windowMs
  message: 'Too many requests from this IP, please try again later.'
});
app.use('/api/', apiLimiter);

// ==========================================
// DATABASE SETUP (Simulating Alembic & Postgres)
// ==========================================
const db = new Database('enterprise.db');
db.pragma('journal_mode = WAL'); // Optimized concurrent reads/writes
db.pragma('foreign_keys = ON');

// Migrations
db.exec(`
  CREATE TABLE IF NOT EXISTS organizations (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    type TEXT NOT NULL, -- HOSPITAL, VENDOR, GOVERNMENT, INVESTOR, INTERNAL
    gstin TEXT,
    is_active BOOLEAN DEFAULT 1,
    kyc_status TEXT DEFAULT 'PENDING', -- PENDING, VERIFIED, REJECTED
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
  );

  CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    org_id INTEGER,
    email TEXT UNIQUE NOT NULL,
    password TEXT NOT NULL,
    role TEXT NOT NULL, -- SUPER_ADMIN, COMPANY_ADMIN, VENDOR_ADMIN, FACILITY_ADMIN, GOVERNMENT_VIEW, INVESTOR_VIEW
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY(org_id) REFERENCES organizations(id)
  );

  CREATE TABLE IF NOT EXISTS products (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    vendor_id INTEGER NOT NULL,
    name TEXT NOT NULL,
    category TEXT NOT NULL,
    price REAL NOT NULL,
    is_active BOOLEAN DEFAULT 1,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY(vendor_id) REFERENCES organizations(id)
  );

  CREATE TABLE IF NOT EXISTS orders (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    facility_id INTEGER NOT NULL,
    vendor_id INTEGER NOT NULL,
    product_id INTEGER NOT NULL,
    status TEXT DEFAULT 'DRAFT', -- DRAFT, PENDING_PAYMENT, PAID, ADMIN_APPROVED, VENDOR_ASSIGNED, SHIPPED, DELIVERED, CLOSED, CANCELLED
    amount REAL NOT NULL,
    cgst REAL NOT NULL,
    sgst REAL NOT NULL,
    igst REAL NOT NULL,
    total REAL NOT NULL,
    razorpay_order_id TEXT,
    razorpay_payment_id TEXT,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY(facility_id) REFERENCES organizations(id),
    FOREIGN KEY(vendor_id) REFERENCES organizations(id),
    FOREIGN KEY(product_id) REFERENCES products(id)
  );

  CREATE TABLE IF NOT EXISTS shipments (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    order_id INTEGER NOT NULL,
    courier_name TEXT,
    tracking_number TEXT,
    status TEXT DEFAULT 'PENDING',
    delivered_at DATETIME,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY(order_id) REFERENCES orders(id)
  );

  CREATE TABLE IF NOT EXISTS invoices (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    order_id INTEGER NOT NULL UNIQUE,
    invoice_number TEXT NOT NULL UNIQUE,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY(order_id) REFERENCES orders(id)
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

  -- Indexes for PostgreSQL optimization simulation
  CREATE INDEX IF NOT EXISTS idx_users_org ON users(org_id);
  CREATE INDEX IF NOT EXISTS idx_products_vendor ON products(vendor_id);
  CREATE INDEX IF NOT EXISTS idx_orders_facility ON orders(facility_id);
  CREATE INDEX IF NOT EXISTS idx_orders_vendor ON orders(vendor_id);
  CREATE INDEX IF NOT EXISTS idx_audit_logs_actor ON audit_logs(actor_id);
`);

// Seed Initial Admin if not exists
const adminExists = db.prepare('SELECT * FROM users WHERE email = ?').get('admin@ayushkendra.com');
if (!adminExists) {
  const hash = bcrypt.hashSync('admin123', 10);
  const orgStmt = db.prepare("INSERT INTO organizations (name, type, kyc_status) VALUES ('AyushKendra HQ', 'INTERNAL', 'VERIFIED')");
  const orgInfo = orgStmt.run();
  db.prepare("INSERT INTO users (org_id, email, password, role) VALUES (?, ?, ?, 'SUPER_ADMIN')").run(orgInfo.lastInsertRowid, 'admin@ayushkendra.com', hash);
}

// ==========================================
// AUDIT LOGGING FUNCTION
// ==========================================
function logAudit(actor_id: number | null, role: string | null, action: string, object_type: string, object_id: number | null, ip_address: string) {
  db.prepare(`
    INSERT INTO audit_logs (actor_id, role, action, object_type, object_id, ip_address)
    VALUES (?, ?, ?, ?, ?, ?)
  `).run(actor_id, role, action, object_type, object_id, ip_address);
}

// ==========================================
// RBAC MIDDLEWARE
// ==========================================
const authenticate = (req: express.Request, res: express.Response, next: express.NextFunction) => {
  const token = req.headers.authorization?.split(' ')[1];
  if (!token) return res.status(401).json({ error: 'Unauthorized' });

  try {
    const decoded = jwt.verify(token, SECRET_KEY) as any;
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

// ==========================================
// MICROSERVICE: AUTH ENGINE
// ==========================================
const authRouter = express.Router();

authRouter.post('/register', (req, res) => {
  const { email, password, role, org_name, org_type, gstin } = req.body;
  
  if (!['VENDOR_ADMIN', 'FACILITY_ADMIN', 'GOVERNMENT_VIEW', 'INVESTOR_VIEW'].includes(role)) {
    return res.status(400).json({ error: 'Invalid role for registration' });
  }

  try {
    db.prepare('BEGIN').run();
    const orgStmt = db.prepare('INSERT INTO organizations (name, type, gstin) VALUES (?, ?, ?)');
    const orgInfo = orgStmt.run(org_name, org_type, gstin || null);
    
    const hash = bcrypt.hashSync(password, 10);
    const userStmt = db.prepare('INSERT INTO users (org_id, email, password, role) VALUES (?, ?, ?, ?)');
    const userInfo = userStmt.run(orgInfo.lastInsertRowid, email, hash, role);
    
    db.prepare('COMMIT').run();
    logAudit(userInfo.lastInsertRowid as number, role, 'REGISTER', 'USER', userInfo.lastInsertRowid as number, req.ip || '');
    
    const token = jwt.sign({ id: userInfo.lastInsertRowid, email, role, org_id: orgInfo.lastInsertRowid }, SECRET_KEY, { expiresIn: '24h' });
    res.json({ access_token: token, role, org_id: orgInfo.lastInsertRowid });
  } catch (err: any) {
    db.prepare('ROLLBACK').run();
    res.status(400).json({ error: err.message });
  }
});

authRouter.post('/login', (req, res) => {
  const { email, password } = req.body;
  const user = db.prepare('SELECT * FROM users WHERE email = ?').get(email) as any;
  
  if (!user || !bcrypt.compareSync(password, user.password)) {
    return res.status(401).json({ error: 'Invalid credentials' });
  }

  logAudit(user.id, user.role, 'LOGIN', 'USER', user.id, req.ip || '');
  const token = jwt.sign({ id: user.id, email: user.email, role: user.role, org_id: user.org_id }, SECRET_KEY, { expiresIn: '24h' });
  res.json({ access_token: token, role: user.role, org_id: user.org_id });
});

// ==========================================
// MICROSERVICE: PRODUCT CATALOGUE
// ==========================================
const productRouter = express.Router();

productRouter.get('/', authenticate, (req, res) => {
  const user = (req as any).user;
  let products;
  if (user.role === 'VENDOR_ADMIN') {
    products = db.prepare('SELECT * FROM products WHERE vendor_id = ? ORDER BY created_at DESC').all(user.org_id);
  } else {
    products = db.prepare('SELECT * FROM products WHERE is_active = 1 ORDER BY created_at DESC').all();
  }
  res.json(products);
});

productRouter.post('/', authenticate, authorize(['VENDOR_ADMIN', 'COMPANY_ADMIN', 'SUPER_ADMIN']), (req, res) => {
  const { name, category, price } = req.body;
  const user = (req as any).user;
  const vendor_id = user.role === 'VENDOR_ADMIN' ? user.org_id : req.body.vendor_id;
  
  const stmt = db.prepare('INSERT INTO products (vendor_id, name, category, price) VALUES (?, ?, ?, ?)');
  const info = stmt.run(vendor_id, name, category, price);
  
  logAudit(user.id, user.role, 'CREATE_PRODUCT', 'PRODUCT', info.lastInsertRowid as number, req.ip || '');
  res.json({ id: info.lastInsertRowid, name, category, price });
});

// ==========================================
// MICROSERVICE: ORDER ENGINE
// ==========================================
const orderRouter = express.Router();

orderRouter.get('/', authenticate, (req, res) => {
  const user = (req as any).user;
  let orders;
  
  if (user.role === 'FACILITY_ADMIN') {
    orders = db.prepare('SELECT * FROM orders WHERE facility_id = ? ORDER BY created_at DESC').all(user.org_id);
  } else if (user.role === 'VENDOR_ADMIN') {
    orders = db.prepare('SELECT * FROM orders WHERE vendor_id = ? ORDER BY created_at DESC').all(user.org_id);
  } else {
    orders = db.prepare('SELECT * FROM orders ORDER BY created_at DESC').all();
  }
  res.json(orders);
});

orderRouter.post('/', authenticate, authorize(['FACILITY_ADMIN']), (req, res) => {
  const { product_id, amount } = req.body;
  const user = (req as any).user;
  
  const product = db.prepare('SELECT * FROM products WHERE id = ?').get(product_id) as any;
  if (!product) return res.status(404).json({ error: 'Product not found' });

  const cgst = amount * 0.09;
  const sgst = amount * 0.09;
  const igst = 0; // Simplified for intra-state
  const total = amount + cgst + sgst + igst;

  const stmt = db.prepare(`
    INSERT INTO orders (facility_id, vendor_id, product_id, status, amount, cgst, sgst, igst, total)
    VALUES (?, ?, ?, 'PENDING_PAYMENT', ?, ?, ?, ?, ?)
  `);
  const info = stmt.run(user.org_id, product.vendor_id, product_id, amount, cgst, sgst, igst, total);
  
  logAudit(user.id, user.role, 'CREATE_ORDER', 'ORDER', info.lastInsertRowid as number, req.ip || '');
  
  // Mock Razorpay Order Creation
  const rzpOrderId = `order_rzp_${crypto.randomBytes(6).toString('hex')}`;
  db.prepare('UPDATE orders SET razorpay_order_id = ? WHERE id = ?').run(rzpOrderId, info.lastInsertRowid);

  res.json({ id: info.lastInsertRowid, razorpay_order_id: rzpOrderId, total });
});

orderRouter.post('/verify-payment', authenticate, authorize(['FACILITY_ADMIN']), (req, res) => {
  const { order_id, razorpay_payment_id } = req.body;
  const user = (req as any).user;
  
  // In production, verify signature here
  db.prepare('UPDATE orders SET status = ?, razorpay_payment_id = ? WHERE id = ? AND facility_id = ?')
    .run('PAID', razorpay_payment_id, order_id, user.org_id);
    
  // Generate Invoice
  const invoiceNumber = `INV-${new Date().getFullYear()}-${order_id.toString().padStart(5, '0')}`;
  db.prepare('INSERT OR IGNORE INTO invoices (order_id, invoice_number) VALUES (?, ?)')
    .run(order_id, invoiceNumber);

  logAudit(user.id, user.role, 'PAYMENT_VERIFIED', 'ORDER', order_id, req.ip || '');
  res.json({ success: true, status: 'PAID' });
});

orderRouter.put('/:id/status', authenticate, authorize(['SUPER_ADMIN', 'COMPANY_ADMIN', 'VENDOR_ADMIN']), (req, res) => {
  const { status } = req.body;
  const user = (req as any).user;
  const orderId = req.params.id;
  
  // State machine validation could be added here
  const stmt = db.prepare('UPDATE orders SET status = ? WHERE id = ?');
  stmt.run(status, orderId);
  
  logAudit(user.id, user.role, `UPDATE_STATUS_${status}`, 'ORDER', parseInt(orderId), req.ip || '');
  res.json({ success: true, status });
});

orderRouter.get('/invoice/:id', authenticate, (req, res) => {
  const user = (req as any).user;
  const order = db.prepare('SELECT * FROM orders WHERE id = ?').get(req.params.id) as any;
  if (!order) return res.status(404).json({ error: 'Order not found' });
  
  if (user.role === 'FACILITY_ADMIN' && order.facility_id !== user.org_id) return res.status(403).json({ error: 'Forbidden' });
  if (user.role === 'VENDOR_ADMIN' && order.vendor_id !== user.org_id) return res.status(403).json({ error: 'Forbidden' });

  const invoice = db.prepare('SELECT * FROM invoices WHERE order_id = ?').get(order.id) as any;
  const invoiceNum = invoice ? invoice.invoice_number : `DRAFT-${order.id}`;

  const doc = new PDFDocument();
  res.setHeader('Content-Type', 'application/pdf');
  res.setHeader('Content-Disposition', `attachment; filename=${invoiceNum}.pdf`);
  
  doc.pipe(res);
  doc.fontSize(20).text('AyushKendra GST Invoice', { align: 'center' });
  doc.moveDown();
  doc.fontSize(12).text(`Invoice Number: ${invoiceNum}`);
  doc.text(`Order ID: ${order.id}`);
  doc.text(`Status: ${order.status}`);
  doc.moveDown();
  doc.text(`Base Amount: ₹${order.amount.toFixed(2)}`);
  doc.text(`CGST (9%): ₹${order.cgst.toFixed(2)}`);
  doc.text(`SGST (9%): ₹${order.sgst.toFixed(2)}`);
  doc.text(`Total Amount: ₹${order.total.toFixed(2)}`);
  doc.moveDown();
  doc.text(`Generated on: ${new Date().toLocaleString()}`);
  doc.end();
  
  logAudit(user.id, user.role, 'DOWNLOAD_INVOICE', 'ORDER', order.id, req.ip || '');
});

// ==========================================
// MICROSERVICE: SHIPMENT ENGINE
// ==========================================
const shipmentRouter = express.Router();

shipmentRouter.post('/', authenticate, authorize(['VENDOR_ADMIN', 'COMPANY_ADMIN', 'SUPER_ADMIN']), (req, res) => {
  const { order_id, courier_name, tracking_number } = req.body;
  const user = (req as any).user;

  const stmt = db.prepare('INSERT INTO shipments (order_id, courier_name, tracking_number, status) VALUES (?, ?, ?, ?)');
  const info = stmt.run(order_id, courier_name, tracking_number, 'SHIPPED');
  
  db.prepare('UPDATE orders SET status = ? WHERE id = ?').run('SHIPPED', order_id);
  
  logAudit(user.id, user.role, 'CREATE_SHIPMENT', 'SHIPMENT', info.lastInsertRowid as number, req.ip || '');
  res.json({ id: info.lastInsertRowid, status: 'SHIPPED' });
});

// ==========================================
// MICROSERVICE: ANALYTICS ENGINE
// ==========================================
const analyticsRouter = express.Router();

analyticsRouter.get('/summary', authenticate, authorize(['SUPER_ADMIN', 'COMPANY_ADMIN', 'GOVERNMENT_VIEW', 'INVESTOR_VIEW']), (req, res) => {
  const totalOrders = (db.prepare('SELECT COUNT(*) as count FROM orders').get() as any).count;
  const totalRevenue = (db.prepare("SELECT SUM(total) as sum FROM orders WHERE status != 'DRAFT' AND status != 'CANCELLED'").get() as any).sum || 0;
  const totalGst = (db.prepare("SELECT SUM(cgst + sgst + igst) as sum FROM orders WHERE status != 'DRAFT' AND status != 'CANCELLED'").get() as any).sum || 0;
  
  const statusDist = db.prepare('SELECT status as name, COUNT(*) as value FROM orders GROUP BY status').all();
  
  res.json({
    total_orders: totalOrders,
    total_revenue: totalRevenue,
    gst_collected: totalGst,
    status_distribution: statusDist
  });
});

// ==========================================
// MICROSERVICE: AUDIT ENGINE
// ==========================================
const auditRouter = express.Router();

auditRouter.get('/', authenticate, authorize(['SUPER_ADMIN', 'GOVERNMENT_VIEW']), (req, res) => {
  const logs = db.prepare('SELECT * FROM audit_logs ORDER BY created_at DESC LIMIT 100').all();
  res.json(logs);
});

// Mount Microservices
app.use('/api/auth', authRouter);
app.use('/api/products', productRouter);
app.use('/api/orders', orderRouter);
app.use('/api/shipments', shipmentRouter);
app.use('/api/analytics', analyticsRouter);
app.use('/api/audit', auditRouter);

// Health Check
app.get('/api/health', (req, res) => {
  res.json({ status: 'ok', timestamp: new Date().toISOString() });
});

// API 404 Handler
app.use('/api/*', (req, res) => {
  res.status(404).json({ error: 'API route not found' });
});

// Global Error Handler
app.use((err: any, req: express.Request, res: express.Response, next: express.NextFunction) => {
  console.error('Unhandled Error:', err);
  if (req.path.startsWith('/api/')) {
    res.status(500).json({ error: 'Internal Server Error', message: err.message });
  } else {
    next(err);
  }
});

// ==========================================
// VITE SPA MIDDLEWARE (Development)
// ==========================================
async function startServer() {
  if (process.env.NODE_ENV !== 'production') {
    const vite = await createViteServer({
      server: { middlewareMode: true },
      appType: 'spa'
    });
    app.use(vite.middlewares);
  } else {
    app.use(express.static(path.join(__dirname, 'dist')));
    app.get('*', (req, res) => {
      res.sendFile(path.join(__dirname, 'dist', 'index.html'));
    });
  }

  app.listen(PORT, '0.0.0.0', () => {
    console.log(`Enterprise Server running on http://0.0.0.0:${PORT}`);
  });
}

startServer();
