import express from 'express';
import { createServer as createViteServer } from 'vite';
import Database from 'better-sqlite3';
import path from 'path';
import { fileURLToPath } from 'url';
import jwt from 'jsonwebtoken';
import bcrypt from 'bcryptjs';
import PDFDocument from 'pdfkit';
import fs from 'fs';
import crypto from 'crypto';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const app = express();
const PORT = 3000;
const SECRET_KEY = process.env.SECRET_KEY || 'SOVEREIGN_SECRET_KEY';
const RAZORPAY_SECRET = process.env.RAZORPAY_SECRET || 'rzp_test_secret';

// ==========================================
// SECURITY & HARDENING (Enterprise Edition)
// ==========================================
app.disable('x-powered-by');
app.use(express.json({ limit: '1mb' })); // Prevent large payload attacks

// ==========================================
// DATABASE SETUP (Simulating Alembic & Postgres)
// ==========================================
const db = new Database('enterprise.db');
db.pragma('journal_mode = WAL'); // Optimized concurrent reads/writes

// Migrations
db.exec(`
  CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    email TEXT UNIQUE,
    password TEXT,
    role TEXT,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
  );

  CREATE TABLE IF NOT EXISTS orders (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    product_id INTEGER,
    buyer_id INTEGER,
    status TEXT DEFAULT 'pending',
    amount REAL,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
  );

  CREATE TABLE IF NOT EXISTS products (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT,
    price REAL,
    category TEXT,
    vendor_id INTEGER,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
  );
`);

// Seed Initial Data
const userCount = db.prepare('SELECT COUNT(*) as c FROM users').get() as { c: number };
if (userCount.c === 0) {
  const hashedPassword = bcrypt.hashSync('password', 10);
  db.prepare('INSERT INTO users (email, password, role) VALUES (?, ?, ?)').run('admin@ayushkendra.com', hashedPassword, 'admin');
  db.prepare('INSERT INTO users (email, password, role) VALUES (?, ?, ?)').run('vendor@ayushkendra.com', hashedPassword, 'vendor');
}

const productCount = db.prepare('SELECT COUNT(*) as c FROM products').get() as { c: number };
if (productCount.c === 0) {
  const insertProduct = db.prepare('INSERT INTO products (name, price, category, vendor_id) VALUES (?, ?, ?, ?)');
  insertProduct.run('Digital BP Monitor', 2500, 'Medical Devices', 2);
  insertProduct.run('Panchakarma Therapy Table', 18000, 'AYUSH Infrastructure', 2);
  insertProduct.run('Surgical Instrument Kit', 12000, 'Medical Devices', 2);
}

// ==========================================
// MICROSERVICE: AUTH ENGINE
// ==========================================
const authRouter = express.Router();

authRouter.post('/register', (req, res) => {
  const { email, password, role } = req.body;
  const hashedPassword = bcrypt.hashSync(password, 10);
  try {
    const stmt = db.prepare('INSERT INTO users (email, password, role) VALUES (?, ?, ?)');
    stmt.run(email, hashedPassword, role);
    res.json({ message: 'User created' });
  } catch (e) {
    res.status(400).json({ error: 'User already exists' });
  }
});

authRouter.post('/login', (req, res) => {
  const { email, password } = req.body;
  const user = db.prepare('SELECT * FROM users WHERE email = ?').get(email) as any;
  if (!user || !bcrypt.compareSync(password, user.password)) {
    return res.status(401).json({ error: 'Invalid credentials' });
  }
  const token = jwt.sign({ sub: user.email, role: user.role, id: user.id }, SECRET_KEY, { expiresIn: '1h' });
  res.json({ access_token: token, role: user.role, email: user.email });
});

// ==========================================
// MICROSERVICE: PRODUCT ENGINE
// ==========================================
const productRouter = express.Router();

productRouter.get('/', (req, res) => {
  const products = db.prepare('SELECT * FROM products ORDER BY created_at DESC').all();
  res.json(products);
});

productRouter.post('/', (req, res) => {
  const { name, price, category, vendor_id } = req.body;
  const stmt = db.prepare('INSERT INTO products (name, price, category, vendor_id) VALUES (?, ?, ?, ?)');
  const info = stmt.run(name, price, category, vendor_id || 101);
  res.json({ id: info.lastInsertRowid, name, price, category });
});

// ==========================================
// MICROSERVICE: ORDER ENGINE
// ==========================================
const orderRouter = express.Router();

// READ ALL (PostgreSQL optimized query simulation)
orderRouter.get('/', (req, res) => {
  const orders = db.prepare(`
    SELECT 
      id, facility_id, vendor_id, status, total, 
      datetime(created_at, 'localtime') as created_at 
    FROM orders 
    ORDER BY created_at DESC
  `).all();
  res.json(orders);
});

// CREATE
orderRouter.post('/', (req, res) => {
  const { product_id, buyer_id, amount } = req.body;
  const stmt = db.prepare('INSERT INTO orders (product_id, buyer_id, amount, status) VALUES (?, ?, ?, ?)');
  const info = stmt.run(product_id, buyer_id, amount, 'pending');
  res.json({ order_id: info.lastInsertRowid, amount, status: 'pending' });
});

// RAZORPAY WEBHOOK
orderRouter.post('/razorpay/webhook', (req, res) => {
  const signature = req.headers['x-razorpay-signature'] as string;
  const body = JSON.stringify(req.body);
  
  const expectedSignature = crypto
    .createHmac('sha256', RAZORPAY_SECRET)
    .update(body)
    .digest('hex');

  if (expectedSignature !== signature) {
    return res.status(400).json({ status: 'Invalid signature' });
  }

  res.json({ status: 'Payment verified' });
});

// INVOICE ENGINE
orderRouter.get('/invoice/:id', (req, res) => {
  const order = db.prepare('SELECT * FROM orders WHERE id = ?').get(req.params.id) as any;
  if (!order) return res.status(404).json({ error: 'Order not found' });

  const doc = new PDFDocument();
  const filename = `invoice_${order.id}.pdf`;
  
  res.setHeader('Content-Type', 'application/pdf');
  res.setHeader('Content-Disposition', `attachment; filename=${filename}`);
  
  doc.pipe(res);
  doc.fontSize(25).text('AyushKendra GST Invoice', { align: 'center' });
  doc.moveDown();
  doc.fontSize(12).text(`Order ID: ${order.id}`);
  doc.text(`Amount: ₹${order.amount}`);
  doc.text(`GST (18%): ₹${(order.amount * 0.18).toFixed(2)}`);
  doc.text(`Total: ₹${(order.amount * 1.18).toFixed(2)}`);
  doc.moveDown();
  doc.text(`Generated on: ${new Date().toLocaleString()}`);
  doc.end();
});

// UPDATE
orderRouter.put('/:id', (req, res) => {
  const { status } = req.body;
  const stmt = db.prepare('UPDATE orders SET status = ? WHERE id = ?');
  stmt.run(status, req.params.id);
  res.json({ success: true, id: req.params.id, status });
});

// DELETE
orderRouter.delete('/:id', (req, res) => {
  const stmt = db.prepare('DELETE FROM orders WHERE id = ?');
  stmt.run(req.params.id);
  res.json({ success: true, deleted_id: req.params.id });
});

// ==========================================
// MICROSERVICE: ANALYTICS ENGINE
// ==========================================
const analyticsRouter = express.Router();

analyticsRouter.get('/', (req, res) => {
  const totalOrders = (db.prepare('SELECT COUNT(*) as count FROM orders').get() as any).count;
  const totalRevenue = (db.prepare("SELECT SUM(total) as sum FROM orders WHERE status != 'DRAFT'").get() as any).sum || 0;
  
  const statusDist = db.prepare('SELECT status as name, COUNT(*) as value FROM orders GROUP BY status').all();
  
  // Mock time-series data for charts
  const revenueTrend = [
    { name: 'Mon', revenue: 12000 },
    { name: 'Tue', revenue: 19000 },
    { name: 'Wed', revenue: 15000 },
    { name: 'Thu', revenue: 22000 },
    { name: 'Fri', revenue: 28000 },
    { name: 'Sat', revenue: 34000 },
    { name: 'Sun', revenue: totalRevenue },
  ];

  res.json({
    total_orders: totalOrders,
    total_revenue: totalRevenue,
    gst_collected: totalRevenue * 0.18,
    status_distribution: statusDist,
    revenue_trend: revenueTrend
  });
});

// Mount Microservices
app.use('/api/auth', authRouter);
app.use('/api/products', productRouter);
app.use('/api/orders', orderRouter);
app.use('/api/analytics', analyticsRouter);

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
// VITE INTEGRATION & SERVER START
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
      if (!req.path.startsWith('/api/')) {
        res.sendFile(path.join(__dirname, 'dist', 'index.html'));
      }
    });
  }

  app.listen(PORT, '0.0.0.0', () => {
    console.log(`AyushKendra Enterprise Server running on port ${PORT}`);
  });
}

startServer();
