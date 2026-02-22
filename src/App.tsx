import { Activity, LayoutDashboard, ShoppingCart, Users, Settings, ShieldCheck, Package, IndianRupee, TrendingUp, RefreshCw, Trash2, CheckCircle2, FileText } from 'lucide-react';
import { motion } from 'motion/react';
import React, { useEffect, useState } from 'react';
import { BarChart, Bar, XAxis, YAxis, CartesianGrid, Tooltip, Legend, ResponsiveContainer, PieChart, Pie, Cell } from 'recharts';
import { clsx, type ClassValue } from 'clsx';
import { twMerge } from 'tailwind-merge';

// Utility for tailwind classes
function cn(...inputs: ClassValue[]) {
  return twMerge(clsx(inputs));
}

// Types
interface Product {
  id: number;
  name: string;
  price: number;
  category: string;
  vendor_id: number;
}

interface AnalyticsData {
  total_orders: number;
  total_revenue: number;
  gst_collected: number;
  status_distribution: { name: string; value: number }[];
  revenue_trend: { name: string; revenue: number }[];
}

interface Order {
  id: number;
  facility_id: number;
  vendor_id: number;
  status: string;
  total: number;
  created_at: string;
}

const COLORS = ['#10b981', '#3b82f6', '#f59e0b', '#ef4444', '#6366f1'];

export default function App() {
  const [activeTab, setActiveTab] = useState('home');
  const [analytics, setAnalytics] = useState<AnalyticsData | null>(null);
  const [orders, setOrders] = useState<Order[]>([]);
  const [products, setProducts] = useState<Product[]>([]);
  const [loading, setLoading] = useState(true);
  const [search, setSearch] = useState('');
  const [user, setUser] = useState<{ email: string; role: string; token: string } | null>(() => {
    const saved = localStorage.getItem('ayush_user');
    return saved ? JSON.parse(saved) : null;
  });
  const [authMode, setAuthMode] = useState<'login' | 'register'>('login');

  const fetchData = async () => {
    setLoading(true);
    try {
      const [analyticsRes, ordersRes, productsRes] = await Promise.all([
        fetch('/api/analytics'),
        fetch('/api/orders'),
        fetch('/api/products')
      ]);
      const analyticsData = await analyticsRes.json();
      const ordersData = await ordersRes.json();
      const productsData = await productsRes.json();
      
      setAnalytics(analyticsData);
      setOrders(ordersData);
      setProducts(productsData);
    } catch (error) {
      console.error('Failed to fetch data:', error);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchData();
  }, []);

  const handleAuth = async (e: React.FormEvent<HTMLFormElement>) => {
    e.preventDefault();
    const formData = new FormData(e.currentTarget);
    const email = formData.get('email');
    const password = formData.get('password');
    const role = formData.get('role') || 'buyer';

    const endpoint = authMode === 'login' ? '/api/auth/login' : '/api/auth/register';
    const res = await fetch(endpoint, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ email, password, role })
    });

    const data = await res.json();
    if (res.ok) {
      if (authMode === 'login') {
        const userData = { email: data.email, role: data.role, token: data.access_token };
        setUser(userData);
        localStorage.setItem('ayush_user', JSON.stringify(userData));
      } else {
        alert('Registration successful! Please login.');
        setAuthMode('login');
      }
    } else {
      alert(data.error || 'Auth failed');
    }
  };

  const logout = () => {
    setUser(null);
    localStorage.removeItem('ayush_user');
  };

  const updateOrderStatus = async (id: number, status: string) => {
    await fetch(`/api/orders/${id}`, {
      method: 'PUT',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ status })
    });
    fetchData();
  };

  const deleteOrder = async (id: number) => {
    if (!confirm('Are you sure you want to delete this order?')) return;
    await fetch(`/api/orders/${id}`, { method: 'DELETE' });
    fetchData();
  };

  const createMockOrder = async () => {
    await fetch(`/api/orders`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        product_id: 1,
        buyer_id: user?.email || 'guest',
        amount: Math.floor(Math.random() * 50000) + 1000
      })
    });
    fetchData();
  };

  const handleVendorSubmit = async (e: React.FormEvent<HTMLFormElement>) => {
    e.preventDefault();
    const formData = new FormData(e.currentTarget);
    const name = formData.get('name') as string;
    const price = parseFloat(formData.get('price') as string);
    const category = formData.get('category') as string;

    await fetch('/api/products', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ name, price, category })
    });
    alert('Product submitted successfully!');
    fetchData();
    e.currentTarget.reset();
  };

  const payNow = async (product: Product) => {
    // Create order first
    const orderRes = await fetch('/api/orders', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        product_id: product.id,
        buyer_id: user?.email || 'guest',
        amount: product.price
      })
    });
    const orderData = await orderRes.json();

    // @ts-ignore
    const options = {
      key: "rzp_test_YourKeyHere",
      amount: product.price * 100,
      currency: "INR",
      name: "AyushKendra",
      description: `Payment for ${product.name}`,
      handler: async function (response: any) {
        alert("Payment Successful: " + response.razorpay_payment_id);
        // Update order status to PAID
        await updateOrderStatus(orderData.order_id, 'PAID');
      },
      theme: { color: "#1e3a8a" }
    };
    // @ts-ignore
    const rzp = new window.Razorpay(options);
    rzp.open();
  };

  const downloadInvoice = (orderId: number) => {
    window.open(`/api/orders/invoice/${orderId}`, '_blank');
  };

  const filteredProducts = products.filter(p => 
    p.name.toLowerCase().includes(search.toLowerCase()) ||
    p.category.toLowerCase().includes(search.toLowerCase())
  );

  if (!user) {
    return (
      <div className="min-h-screen bg-slate-900 flex items-center justify-center p-6">
        <motion.div 
          initial={{ opacity: 0, scale: 0.95 }}
          animate={{ opacity: 1, scale: 1 }}
          className="bg-white w-full max-w-md p-10 rounded-3xl shadow-2xl"
        >
          <div className="flex flex-col items-center mb-10">
            <div className="bg-emerald-500 text-white p-3 rounded-2xl mb-4">
              <Activity className="w-8 h-8" />
            </div>
            <h1 className="text-3xl font-bold text-slate-900">AyushKendra</h1>
            <p className="text-slate-500 font-medium uppercase tracking-widest text-xs mt-2">Sovereign Enterprise Portal</p>
          </div>

          <form onSubmit={handleAuth} className="space-y-6">
            <div>
              <label className="block text-sm font-bold text-slate-700 mb-2">Email Address</label>
              <input 
                name="email" 
                type="email" 
                required 
                className="w-full p-4 bg-slate-50 border border-slate-200 rounded-xl outline-none focus:ring-2 focus:ring-emerald-500/20 focus:border-emerald-500 transition-all"
                placeholder="admin@ayushkendra.com"
              />
            </div>
            <div>
              <label className="block text-sm font-bold text-slate-700 mb-2">Password</label>
              <input 
                name="password" 
                type="password" 
                required 
                className="w-full p-4 bg-slate-50 border border-slate-200 rounded-xl outline-none focus:ring-2 focus:ring-emerald-500/20 focus:border-emerald-500 transition-all"
                placeholder="••••••••"
              />
            </div>
            {authMode === 'register' && (
              <div>
                <label className="block text-sm font-bold text-slate-700 mb-2">Role</label>
                <select 
                  name="role" 
                  className="w-full p-4 bg-slate-50 border border-slate-200 rounded-xl outline-none focus:ring-2 focus:ring-emerald-500/20 focus:border-emerald-500 transition-all"
                >
                  <option value="buyer">Buyer / Hospital</option>
                  <option value="vendor">Vendor / Manufacturer</option>
                </select>
              </div>
            )}
            <button type="submit" className="w-full bg-emerald-600 hover:bg-emerald-700 text-white py-4 rounded-xl font-bold text-lg transition-colors shadow-lg shadow-emerald-600/20">
              {authMode === 'login' ? 'Sign In' : 'Create Account'}
            </button>
          </form>

          <div className="mt-8 text-center">
            <button 
              onClick={() => setAuthMode(authMode === 'login' ? 'register' : 'login')}
              className="text-emerald-600 font-bold hover:underline"
            >
              {authMode === 'login' ? "Don't have an account? Register" : "Already have an account? Login"}
            </button>
          </div>
        </motion.div>
      </div>
    );
  }

  return (
    <div className="min-h-screen bg-slate-50 font-sans text-slate-900 flex">
      {/* Sidebar */}
      <aside className="w-64 bg-slate-900 text-slate-300 flex flex-col fixed h-full z-50">
        <div className="p-6 flex items-center gap-3 border-b border-slate-800">
          <div className="bg-emerald-500 text-white p-1.5 rounded-lg">
            <Activity className="w-6 h-6" />
          </div>
          <div>
            <h1 className="text-lg font-bold text-white leading-tight">AyushKendra</h1>
            <span className="text-xs text-emerald-400 font-medium tracking-wider">ENTERPRISE</span>
          </div>
        </div>
        
        <nav className="flex-1 px-4 py-6 space-y-2">
          {[
            { id: 'home', icon: LayoutDashboard, label: 'Home' },
            { id: 'products', icon: Package, label: 'Products' },
            { id: 'admin', icon: ShieldCheck, label: 'Admin Dashboard' },
            { id: 'orders', icon: ShoppingCart, label: 'Order History' },
            { id: 'vendor', icon: Users, label: 'Vendor Portal' },
          ].map((item) => (
            <button
              key={item.id}
              onClick={() => setActiveTab(item.id)}
              className={cn(
                "w-full flex items-center gap-3 px-4 py-3 rounded-xl text-sm font-medium transition-colors text-left",
                activeTab === item.id 
                  ? "bg-emerald-500/10 text-emerald-400" 
                  : "hover:bg-slate-800 hover:text-white"
              )}
            >
              <item.icon className="w-5 h-5" />
              {item.label}
            </button>
          ))}
        </nav>

        <div className="p-4 border-t border-slate-800">
          <p className="text-[10px] text-slate-500 text-center mb-4 uppercase tracking-widest">Powered by AllianceVenture</p>
          <button 
            onClick={logout}
            className="w-full flex items-center gap-3 px-4 py-3 rounded-xl text-sm font-medium hover:bg-red-500/10 hover:text-red-400 transition-colors"
          >
            <Settings className="w-5 h-5" />
            Logout
          </button>
        </div>
      </aside>

      {/* Main Content */}
      <main className="flex-1 ml-64 p-8">
        <div className="max-w-7xl mx-auto">
          
          {/* Header */}
          <header className="flex items-center justify-between mb-8">
            <div>
              <h2 className="text-2xl font-bold text-slate-900 capitalize">{activeTab.replace('-', ' ')}</h2>
              <p className="text-slate-500 text-sm mt-1">
                {activeTab === 'home' && "Integrated Medical & AYUSH Supply Platform"}
                {activeTab === 'products' && "Browse institutional healthcare procurement catalogue."}
                {activeTab === 'admin' && "Enterprise operations and analytics dashboard."}
                {activeTab === 'vendor' && "Submit and manage your healthcare supplies."}
              </p>
            </div>
            <div className="flex items-center gap-4">
              <button 
                onClick={fetchData}
                className="p-2 text-slate-400 hover:text-slate-600 hover:bg-slate-100 rounded-lg transition-colors"
                title="Refresh Data"
              >
                <RefreshCw className={cn("w-5 h-5", loading && "animate-spin")} />
              </button>
              <div className="flex items-center gap-3 px-4 py-2 bg-white border border-slate-200 rounded-full shadow-sm">
                <div className="w-8 h-8 bg-emerald-100 text-emerald-700 rounded-full flex items-center justify-center font-bold text-sm">
                  AD
                </div>
                <span className="text-sm font-medium">Admin User</span>
              </div>
            </div>
          </header>

          {/* HOME SECTION */}
          {activeTab === 'home' && (
            <motion.div 
              initial={{ opacity: 0, y: 20 }}
              animate={{ opacity: 1, y: 0 }}
              className="space-y-12"
            >
              <div className="bg-white p-12 rounded-3xl border border-slate-200 shadow-sm text-center relative overflow-hidden">
                <div className="absolute top-0 right-0 w-64 h-64 bg-emerald-50 rounded-full -mr-32 -mt-32 blur-3xl opacity-50"></div>
                <div className="relative z-10">
                  <h2 className="text-4xl font-bold text-slate-900 mb-6">
                    India’s Integrated Medical & <span className="text-emerald-600">AYUSH Supply</span> Platform
                  </h2>
                  <p className="text-lg text-slate-600 max-w-3xl mx-auto leading-relaxed">
                    Institutional healthcare procurement with digital governance,
                    GST billing, vendor dashboards and secure payments. Powering modern hospitals and traditional wellness centers alike.
                  </p>
                  <div className="mt-10 flex justify-center gap-4">
                    <button onClick={() => setActiveTab('products')} className="bg-slate-900 text-white px-8 py-3 rounded-xl font-bold hover:bg-slate-800 transition-colors">
                      Browse Products
                    </button>
                    <button onClick={() => setActiveTab('vendor')} className="bg-white text-slate-900 border border-slate-200 px-8 py-3 rounded-xl font-bold hover:bg-slate-50 transition-colors">
                      Become a Vendor
                    </button>
                  </div>
                </div>
              </div>

              <div className="grid md:grid-cols-3 gap-8">
                <div className="bg-white p-8 rounded-2xl border border-slate-200 shadow-sm">
                  <div className="w-12 h-12 bg-blue-50 text-blue-600 rounded-xl flex items-center justify-center mb-6">
                    <ShieldCheck className="w-6 h-6" />
                  </div>
                  <h3 className="text-xl font-bold mb-3">Digital Governance</h3>
                  <p className="text-slate-600 text-sm leading-relaxed">Transparent procurement processes with full audit trails and compliance tracking.</p>
                </div>
                <div className="bg-white p-8 rounded-2xl border border-slate-200 shadow-sm">
                  <div className="w-12 h-12 bg-emerald-50 text-emerald-600 rounded-xl flex items-center justify-center mb-6">
                    <IndianRupee className="w-6 h-6" />
                  </div>
                  <h3 className="text-xl font-bold mb-3">GST Billing</h3>
                  <p className="text-slate-600 text-sm leading-relaxed">Automated GST-compliant invoicing for all institutional orders and bulk supplies.</p>
                </div>
                <div className="bg-white p-8 rounded-2xl border border-slate-200 shadow-sm">
                  <div className="w-12 h-12 bg-indigo-50 text-indigo-600 rounded-xl flex items-center justify-center mb-6">
                    <Users className="w-6 h-6" />
                  </div>
                  <h3 className="text-xl font-bold mb-3">Vendor Network</h3>
                  <p className="text-slate-600 text-sm leading-relaxed">Connecting certified manufacturers with hospitals and AYUSH practitioners nationwide.</p>
                </div>
              </div>
            </motion.div>
          )}

          {/* PRODUCTS SECTION */}
          {activeTab === 'products' && (
            <motion.div 
              initial={{ opacity: 0, y: 20 }}
              animate={{ opacity: 1, y: 0 }}
              className="space-y-8"
            >
              <div className="flex flex-col md:flex-row gap-4 items-center justify-between">
                <div className="relative w-full md:w-96">
                  <ShoppingCart className="absolute left-3 top-1/2 -translate-y-1/2 w-5 h-5 text-slate-400" />
                  <input
                    type="text"
                    placeholder="Search products or categories..."
                    className="w-full pl-10 pr-4 py-3 bg-white border border-slate-200 rounded-xl outline-none focus:ring-2 focus:ring-emerald-500/20 focus:border-emerald-500 transition-all"
                    value={search}
                    onChange={(e) => setSearch(e.target.value)}
                  />
                </div>
                <div className="flex gap-2">
                  <button className="px-4 py-2 bg-white border border-slate-200 rounded-lg text-sm font-medium hover:bg-slate-50">Medical Devices</button>
                  <button className="px-4 py-2 bg-white border border-slate-200 rounded-lg text-sm font-medium hover:bg-slate-50">AYUSH Infrastructure</button>
                </div>
              </div>

              <div className="grid md:grid-cols-3 gap-8">
                {filteredProducts.map(p => (
                  <motion.div 
                    key={p.id} 
                    whileHover={{ y: -5 }}
                    className="bg-white p-6 rounded-2xl shadow-sm border border-slate-200 flex flex-col"
                  >
                    <div className="w-full aspect-video bg-slate-100 rounded-xl mb-6 flex items-center justify-center text-slate-300">
                      <Package className="w-12 h-12" />
                    </div>
                    <div className="flex-1">
                      <span className="text-[10px] font-bold uppercase tracking-widest text-emerald-600 bg-emerald-50 px-2 py-1 rounded mb-2 inline-block">
                        {p.category}
                      </span>
                      <h3 className="text-xl font-bold text-slate-900 mb-2">{p.name}</h3>
                      <p className="text-2xl font-bold text-slate-900 mb-6">
                        ₹{p.price.toLocaleString('en-IN')}
                      </p>
                    </div>
                    <button
                      onClick={() => payNow(p)}
                      className="w-full bg-slate-900 hover:bg-slate-800 text-white py-3 rounded-xl font-bold transition-colors flex items-center justify-center gap-2"
                    >
                      <ShoppingCart className="w-4 h-4" /> Buy Now
                    </button>
                  </motion.div>
                ))}
                {filteredProducts.length === 0 && (
                  <div className="col-span-3 py-20 text-center text-slate-500">
                    No products found matching your search.
                  </div>
                )}
              </div>
            </motion.div>
          )}

          {/* ADMIN DASHBOARD SECTION */}
          {activeTab === 'admin' && analytics && (
            <motion.div 
              initial={{ opacity: 0, y: 20 }}
              animate={{ opacity: 1, y: 0 }}
              className="space-y-8"
            >
              {/* KPI Cards */}
              <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
                <div className="bg-white p-6 rounded-2xl border border-slate-200 shadow-sm">
                  <div className="flex items-center justify-between mb-4">
                    <h3 className="text-slate-500 font-medium">Total Revenue</h3>
                    <div className="p-2 bg-emerald-50 text-emerald-600 rounded-lg">
                      <IndianRupee className="w-5 h-5" />
                    </div>
                  </div>
                  <p className="text-3xl font-bold text-slate-900">
                    ₹{analytics.total_revenue.toLocaleString('en-IN')}
                  </p>
                  <p className="text-sm text-emerald-600 flex items-center gap-1 mt-2 font-medium">
                    <TrendingUp className="w-4 h-4" /> +12.5% from last month
                  </p>
                </div>

                <div className="bg-white p-6 rounded-2xl border border-slate-200 shadow-sm">
                  <div className="flex items-center justify-between mb-4">
                    <h3 className="text-slate-500 font-medium">Total Orders</h3>
                    <div className="p-2 bg-blue-50 text-blue-600 rounded-lg">
                      <ShoppingCart className="w-5 h-5" />
                    </div>
                  </div>
                  <p className="text-3xl font-bold text-slate-900">{analytics.total_orders}</p>
                  <p className="text-sm text-slate-500 mt-2">Across all facilities</p>
                </div>

                <div className="bg-white p-6 rounded-2xl border border-slate-200 shadow-sm">
                  <div className="flex items-center justify-between mb-4">
                    <h3 className="text-slate-500 font-medium">GST Collected</h3>
                    <div className="p-2 bg-purple-50 text-purple-600 rounded-lg">
                      <FileText className="w-5 h-5" />
                    </div>
                  </div>
                  <p className="text-3xl font-bold text-slate-900">
                    ₹{analytics.gst_collected.toLocaleString('en-IN')}
                  </p>
                  <p className="text-sm text-slate-500 mt-2">Ready for compliance filing</p>
                </div>
              </div>

              {/* Charts */}
              <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
                <div className="lg:col-span-2 bg-white p-6 rounded-2xl border border-slate-200 shadow-sm">
                  <h3 className="text-lg font-bold text-slate-900 mb-6">Revenue Trend</h3>
                  <div className="h-72">
                    <ResponsiveContainer width="100%" height="100%">
                      <BarChart data={analytics.revenue_trend}>
                        <CartesianGrid strokeDasharray="3 3" vertical={false} stroke="#e2e8f0" />
                        <XAxis dataKey="name" axisLine={false} tickLine={false} tick={{ fill: '#64748b' }} />
                        <YAxis axisLine={false} tickLine={false} tick={{ fill: '#64748b' }} tickFormatter={(value) => `₹${value/1000}k`} />
                        <Tooltip 
                          cursor={{ fill: '#f1f5f9' }}
                          contentStyle={{ borderRadius: '12px', border: 'none', boxShadow: '0 4px 6px -1px rgb(0 0 0 / 0.1)' }}
                        />
                        <Bar dataKey="revenue" fill="#10b981" radius={[4, 4, 0, 0]} />
                      </BarChart>
                    </ResponsiveContainer>
                  </div>
                </div>

                <div className="bg-white p-6 rounded-2xl border border-slate-200 shadow-sm">
                  <h3 className="text-lg font-bold text-slate-900 mb-6">Order Status</h3>
                  <div className="h-72">
                    <ResponsiveContainer width="100%" height="100%">
                      <PieChart>
                        <Pie
                          data={analytics.status_distribution}
                          cx="50%"
                          cy="50%"
                          innerRadius={60}
                          outerRadius={80}
                          paddingAngle={5}
                          dataKey="value"
                        >
                          {analytics.status_distribution.map((entry, index) => (
                            <Cell key={`cell-${index}`} fill={COLORS[index % COLORS.length]} />
                          ))}
                        </Pie>
                        <Tooltip contentStyle={{ borderRadius: '12px', border: 'none', boxShadow: '0 4px 6px -1px rgb(0 0 0 / 0.1)' }} />
                        <Legend verticalAlign="bottom" height={36} iconType="circle" />
                      </PieChart>
                    </ResponsiveContainer>
                  </div>
                </div>
              </div>
            </motion.div>
          )}

          {/* ORDERS SECTION */}
          {activeTab === 'orders' && (
            <motion.div 
              initial={{ opacity: 0, y: 20 }}
              animate={{ opacity: 1, y: 0 }}
              className="bg-white rounded-2xl border border-slate-200 shadow-sm overflow-hidden"
            >
              <div className="p-6 border-b border-slate-200 flex items-center justify-between">
                <h3 className="text-lg font-bold text-slate-900">Order Management</h3>
                <button 
                  onClick={createMockOrder}
                  className="bg-emerald-600 hover:bg-emerald-700 text-white px-4 py-2 rounded-lg text-sm font-medium transition-colors"
                >
                  + Create Mock Order
                </button>
              </div>
              <div className="overflow-x-auto">
                <table className="w-full text-left border-collapse">
                  <thead>
                    <tr className="bg-slate-50 border-b border-slate-200">
                      <th className="py-3 px-6 text-xs font-semibold text-slate-500 uppercase tracking-wider">Order ID</th>
                      <th className="py-3 px-6 text-xs font-semibold text-slate-500 uppercase tracking-wider">Date</th>
                      <th className="py-3 px-6 text-xs font-semibold text-slate-500 uppercase tracking-wider">Facility / Vendor</th>
                      <th className="py-3 px-6 text-xs font-semibold text-slate-500 uppercase tracking-wider">Total</th>
                      <th className="py-3 px-6 text-xs font-semibold text-slate-500 uppercase tracking-wider">Status</th>
                      <th className="py-3 px-6 text-xs font-semibold text-slate-500 uppercase tracking-wider text-right">Actions</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-slate-200">
                    {orders.map((order) => (
                      <tr key={order.id} className="hover:bg-slate-50 transition-colors">
                        <td className="py-4 px-6 font-medium text-slate-900">#ORD-{order.id.toString().padStart(4, '0')}</td>
                        <td className="py-4 px-6 text-sm text-slate-500">{new Date(order.created_at).toLocaleDateString()}</td>
                        <td className="py-4 px-6">
                          <div className="text-sm font-medium text-slate-900">Product {order.product_id}</div>
                          <div className="text-xs text-slate-500">Buyer: {order.buyer_id}</div>
                        </td>
                        <td className="py-4 px-6 font-medium text-slate-900">₹{order.amount.toLocaleString('en-IN')}</td>
                        <td className="py-4 px-6">
                          <span className={cn(
                            "px-2.5 py-1 rounded-full text-xs font-medium",
                            order.status === 'DELIVERED' ? "bg-emerald-100 text-emerald-700" :
                            order.status === 'SHIPPED' ? "bg-blue-100 text-blue-700" :
                            order.status === 'PAID' ? "bg-indigo-100 text-indigo-700" :
                            order.status === 'pending' ? "bg-amber-100 text-amber-700" :
                            "bg-slate-100 text-slate-700"
                          )}>
                            {order.status}
                          </span>
                        </td>
                        <td className="py-4 px-6 text-right">
                          <div className="flex items-center justify-end gap-2">
                            <button 
                              onClick={() => downloadInvoice(order.id)}
                              className="p-1.5 text-slate-400 hover:text-emerald-600 hover:bg-emerald-50 rounded-md transition-colors"
                              title="Download Invoice"
                            >
                              <FileText className="w-4 h-4" />
                            </button>
                            <select 
                              className="text-xs border border-slate-200 rounded-md px-2 py-1 bg-white text-slate-700 outline-none focus:border-emerald-500"
                              value={order.status}
                              onChange={(e) => updateOrderStatus(order.id, e.target.value)}
                            >
                              <option value="pending">Pending</option>
                              <option value="PAID">Paid</option>
                              <option value="SHIPPED">Shipped</option>
                              <option value="DELIVERED">Delivered</option>
                            </select>
                            <button 
                              onClick={() => deleteOrder(order.id)}
                              className="p-1.5 text-slate-400 hover:text-red-600 hover:bg-red-50 rounded-md transition-colors"
                              title="Delete Order"
                            >
                              <Trash2 className="w-4 h-4" />
                            </button>
                          </div>
                        </td>
                      </tr>
                    ))}
                    {orders.length === 0 && (
                      <tr>
                        <td colSpan={6} className="py-8 text-center text-slate-500">No orders found.</td>
                      </tr>
                    )}
                  </tbody>
                </table>
              </div>
            </motion.div>
          )}

          {/* VENDOR PORTAL SECTION */}
          {activeTab === 'vendor' && (
            <motion.div 
              initial={{ opacity: 0, y: 20 }}
              animate={{ opacity: 1, y: 0 }}
              className="max-w-2xl mx-auto"
            >
              <div className="bg-white p-10 rounded-3xl border border-slate-200 shadow-sm">
                <div className="flex items-center gap-4 mb-8">
                  <div className="w-12 h-12 bg-emerald-50 text-emerald-600 rounded-2xl flex items-center justify-center">
                    <Package className="w-6 h-6" />
                  </div>
                  <div>
                    <h3 className="text-2xl font-bold text-slate-900">Submit New Product</h3>
                    <p className="text-slate-500 text-sm">Add your medical or AYUSH equipment to our network.</p>
                  </div>
                </div>
                
                <form onSubmit={handleVendorSubmit} className="space-y-6">
                  <div>
                    <label className="block text-sm font-bold text-slate-700 mb-2">Product Name</label>
                    <input
                      name="name"
                      type="text"
                      required
                      placeholder="e.g. Digital BP Monitor"
                      className="w-full p-4 bg-slate-50 border border-slate-200 rounded-xl outline-none focus:ring-2 focus:ring-emerald-500/20 focus:border-emerald-500 transition-all"
                    />
                  </div>
                  <div className="grid grid-cols-2 gap-6">
                    <div>
                      <label className="block text-sm font-bold text-slate-700 mb-2">Price (INR)</label>
                      <input
                        name="price"
                        type="number"
                        required
                        placeholder="2500"
                        className="w-full p-4 bg-slate-50 border border-slate-200 rounded-xl outline-none focus:ring-2 focus:ring-emerald-500/20 focus:border-emerald-500 transition-all"
                      />
                    </div>
                    <div>
                      <label className="block text-sm font-bold text-slate-700 mb-2">Category</label>
                      <select
                        name="category"
                        required
                        className="w-full p-4 bg-slate-50 border border-slate-200 rounded-xl outline-none focus:ring-2 focus:ring-emerald-500/20 focus:border-emerald-500 transition-all"
                      >
                        <option value="Medical Devices">Medical Devices</option>
                        <option value="AYUSH Infrastructure">AYUSH Infrastructure</option>
                        <option value="Consumables">Consumables</option>
                      </select>
                    </div>
                  </div>
                  <button type="submit" className="w-full bg-emerald-600 hover:bg-emerald-700 text-white py-4 rounded-xl font-bold text-lg transition-colors shadow-lg shadow-emerald-600/20">
                    Submit for Approval
                  </button>
                </form>
              </div>
            </motion.div>
          )}

        </div>
      </main>
      
      {/* Footer (Floating) */}
      <footer className="fixed bottom-0 left-64 right-0 bg-white/80 backdrop-blur-md border-t border-slate-200 py-4 px-8 flex items-center justify-between text-[10px] font-bold text-slate-400 uppercase tracking-widest z-40">
        <div>© 2026 AyushKendra Enterprise</div>
        <div className="flex gap-6">
          <a href="#" className="hover:text-emerald-500 transition-colors">Privacy</a>
          <a href="#" className="hover:text-emerald-500 transition-colors">Terms</a>
          <a href="#" className="hover:text-emerald-500 transition-colors">Compliance</a>
        </div>
      </footer>
    </div>
  );
}

