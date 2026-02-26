import { Activity, LayoutDashboard, ShoppingCart, Users, Settings, ShieldCheck, Package, IndianRupee, TrendingUp, RefreshCw, Trash2, CheckCircle2, FileText, Truck, FileSearch, Globe, ChevronDown } from 'lucide-react';
import { motion } from 'motion/react';
import React, { useEffect, useState } from 'react';
import { BarChart, Bar, XAxis, YAxis, CartesianGrid, Tooltip, Legend, ResponsiveContainer, PieChart, Pie, Cell } from 'recharts';
import { clsx, type ClassValue } from 'clsx';
import { twMerge } from 'tailwind-merge';
import Landing from './components/Landing';

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

interface AuditLog {
  id: number;
  actor_id: number;
  role: string;
  action: string;
  object_type: string;
  object_id: number;
  ip_address: string;
  created_at: string;
}

const COLORS = ['#10b981', '#3b82f6', '#f59e0b', '#ef4444', '#6366f1'];

export default function App() {
  const [activeTab, setActiveTab] = useState('home');
  const [analytics, setAnalytics] = useState<AnalyticsData | null>(null);
  const [orders, setOrders] = useState<Order[]>([]);
  const [products, setProducts] = useState<Product[]>([]);
  const [auditLogs, setAuditLogs] = useState<AuditLog[]>([]);
  const [loading, setLoading] = useState(true);
  const [search, setSearch] = useState('');
  const [user, setUser] = useState<{ email: string; role: string; token: string; org_id?: number } | null>(() => {
    const saved = localStorage.getItem('ayush_user');
    return saved ? JSON.parse(saved) : null;
  });
  const [authMode, setAuthMode] = useState<'login' | 'register'>('login');
  const [showLanding, setShowLanding] = useState(true);

  const fetchData = async () => {
    if (!user) return;
    setLoading(true);
    try {
      const headers = { Authorization: `Bearer ${user.token}` };
      
      const [ordersRes, productsRes, analyticsRes] = await Promise.all([
        fetch('/api/orders', { headers }),
        fetch('/api/products', { headers }),
        fetch('/api/analytics/summary', { headers })
      ]);

      if (ordersRes.ok) setOrders(await ordersRes.json());
      if (productsRes.ok) setProducts(await productsRes.json());
      if (analyticsRes.ok) setAnalytics(await analyticsRes.json());

      if (['SUPER_ADMIN', 'GOVERNMENT_VIEW'].includes(user.role)) {
        const auditRes = await fetch('/api/audit', { headers });
        if (auditRes.ok) setAuditLogs(await auditRes.json());
      }
    } catch (error) {
      console.error('Failed to fetch data:', error);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    if (user) {
      fetchData();
    }
  }, [user]);

  const handleAuth = async (e: React.FormEvent<HTMLFormElement>) => {
    e.preventDefault();
    const formData = new FormData(e.currentTarget);
    const email = formData.get('email');
    const password = formData.get('password');
    const role = formData.get('role') || 'FACILITY_ADMIN';
    const org_name = formData.get('org_name');
    const gstin = formData.get('gstin');

    const endpoint = authMode === 'login' ? '/api/auth/login' : '/api/auth/register';
    const body: any = { email, password, role };
    
    if (authMode === 'register') {
      body.org_name = org_name;
      body.org_type = role === 'VENDOR_ADMIN' ? 'VENDOR' : role === 'FACILITY_ADMIN' ? 'HOSPITAL' : role === 'ADMIN_VIEW' ? 'ADMIN' : 'GOVERNMENT';
      body.gstin = gstin;
    }

    const res = await fetch(endpoint, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(body)
    });

    const data = await res.json();
    if (res.ok) {
      const userData = { email: email as string, role: data.role, token: data.access_token, org_id: data.org_id };
      setUser(userData);
      localStorage.setItem('ayush_user', JSON.stringify(userData));
    } else {
      alert(data.error || 'Authentication failed');
    }
  };

  const logout = () => {
    localStorage.removeItem('ayush_user');
    setUser(null);
    setShowLanding(true);
  };

  const createOrder = async (productId: number, amount: number) => {
    const res = await fetch('/api/orders', {
      method: 'POST',
      headers: { 
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${user?.token}`
      },
      body: JSON.stringify({ product_id: productId, amount })
    });
    
    if (res.ok) {
      const data = await res.json();
      alert(`Order created successfully! Total with GST: ₹${data.total.toFixed(2)}`);
      fetchData();
    } else {
      alert('Failed to create order');
    }
  };

  const updateOrderStatus = async (orderId: number, status: string) => {
    const res = await fetch(`/api/orders/${orderId}/status`, {
      method: 'PUT',
      headers: { 
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${user?.token}`
      },
      body: JSON.stringify({ status })
    });
    if (res.ok) {
      fetchData();
    }
  };

  const addProduct = async (e: React.FormEvent<HTMLFormElement>) => {
    e.preventDefault();
    const form = e.currentTarget;
    const formData = new FormData(form);
    const res = await fetch('/api/products', {
      method: 'POST',
      headers: { 
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${user?.token}`
      },
      body: JSON.stringify({
        name: formData.get('name'),
        category: formData.get('category'),
        price: Number(formData.get('price'))
      })
    });
    if (res.ok) {
      form.reset();
      fetchData();
    }
  };

  const downloadInvoice = async (orderId: number) => {
    const res = await fetch(`/api/orders/invoice/${orderId}`, {
      headers: { Authorization: `Bearer ${user?.token}` }
    });
    if (res.ok) {
      const blob = await res.blob();
      const url = window.URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = `invoice_${orderId}.pdf`;
      document.body.appendChild(a);
      a.click();
      a.remove();
    } else {
      alert('Failed to download invoice');
    }
  };

  const filteredProducts = products.filter(p => 
    p.name.toLowerCase().includes(search.toLowerCase()) ||
    p.category.toLowerCase().includes(search.toLowerCase())
  );

  if (showLanding && !user) {
    return <Landing onEnterPortal={() => setShowLanding(false)} />;
  }

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
            <p className="text-slate-500 font-medium uppercase tracking-widest text-xs mt-2">Enterprise Procurement Portal</p>
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
              <>
                <div>
                  <label className="block text-sm font-bold text-slate-700 mb-2">Organization Name</label>
                  <input 
                    name="org_name" 
                    type="text" 
                    required 
                    className="w-full p-4 bg-slate-50 border border-slate-200 rounded-xl outline-none focus:ring-2 focus:ring-emerald-500/20 focus:border-emerald-500 transition-all"
                    placeholder="Apollo Hospitals"
                  />
                </div>
                <div>
                  <label className="block text-sm font-bold text-slate-700 mb-2">GSTIN (Optional)</label>
                  <input 
                    name="gstin" 
                    type="text" 
                    className="w-full p-4 bg-slate-50 border border-slate-200 rounded-xl outline-none focus:ring-2 focus:ring-emerald-500/20 focus:border-emerald-500 transition-all"
                    placeholder="22AAAAA0000A1Z5"
                  />
                </div>
                <div>
                  <label className="block text-sm font-bold text-slate-700 mb-2">Role</label>
                  <select 
                    name="role" 
                    className="w-full p-4 bg-slate-50 border border-slate-200 rounded-xl outline-none focus:ring-2 focus:ring-emerald-500/20 focus:border-emerald-500 transition-all"
                  >
                    <option value="FACILITY_ADMIN">Healthcare Facility / Hospital</option>
                    <option value="VENDOR_ADMIN">Medical Device Vendor / Manufacturer</option>
                    <option value="GOVERNMENT_VIEW">Government / Auditor</option>
                    <option value="ADMIN_VIEW">Admin</option>
                  </select>
                </div>
              </>
            )}
            <button type="submit" className="w-full bg-emerald-600 hover:bg-emerald-700 text-white py-4 rounded-xl font-bold text-lg transition-colors shadow-lg shadow-emerald-600/20">
              {authMode === 'login' ? 'Sign In' : 'Create Account'}
            </button>
          </form>

          <div className="mt-8 text-center">
            <button 
              onClick={() => setAuthMode(m => m === 'login' ? 'register' : 'login')}
              className="text-emerald-600 font-medium hover:text-emerald-700"
            >
              {authMode === 'login' ? "Don't have an account? Register" : "Already have an account? Sign In"}
            </button>
          </div>
        </motion.div>
      </div>
    );
  }

  // Navigation Items based on Role
  const navItems = [
    { id: 'home', icon: LayoutDashboard, label: 'Dashboard', roles: ['SUPER_ADMIN', 'COMPANY_ADMIN', 'FACILITY_ADMIN', 'VENDOR_ADMIN', 'GOVERNMENT_VIEW', 'ADMIN_VIEW'] },
    { id: 'products', icon: Package, label: 'Catalogue', roles: ['SUPER_ADMIN', 'COMPANY_ADMIN', 'FACILITY_ADMIN', 'VENDOR_ADMIN'] },
    { id: 'orders', icon: ShoppingCart, label: 'Procurement Log', roles: ['SUPER_ADMIN', 'COMPANY_ADMIN', 'FACILITY_ADMIN', 'VENDOR_ADMIN'] },
    { id: 'audit', icon: FileSearch, label: 'Audit Trail', roles: ['SUPER_ADMIN', 'GOVERNMENT_VIEW'] },
  ].filter(item => item.roles.includes(user.role));

  return (
    <div className="min-h-screen bg-slate-50 flex font-sans text-slate-900">
      
      {/* Sidebar */}
      <aside className="w-64 bg-slate-900 text-slate-300 flex flex-col fixed h-full z-10">
        <div className="p-6 flex items-center gap-3 border-b border-slate-800">
          <div className="bg-emerald-500 text-white p-2 rounded-xl">
            <Activity className="w-6 h-6" />
          </div>
          <div>
            <h1 className="text-lg font-bold text-white leading-tight">AyushKendra</h1>
            <span className="text-[10px] text-emerald-400 font-medium tracking-wider">{user.role.replace('_', ' ')}</span>
          </div>
        </div>
        
        <nav className="flex-1 px-4 py-6 space-y-2">
          {navItems.map((item) => (
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
          <p className="text-[10px] text-slate-500 text-center mb-4 uppercase tracking-widest">
            Powered by <a href="https://allianceventures.com" target="_blank" rel="noopener noreferrer" className="text-emerald-400 hover:underline">ALLIANCEVENTURES</a>
          </p>
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
                {activeTab === 'home' && "Enterprise Overview & Analytics"}
                {activeTab === 'products' && "Browse institutional healthcare procurement catalogue."}
                {activeTab === 'orders' && "Track all your medical device orders and shipments."}
                {activeTab === 'audit' && "Immutable transaction and action logs."}
              </p>
            </div>
            <div className="flex items-center gap-4">
              {/* Ecosystem Dropdown */}
              <div className="relative group z-50">
                <button className="flex items-center gap-2 px-4 py-2 bg-slate-900 text-white rounded-full text-sm font-medium hover:bg-slate-800 transition-colors shadow-sm">
                  <Globe className="w-4 h-4 text-emerald-400" />
                  ALLIANCEVENTURES <ChevronDown className="w-4 h-4" />
                </button>
                <div className="absolute right-0 top-full mt-2 w-56 bg-white text-slate-900 rounded-xl shadow-xl border border-slate-200 opacity-0 invisible group-hover:opacity-100 group-hover:visible transition-all overflow-hidden">
                  <a href="https://rupaykg.com" target="_blank" rel="noopener noreferrer" className="block px-4 py-3 hover:bg-emerald-50 hover:text-emerald-700 text-sm font-medium border-b border-slate-100 transition-colors">RupayKg (Sustainability)</a>
                  <a href="https://vyaparkendra.com" target="_blank" rel="noopener noreferrer" className="block px-4 py-3 hover:bg-emerald-50 hover:text-emerald-700 text-sm font-medium border-b border-slate-100 transition-colors">VyaparKendra (Commerce)</a>
                  <a href="#" className="block px-4 py-3 hover:bg-emerald-50 hover:text-emerald-700 text-sm font-bold transition-colors">AyushKendra (Health-Tech)</a>
                </div>
              </div>

              <button 
                onClick={fetchData}
                className="p-2 text-slate-400 hover:text-slate-600 hover:bg-slate-100 rounded-lg transition-colors"
                title="Refresh Data"
              >
                <RefreshCw className={cn("w-5 h-5", loading && "animate-spin")} />
              </button>
              <div className="flex items-center gap-3 px-4 py-2 bg-white border border-slate-200 rounded-full shadow-sm">
                <div className="w-8 h-8 bg-emerald-100 text-emerald-700 rounded-full flex items-center justify-center font-bold text-sm">
                  {user.email.charAt(0).toUpperCase()}
                </div>
                <span className="text-sm font-medium">{user.email}</span>
              </div>
            </div>
          </header>

          {/* Tab Content */}
          {activeTab === 'home' && (
            <motion.div
              initial={{ opacity: 0, y: 10 }}
              animate={{ opacity: 1, y: 0 }}
              className="space-y-8"
            >
              {['SUPER_ADMIN', 'COMPANY_ADMIN', 'GOVERNMENT_VIEW', 'ADMIN_VIEW'].includes(user.role) && analytics && (
                <>
                  <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
                    <div className="bg-white p-6 rounded-3xl shadow-sm border border-slate-200 flex items-center gap-4">
                      <div className="bg-blue-50 text-blue-600 p-4 rounded-2xl">
                        <ShoppingCart className="w-8 h-8" />
                      </div>
                      <div>
                        <p className="text-sm font-bold text-slate-500 uppercase tracking-wider">Total Orders</p>
                        <p className="text-3xl font-black text-slate-900">{analytics.total_orders}</p>
                      </div>
                    </div>
                    <div className="bg-white p-6 rounded-3xl shadow-sm border border-slate-200 flex items-center gap-4">
                      <div className="bg-emerald-50 text-emerald-600 p-4 rounded-2xl">
                        <IndianRupee className="w-8 h-8" />
                      </div>
                      <div>
                        <p className="text-sm font-bold text-slate-500 uppercase tracking-wider">Total Revenue</p>
                        <p className="text-3xl font-black text-slate-900">₹{(analytics.total_revenue || 0).toLocaleString()}</p>
                      </div>
                    </div>
                    <div className="bg-white p-6 rounded-3xl shadow-sm border border-slate-200 flex items-center gap-4">
                      <div className="bg-amber-50 text-amber-600 p-4 rounded-2xl">
                        <FileText className="w-8 h-8" />
                      </div>
                      <div>
                        <p className="text-sm font-bold text-slate-500 uppercase tracking-wider">GST Collected</p>
                        <p className="text-3xl font-black text-slate-900">₹{(analytics.gst_collected || 0).toLocaleString()}</p>
                      </div>
                    </div>
                  </div>

                  <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
                    <div className="bg-white p-6 rounded-3xl shadow-sm border border-slate-200">
                      <h3 className="text-lg font-bold text-slate-900 mb-6">Order Status Distribution</h3>
                      <div className="h-72">
                        <ResponsiveContainer width="100%" height="100%">
                          <PieChart>
                            <Pie
                              data={analytics.status_distribution}
                              cx="50%"
                              cy="50%"
                              innerRadius={60}
                              outerRadius={100}
                              paddingAngle={5}
                              dataKey="value"
                            >
                              {analytics.status_distribution.map((entry, index) => (
                                <Cell key={`cell-${index}`} fill={COLORS[index % COLORS.length]} />
                              ))}
                            </Pie>
                            <Tooltip />
                            <Legend />
                          </PieChart>
                        </ResponsiveContainer>
                      </div>
                    </div>
                  </div>
                </>
              )}

              {user.role === 'VENDOR_ADMIN' && (
                <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
                  <div className="bg-white p-6 rounded-3xl shadow-sm border border-slate-200 flex items-center gap-4">
                    <div className="bg-blue-50 text-blue-600 p-4 rounded-2xl">
                      <ShoppingCart className="w-8 h-8" />
                    </div>
                    <div>
                      <p className="text-sm font-bold text-slate-500 uppercase tracking-wider">My Orders</p>
                      <p className="text-3xl font-black text-slate-900">{orders.length}</p>
                    </div>
                  </div>
                  <div className="bg-white p-6 rounded-3xl shadow-sm border border-slate-200 flex items-center gap-4">
                    <div className="bg-emerald-50 text-emerald-600 p-4 rounded-2xl">
                      <IndianRupee className="w-8 h-8" />
                    </div>
                    <div>
                      <p className="text-sm font-bold text-slate-500 uppercase tracking-wider">My Revenue</p>
                      <p className="text-3xl font-black text-slate-900">₹{orders.reduce((acc, o) => acc + o.total, 0).toLocaleString()}</p>
                    </div>
                  </div>
                  <div className="bg-white p-6 rounded-3xl shadow-sm border border-slate-200 flex items-center gap-4">
                    <div className="bg-amber-50 text-amber-600 p-4 rounded-2xl">
                      <Package className="w-8 h-8" />
                    </div>
                    <div>
                      <p className="text-sm font-bold text-slate-500 uppercase tracking-wider">My Products</p>
                      <p className="text-3xl font-black text-slate-900">{products.filter(p => p.vendor_id === user.org_id).length}</p>
                    </div>
                  </div>
                </div>
              )}

              {user.role === 'FACILITY_ADMIN' && (
                <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
                  <div className="bg-white p-6 rounded-3xl shadow-sm border border-slate-200 flex items-center gap-4">
                    <div className="bg-blue-50 text-blue-600 p-4 rounded-2xl">
                      <ShoppingCart className="w-8 h-8" />
                    </div>
                    <div>
                      <p className="text-sm font-bold text-slate-500 uppercase tracking-wider">Orders Placed</p>
                      <p className="text-3xl font-black text-slate-900">{orders.length}</p>
                    </div>
                  </div>
                  <div className="bg-white p-6 rounded-3xl shadow-sm border border-slate-200 flex items-center gap-4">
                    <div className="bg-emerald-50 text-emerald-600 p-4 rounded-2xl">
                      <IndianRupee className="w-8 h-8" />
                    </div>
                    <div>
                      <p className="text-sm font-bold text-slate-500 uppercase tracking-wider">Total Spent</p>
                      <p className="text-3xl font-black text-slate-900">₹{orders.reduce((acc, o) => acc + o.total, 0).toLocaleString()}</p>
                    </div>
                  </div>
                  <div className="bg-white p-6 rounded-3xl shadow-sm border border-slate-200 flex items-center gap-4">
                    <div className="bg-amber-50 text-amber-600 p-4 rounded-2xl">
                      <RefreshCw className="w-8 h-8" />
                    </div>
                    <div>
                      <p className="text-sm font-bold text-slate-500 uppercase tracking-wider">Pending Orders</p>
                      <p className="text-3xl font-black text-slate-900">{orders.filter(o => o.status === 'PENDING').length}</p>
                    </div>
                  </div>
                </div>
              )}
            </motion.div>
          )}

          {activeTab === 'products' && (
            <motion.div
              initial={{ opacity: 0, y: 10 }}
              animate={{ opacity: 1, y: 0 }}
              className="space-y-6"
            >
              {user.role === 'VENDOR_ADMIN' && (
                <div className="bg-white p-6 rounded-3xl shadow-sm border border-slate-200 mb-8">
                  <h3 className="text-lg font-bold text-slate-900 mb-4">Add New Product</h3>
                  <form onSubmit={addProduct} className="grid grid-cols-1 md:grid-cols-4 gap-4 items-end">
                    <div className="md:col-span-2">
                      <label className="block text-sm font-bold text-slate-700 mb-2">Product Name</label>
                      <input 
                        name="name" 
                        type="text" 
                        placeholder="e.g. MRI Machine" 
                        required 
                        className="w-full p-3 bg-slate-50 border border-slate-200 rounded-xl outline-none focus:ring-2 focus:ring-emerald-500/20 focus:border-emerald-500 transition-all"
                      />
                    </div>
                    <div>
                      <label className="block text-sm font-bold text-slate-700 mb-2">Category</label>
                      <input 
                        name="category" 
                        type="text" 
                        placeholder="e.g. Diagnostic Equipment" 
                        required 
                        className="w-full p-3 bg-slate-50 border border-slate-200 rounded-xl outline-none focus:ring-2 focus:ring-emerald-500/20 focus:border-emerald-500 transition-all"
                      />
                    </div>
                    <div>
                      <label className="block text-sm font-bold text-slate-700 mb-2">Base Price (₹)</label>
                      <input 
                        name="price" 
                        type="number" 
                        placeholder="0.00" 
                        required 
                        className="w-full p-3 bg-slate-50 border border-slate-200 rounded-xl outline-none focus:ring-2 focus:ring-emerald-500/20 focus:border-emerald-500 transition-all"
                      />
                    </div>
                    <div className="md:col-span-4 mt-2">
                      <button type="submit" className="bg-slate-900 hover:bg-slate-800 text-white px-6 py-3 rounded-xl font-bold transition-colors">
                        Add to Catalogue
                      </button>
                    </div>
                  </form>
                </div>
              )}

              <div className="flex items-center gap-4 mb-6">
                <input 
                  type="text"
                  placeholder="Search catalogue..."
                  value={search}
                  onChange={(e) => setSearch(e.target.value)}
                  className="flex-1 p-4 bg-white border border-slate-200 rounded-2xl outline-none focus:ring-2 focus:ring-emerald-500/20 focus:border-emerald-500 transition-all shadow-sm"
                />
              </div>

              <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
                {filteredProducts.map((product) => (
                  <div key={product.id} className="bg-white p-6 rounded-3xl shadow-sm border border-slate-200 hover:shadow-md transition-shadow">
                    <div className="flex justify-between items-start mb-4">
                      <div>
                        <span className="text-xs font-bold text-emerald-600 bg-emerald-50 px-2 py-1 rounded-md uppercase tracking-wider">{product.category}</span>
                        <h3 className="text-lg font-bold text-slate-900 mt-2">{product.name}</h3>
                      </div>
                      <span className="text-lg font-black text-slate-900">₹{product.price.toLocaleString()}</span>
                    </div>
                    
                    {user.role === 'FACILITY_ADMIN' && (
                      <button 
                        onClick={() => createOrder(product.id, 1)}
                        className="w-full mt-4 bg-emerald-50 hover:bg-emerald-100 text-emerald-700 py-3 rounded-xl font-bold transition-colors flex items-center justify-center gap-2"
                      >
                        <ShoppingCart className="w-4 h-4" />
                        Procure Item
                      </button>
                    )}
                  </div>
                ))}
                {filteredProducts.length === 0 && (
                  <div className="col-span-full text-center py-12 text-slate-500">
                    No products found matching your search.
                  </div>
                )}
              </div>
            </motion.div>
          )}

          {activeTab === 'orders' && (
            <motion.div
              initial={{ opacity: 0, y: 10 }}
              animate={{ opacity: 1, y: 0 }}
            >
              <div className="bg-white rounded-3xl shadow-sm border border-slate-200 overflow-hidden">
                <div className="overflow-x-auto">
                  <table className="w-full text-left border-collapse">
                    <thead>
                      <tr className="bg-slate-50 text-slate-500 text-xs uppercase tracking-wider">
                        <th className="p-4 font-bold border-b border-slate-200">Order ID</th>
                        <th className="p-4 font-bold border-b border-slate-200">Date</th>
                        <th className="p-4 font-bold border-b border-slate-200">Amount (Inc. GST)</th>
                        <th className="p-4 font-bold border-b border-slate-200">Status</th>
                        <th className="p-4 font-bold border-b border-slate-200">Actions</th>
                      </tr>
                    </thead>
                    <tbody className="text-sm">
                      {orders.map((order) => (
                        <tr key={order.id} className="border-b border-slate-100 hover:bg-slate-50/50 transition-colors">
                          <td className="p-4 font-mono font-medium text-slate-900">#{order.id}</td>
                          <td className="p-4 text-slate-600">{new Date(order.created_at).toLocaleDateString()}</td>
                          <td className="p-4 font-medium text-slate-900">₹{order.total.toLocaleString()}</td>
                          <td className="p-4">
                            <span className={cn(
                              "px-3 py-1 rounded-full text-xs font-bold uppercase tracking-wider",
                              order.status === 'PAID' ? "bg-emerald-100 text-emerald-700" :
                              order.status === 'PENDING_PAYMENT' ? "bg-amber-100 text-amber-700" :
                              order.status === 'SHIPPED' ? "bg-blue-100 text-blue-700" :
                              "bg-slate-100 text-slate-700"
                            )}>
                              {order.status.replace('_', ' ')}
                            </span>
                          </td>
                          <td className="p-4 flex gap-2">
                            {(order.status === 'PAID' || order.status === 'SHIPPED' || order.status === 'DELIVERED') && (
                              <button 
                                onClick={() => downloadInvoice(order.id)}
                                className="p-2 text-slate-400 hover:text-emerald-600 hover:bg-emerald-50 rounded-lg transition-colors"
                                title="Download GST Invoice"
                              >
                                <FileText className="w-5 h-5" />
                              </button>
                            )}
                            {user.role === 'VENDOR_ADMIN' && order.status === 'PAID' && (
                              <button 
                                onClick={() => updateOrderStatus(order.id, 'SHIPPED')}
                                className="p-2 text-slate-400 hover:text-blue-600 hover:bg-blue-50 rounded-lg transition-colors"
                                title="Mark as Shipped"
                              >
                                <Truck className="w-5 h-5" />
                              </button>
                            )}
                            {user.role === 'FACILITY_ADMIN' && order.status === 'PENDING_PAYMENT' && (
                              <button 
                                onClick={() => updateOrderStatus(order.id, 'PAID')}
                                className="p-2 text-slate-400 hover:text-emerald-600 hover:bg-emerald-50 rounded-lg transition-colors"
                                title="Simulate Payment"
                              >
                                <IndianRupee className="w-5 h-5" />
                              </button>
                            )}
                          </td>
                        </tr>
                      ))}
                      {orders.length === 0 && (
                        <tr>
                          <td colSpan={5} className="p-8 text-center text-slate-500">
                            No orders found.
                          </td>
                        </tr>
                      )}
                    </tbody>
                  </table>
                </div>
              </div>
            </motion.div>
          )}

          {activeTab === 'audit' && (
            <motion.div
              initial={{ opacity: 0, y: 10 }}
              animate={{ opacity: 1, y: 0 }}
            >
              <div className="bg-white rounded-3xl shadow-sm border border-slate-200 overflow-hidden">
                <div className="overflow-x-auto">
                  <table className="w-full text-left border-collapse">
                    <thead>
                      <tr className="bg-slate-50 text-slate-500 text-xs uppercase tracking-wider">
                        <th className="p-4 font-bold border-b border-slate-200">Timestamp</th>
                        <th className="p-4 font-bold border-b border-slate-200">Actor Role</th>
                        <th className="p-4 font-bold border-b border-slate-200">Action</th>
                        <th className="p-4 font-bold border-b border-slate-200">Object Type</th>
                        <th className="p-4 font-bold border-b border-slate-200">Object ID</th>
                        <th className="p-4 font-bold border-b border-slate-200">IP Address</th>
                      </tr>
                    </thead>
                    <tbody className="text-sm">
                      {auditLogs.map((log) => (
                        <tr key={log.id} className="border-b border-slate-100 hover:bg-slate-50/50 transition-colors">
                          <td className="p-4 text-slate-600">{new Date(log.created_at).toLocaleString()}</td>
                          <td className="p-4 font-medium text-slate-900">{log.role}</td>
                          <td className="p-4">
                            <span className="px-2 py-1 bg-slate-100 text-slate-700 rounded-md text-xs font-bold uppercase tracking-wider">
                              {log.action}
                            </span>
                          </td>
                          <td className="p-4 text-slate-600">{log.object_type}</td>
                          <td className="p-4 font-mono text-slate-900">{log.object_id || '-'}</td>
                          <td className="p-4 font-mono text-slate-500 text-xs">{log.ip_address}</td>
                        </tr>
                      ))}
                      {auditLogs.length === 0 && (
                        <tr>
                          <td colSpan={6} className="p-8 text-center text-slate-500">
                            No audit logs available.
                          </td>
                        </tr>
                      )}
                    </tbody>
                  </table>
                </div>
              </div>
            </motion.div>
          )}

        </div>
      </main>
    </div>
  );
}
