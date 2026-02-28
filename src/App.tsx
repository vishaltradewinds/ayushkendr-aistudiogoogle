import { Activity, LayoutDashboard, ShoppingCart, Users, Settings, ShieldCheck, Package, IndianRupee, TrendingUp, RefreshCw, Trash2, CheckCircle2, FileText, Truck, FileSearch, Globe, ChevronDown, Filter, Search, Building2, Star, Edit2, X, Plus, Minus, UserCircle, Lock } from 'lucide-react';
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
  vendor_name?: string;
  vendor_rating?: number;
  stock?: number;
  description?: string;
  specifications?: string; // JSON string
  images?: string; // JSON string
}

interface Review {
  id: number;
  product_id: number;
  user_id: number;
  user_email: string;
  rating: number;
  comment: string;
  created_at: string;
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

interface CartItem {
  product: Product;
  quantity: number;
}

interface User {
  id: number;
  email: string;
  role: string;
  is_active: number;
  created_at: string;
  org_name?: string;
}

const COLORS = ['#10b981', '#3b82f6', '#f59e0b', '#ef4444', '#6366f1'];

export default function App() {
  const [activeTab, setActiveTab] = useState('home');
  const [analytics, setAnalytics] = useState<AnalyticsData | null>(null);
  const [orders, setOrders] = useState<Order[]>([]);
  const [products, setProducts] = useState<Product[]>([]);
  const [auditLogs, setAuditLogs] = useState<AuditLog[]>([]);
  const [users, setUsers] = useState<User[]>([]);
  const [userProfile, setUserProfile] = useState<User | null>(null);
  const [selectedProductId, setSelectedProductId] = useState<number | null>(null);
  const [productReviews, setProductReviews] = useState<Review[]>([]);
  const [loading, setLoading] = useState(true);
  const [search, setSearch] = useState('');
  const [categoryFilter, setCategoryFilter] = useState('All');
  const [availabilityFilter, setAvailabilityFilter] = useState('All');
  const [ratingFilter, setRatingFilter] = useState(0);
  const [editingProduct, setEditingProduct] = useState<number | null>(null);
  const [cart, setCart] = useState<CartItem[]>([]);
  const [productQuantities, setProductQuantities] = useState<Record<number, number>>({});
  const [ordersPage, setOrdersPage] = useState(1);
  const [ordersTotalPages, setOrdersTotalPages] = useState(1);
  const ordersLimit = 10;

  const [user, setUser] = useState<{ email: string; role: string; token: string; org_id?: number } | null>(() => {
    const saved = localStorage.getItem('ayush_user');
    return saved ? JSON.parse(saved) : null;
  });
  const [authMode, setAuthMode] = useState<'login' | 'register'>('login');
  const [showLanding, setShowLanding] = useState(true);

  // Role-based navigation logic
  useEffect(() => {
    if (user) {
      const allowedTabs = [
        { id: 'home', roles: ['SUPER_ADMIN', 'COMPANY_ADMIN', 'FACILITY_ADMIN', 'VENDOR_ADMIN', 'GOVERNMENT_VIEW', 'ADMIN_VIEW'] },
        { id: 'products', roles: ['SUPER_ADMIN', 'COMPANY_ADMIN', 'FACILITY_ADMIN', 'VENDOR_ADMIN'] },
        { id: 'cart', roles: ['FACILITY_ADMIN'] },
        { id: 'orders', roles: ['SUPER_ADMIN', 'COMPANY_ADMIN', 'FACILITY_ADMIN', 'VENDOR_ADMIN'] },
        { id: 'audit', roles: ['SUPER_ADMIN', 'GOVERNMENT_VIEW'] },
      ].filter(t => t.roles.includes(user.role)).map(t => t.id);

      // Security guard: if current tab is not allowed, redirect to first allowed tab
      if (!allowedTabs.includes(activeTab)) {
        setActiveTab(allowedTabs[0] || 'home');
      }
    }
  }, [user, activeTab]);

  // Initial redirection upon login
  useEffect(() => {
    if (user) {
      const hasRedirected = sessionStorage.getItem('ayush_redirected');
      if (!hasRedirected) {
        const roleToTab: Record<string, string> = {
          'SUPER_ADMIN': 'home',
          'COMPANY_ADMIN': 'home',
          'VENDOR_ADMIN': 'home',
          'FACILITY_ADMIN': 'products',
          'GOVERNMENT_VIEW': 'audit',
          'ADMIN_VIEW': 'home'
        };
        setActiveTab(roleToTab[user.role] || 'home');
        sessionStorage.setItem('ayush_redirected', 'true');
      }
    } else {
      sessionStorage.removeItem('ayush_redirected');
    }
  }, [user]);

  const fetchOrders = async () => {
    if (!user) return;
    try {
      const headers = { Authorization: `Bearer ${user.token}` };
      const res = await fetch(`/api/orders?page=${ordersPage}&limit=${ordersLimit}`, { headers });
      if (res.ok) {
        const data = await res.json();
        setOrders(data.data);
        setOrdersTotalPages(data.totalPages);
      }
    } catch (error) {
      console.error('Failed to fetch orders:', error);
    }
  };

  useEffect(() => {
    fetchOrders();
  }, [ordersPage, user]);

  const fetchData = async () => {
    if (!user) return;
    setLoading(true);
    try {
      const headers = { Authorization: `Bearer ${user.token}` };
      
      const [productsRes, analyticsRes] = await Promise.all([
        fetch('/api/products', { headers }),
        fetch('/api/analytics/summary', { headers })
      ]);

      if (productsRes.ok) setProducts(await productsRes.json());
      if (analyticsRes.ok) setAnalytics(await analyticsRes.json());

      const [meRes, usersRes] = await Promise.all([
        fetch('/api/auth/me', { headers }),
        ['SUPER_ADMIN', 'COMPANY_ADMIN'].includes(user.role) ? fetch('/api/users', { headers }) : Promise.resolve(null)
      ]);

      if (meRes.ok) setUserProfile(await meRes.json());
      if (usersRes && usersRes.ok) setUsers(await usersRes.json());

      if (['SUPER_ADMIN', 'GOVERNMENT_VIEW'].includes(user.role)) {
        const auditRes = await fetch('/api/audit', { headers });
        if (auditRes.ok) setAuditLogs(await auditRes.json());
      }
      
      await fetchOrders();
    } catch (error) {
      console.error('Failed to fetch data:', error);
    } finally {
      setLoading(false);
    }
  };

  const toggleUserStatus = async (userId: number, currentStatus: number) => {
    const res = await fetch(`/api/users/${userId}/status`, {
      method: 'PUT',
      headers: { 
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${user?.token}`
      },
      body: JSON.stringify({ is_active: currentStatus === 1 ? 0 : 1 })
    });
    if (res.ok) {
      fetchData();
    }
  };

  const addUser = async (e: React.FormEvent<HTMLFormElement>) => {
    e.preventDefault();
    const form = e.currentTarget;
    const formData = new FormData(form);
    const res = await fetch('/api/users', {
      method: 'POST',
      headers: { 
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${user?.token}`
      },
      body: JSON.stringify({
        email: formData.get('email'),
        password: formData.get('password'),
        role: formData.get('role'),
        org_id: Number(formData.get('org_id') || user?.org_id)
      })
    });
    if (res.ok) {
      form.reset();
      fetchData();
      alert('User created successfully');
    } else {
      const data = await res.json();
      alert(data.error || 'Failed to create user');
    }
  };

  const changePassword = async (e: React.FormEvent<HTMLFormElement>) => {
    e.preventDefault();
    const form = e.currentTarget;
    const formData = new FormData(form);
    const currentPassword = formData.get('currentPassword');
    const newPassword = formData.get('newPassword');
    const confirmPassword = formData.get('confirmPassword');

    if (newPassword !== confirmPassword) {
      alert('New passwords do not match');
      return;
    }

    try {
      const res = await fetch('/api/auth/change-password', {
        method: 'POST',
        headers: { 
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${user?.token}`
        },
        body: JSON.stringify({ currentPassword, newPassword })
      });

      if (res.ok) {
        alert('Password changed successfully');
        form.reset();
      } else {
        const data = await res.json();
        alert(data.error || 'Failed to change password');
      }
    } catch (error) {
      alert('An error occurred');
    }
  };

  useEffect(() => {
    if (user) {
      fetchData();
    }
  }, [user]);

  const fetchProductReviews = async (productId: number) => {
    try {
      const res = await fetch(`/api/products/${productId}/reviews`, {
        headers: { Authorization: `Bearer ${user?.token}` }
      });
      if (res.ok) {
        setProductReviews(await res.json());
      }
    } catch (error) {
      console.error('Failed to fetch reviews:', error);
    }
  };

  const submitReview = async (e: React.FormEvent<HTMLFormElement>, productId: number) => {
    e.preventDefault();
    const form = e.currentTarget;
    const formData = new FormData(form);
    try {
      const res = await fetch(`/api/products/${productId}/reviews`, {
        method: 'POST',
        headers: { 
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${user?.token}`
        },
        body: JSON.stringify({
          rating: Number(formData.get('rating')),
          comment: formData.get('comment')
        })
      });
      if (res.ok) {
        form.reset();
        fetchProductReviews(productId);
      }
    } catch (error) {
      console.error('Failed to submit review:', error);
    }
  };

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
    sessionStorage.removeItem('ayush_redirected');
    setUser(null);
    setShowLanding(true);
    setCart([]);
  };

  const updateProductQuantity = (productId: number, delta: number) => {
    setProductQuantities(prev => ({
      ...prev,
      [productId]: Math.max(1, (prev[productId] || 1) + delta)
    }));
  };

  const addToCart = (product: Product) => {
    const quantity = productQuantities[product.id] || 1;
    setCart(prev => {
      const existing = prev.find(item => item.product.id === product.id);
      if (existing) {
        return prev.map(item => 
          item.product.id === product.id 
            ? { ...item, quantity: item.quantity + quantity } 
            : item
        );
      }
      return [...prev, { product, quantity }];
    });
    setProductQuantities(prev => ({ ...prev, [product.id]: 1 }));
    alert(`${quantity} x ${product.name} added to cart!`);
  };

  const removeFromCart = (productId: number) => {
    setCart(prev => prev.filter(item => item.product.id !== productId));
  };

  const updateCartQuantity = (productId: number, quantity: number) => {
    if (quantity <= 0) {
      removeFromCart(productId);
      return;
    }
    setCart(prev => prev.map(item => 
      item.product.id === productId ? { ...item, quantity } : item
    ));
  };

  const checkout = async () => {
    if (cart.length === 0) return;
    
    setLoading(true);
    try {
      for (const item of cart) {
        await fetch('/api/orders', {
          method: 'POST',
          headers: { 
            'Content-Type': 'application/json',
            'Authorization': `Bearer ${user?.token}`
          },
          body: JSON.stringify({ product_id: item.product.id, amount: item.quantity })
        });
      }
      setCart([]);
      setActiveTab('orders');
      fetchData();
      alert('All orders placed successfully!');
    } catch (error) {
      alert('Failed to complete checkout');
    } finally {
      setLoading(false);
    }
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
        price: Number(formData.get('price')),
        stock: Number(formData.get('stock') || 10),
        description: formData.get('description'),
        specifications: formData.get('specifications'),
        images: formData.get('images')
      })
    });
    if (res.ok) {
      form.reset();
      fetchData();
    }
  };

  const deleteProduct = async (productId: number) => {
    if (!confirm('Are you sure you want to delete this product?')) return;
    const res = await fetch(`/api/products/${productId}`, {
      method: 'DELETE',
      headers: { Authorization: `Bearer ${user?.token}` }
    });
    if (res.ok) {
      fetchData();
    } else {
      const data = await res.json();
      alert(data.error || 'Failed to delete product');
    }
  };

  const updateProduct = async (e: React.FormEvent<HTMLFormElement>, productId: number) => {
    e.preventDefault();
    const formData = new FormData(e.currentTarget);
    const res = await fetch(`/api/products/${productId}`, {
      method: 'PUT',
      headers: { 
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${user?.token}`
      },
      body: JSON.stringify({
        name: formData.get('name'),
        category: formData.get('category'),
        price: Number(formData.get('price')),
        stock: Number(formData.get('stock')),
        description: formData.get('description'),
        specifications: formData.get('specifications'),
        images: formData.get('images')
      })
    });
    if (res.ok) {
      setEditingProduct(null);
      fetchData();
    } else {
      const data = await res.json();
      alert(data.error || 'Failed to update product');
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

  const filteredProducts = products.filter(p => {
    const matchesSearch = 
      p.name.toLowerCase().includes(search.toLowerCase()) ||
      p.category.toLowerCase().includes(search.toLowerCase()) ||
      (p.vendor_name || '').toLowerCase().includes(search.toLowerCase());
    
    const matchesCategory = categoryFilter === 'All' || p.category === categoryFilter;
    
    const matchesAvailability = 
      availabilityFilter === 'All' || 
      (availabilityFilter === 'In Stock' && (p.stock || 0) > 0) ||
      (availabilityFilter === 'Out of Stock' && (p.stock || 0) === 0);

    const matchesRating = (p.vendor_rating || 0) >= ratingFilter;
    
    return matchesSearch && matchesCategory && matchesAvailability && matchesRating;
  });

  const categories = ['All', ...Array.from(new Set(products.map(p => p.category)))];

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
    { id: 'cart', icon: ShoppingCart, label: 'Shopping Cart', roles: ['FACILITY_ADMIN'] },
    { id: 'users', icon: Users, label: 'User Management', roles: ['SUPER_ADMIN', 'COMPANY_ADMIN'] },
    { id: 'orders', icon: IndianRupee, label: 'Procurement Log', roles: ['SUPER_ADMIN', 'COMPANY_ADMIN', 'FACILITY_ADMIN', 'VENDOR_ADMIN'] },
    { id: 'audit', icon: FileSearch, label: 'Audit Trail', roles: ['SUPER_ADMIN', 'GOVERNMENT_VIEW'] },
    { id: 'profile', icon: UserCircle, label: 'User Profile', roles: ['SUPER_ADMIN', 'COMPANY_ADMIN', 'FACILITY_ADMIN', 'VENDOR_ADMIN', 'GOVERNMENT_VIEW', 'ADMIN_VIEW'] },
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
                "w-full flex items-center gap-3 px-4 py-3 rounded-xl text-sm font-medium transition-colors text-left relative",
                activeTab === item.id 
                  ? "bg-emerald-500/10 text-emerald-400" 
                  : "hover:bg-slate-800 hover:text-white"
              )}
            >
              <item.icon className="w-5 h-5" />
              {item.label}
              {item.id === 'cart' && cart.length > 0 && (
                <span className="absolute right-4 top-1/2 -translate-y-1/2 bg-emerald-500 text-white text-[10px] font-bold px-1.5 py-0.5 rounded-full min-w-[18px] text-center">
                  {cart.reduce((acc, item) => acc + item.quantity, 0)}
                </span>
              )}
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
                {activeTab === 'cart' && "Review and manage your selected medical supplies."}
                {activeTab === 'users' && "Manage system users and access permissions."}
                {activeTab === 'profile' && "View your account details and manage security."}
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
          {activeTab === 'home' && analytics && (
            <motion.div
              initial={{ opacity: 0, y: 10 }}
              animate={{ opacity: 1, y: 0 }}
              className="space-y-8"
            >
              {['SUPER_ADMIN', 'COMPANY_ADMIN'].includes(user.role) && (
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
              )}

              {user.role === 'GOVERNMENT_VIEW' && (
                <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
                  <div className="bg-white p-6 rounded-3xl shadow-sm border border-slate-200 flex items-center gap-4">
                    <div className="bg-amber-50 text-amber-600 p-4 rounded-2xl">
                      <ShieldCheck className="w-8 h-8" />
                    </div>
                    <div>
                      <p className="text-sm font-bold text-slate-500 uppercase tracking-wider">Tax Revenue (GST)</p>
                      <p className="text-3xl font-black text-slate-900">₹{(analytics.gst_collected || 0).toLocaleString()}</p>
                    </div>
                  </div>
                  <div className="bg-white p-6 rounded-3xl shadow-sm border border-slate-200 flex items-center gap-4">
                    <div className="bg-emerald-50 text-emerald-600 p-4 rounded-2xl">
                      <TrendingUp className="w-8 h-8" />
                    </div>
                    <div>
                      <p className="text-sm font-bold text-slate-500 uppercase tracking-wider">Transaction Volume</p>
                      <p className="text-3xl font-black text-slate-900">₹{(analytics.total_revenue || 0).toLocaleString()}</p>
                    </div>
                  </div>
                  <div className="bg-white p-6 rounded-3xl shadow-sm border border-slate-200 flex items-center gap-4">
                    <div className="bg-blue-50 text-blue-600 p-4 rounded-2xl">
                      <Activity className="w-8 h-8" />
                    </div>
                    <div>
                      <p className="text-sm font-bold text-slate-500 uppercase tracking-wider">Orders Processed</p>
                      <p className="text-3xl font-black text-slate-900">{analytics.total_orders}</p>
                    </div>
                  </div>
                </div>
              )}

              {user.role === 'ADMIN_VIEW' && (
                <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
                  <div className="bg-white p-6 rounded-3xl shadow-sm border border-slate-200 flex items-center gap-4">
                    <div className="bg-blue-50 text-blue-600 p-4 rounded-2xl">
                      <ShoppingCart className="w-8 h-8" />
                    </div>
                    <div>
                      <p className="text-sm font-bold text-slate-500 uppercase tracking-wider">Operational Volume</p>
                      <p className="text-3xl font-black text-slate-900">{analytics.total_orders}</p>
                    </div>
                  </div>
                  <div className="bg-white p-6 rounded-3xl shadow-sm border border-slate-200 flex items-center gap-4">
                    <div className="bg-emerald-50 text-emerald-600 p-4 rounded-2xl">
                      <IndianRupee className="w-8 h-8" />
                    </div>
                    <div>
                      <p className="text-sm font-bold text-slate-500 uppercase tracking-wider">Platform GMV</p>
                      <p className="text-3xl font-black text-slate-900">₹{(analytics.total_revenue || 0).toLocaleString()}</p>
                    </div>
                  </div>
                  <div className="bg-white p-6 rounded-3xl shadow-sm border border-slate-200 flex items-center gap-4">
                    <div className="bg-purple-50 text-purple-600 p-4 rounded-2xl">
                      <Users className="w-8 h-8" />
                    </div>
                    <div>
                      <p className="text-sm font-bold text-slate-500 uppercase tracking-wider">Active Users</p>
                      <p className="text-3xl font-black text-slate-900">System Wide</p>
                    </div>
                  </div>
                </div>
              )}

              {user.role === 'VENDOR_ADMIN' && (
                <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
                  <div className="bg-white p-6 rounded-3xl shadow-sm border border-slate-200 flex items-center gap-4">
                    <div className="bg-blue-50 text-blue-600 p-4 rounded-2xl">
                      <ShoppingCart className="w-8 h-8" />
                    </div>
                    <div>
                      <p className="text-sm font-bold text-slate-500 uppercase tracking-wider">My Orders</p>
                      <p className="text-3xl font-black text-slate-900">{analytics.total_orders}</p>
                    </div>
                  </div>
                  <div className="bg-white p-6 rounded-3xl shadow-sm border border-slate-200 flex items-center gap-4">
                    <div className="bg-emerald-50 text-emerald-600 p-4 rounded-2xl">
                      <IndianRupee className="w-8 h-8" />
                    </div>
                    <div>
                      <p className="text-sm font-bold text-slate-500 uppercase tracking-wider">My Revenue</p>
                      <p className="text-3xl font-black text-slate-900">₹{(analytics.total_revenue || 0).toLocaleString()}</p>
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
                      <p className="text-3xl font-black text-slate-900">{analytics.total_orders}</p>
                    </div>
                  </div>
                  <div className="bg-white p-6 rounded-3xl shadow-sm border border-slate-200 flex items-center gap-4">
                    <div className="bg-emerald-50 text-emerald-600 p-4 rounded-2xl">
                      <IndianRupee className="w-8 h-8" />
                    </div>
                    <div>
                      <p className="text-sm font-bold text-slate-500 uppercase tracking-wider">Total Spent</p>
                      <p className="text-3xl font-black text-slate-900">₹{(analytics.total_revenue || 0).toLocaleString()}</p>
                    </div>
                  </div>
                  <div className="bg-white p-6 rounded-3xl shadow-sm border border-slate-200 flex items-center gap-4">
                    <div className="bg-amber-50 text-amber-600 p-4 rounded-2xl">
                      <RefreshCw className="w-8 h-8" />
                    </div>
                    <div>
                      <p className="text-sm font-bold text-slate-500 uppercase tracking-wider">Pending Deliveries</p>
                      <p className="text-3xl font-black text-slate-900">{orders.filter(o => o.status !== 'DELIVERED' && o.status !== 'CANCELLED').length}</p>
                    </div>
                  </div>
                </div>
              )}

              {/* Shared Charts Section */}
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
                          {analytics.status_distribution.map((entry: any, index: number) => (
                            <Cell key={`cell-${index}`} fill={COLORS[index % COLORS.length]} />
                          ))}
                        </Pie>
                        <Tooltip />
                        <Legend />
                      </PieChart>
                    </ResponsiveContainer>
                  </div>
                </div>

                {user.role !== 'FACILITY_ADMIN' && (
                  <div className="bg-white p-6 rounded-3xl shadow-sm border border-slate-200">
                    <h3 className="text-lg font-bold text-slate-900 mb-6">Revenue Trend (Last 7 Days)</h3>
                    <div className="h-72">
                      <ResponsiveContainer width="100%" height="100%">
                        <BarChart data={analytics.revenue_trend}>
                          <CartesianGrid strokeDasharray="3 3" vertical={false} stroke="#e2e8f0" />
                          <XAxis dataKey="name" axisLine={false} tickLine={false} tick={{fill: '#64748b', fontSize: 12}} dy={10} />
                          <YAxis axisLine={false} tickLine={false} tick={{fill: '#64748b', fontSize: 12}} dx={-10} tickFormatter={(value) => `₹${value/1000}k`} />
                          <Tooltip 
                            cursor={{fill: '#f1f5f9'}}
                            contentStyle={{borderRadius: '12px', border: 'none', boxShadow: '0 4px 6px -1px rgb(0 0 0 / 0.1)'}}
                          />
                          <Bar dataKey="revenue" fill="#10b981" radius={[4, 4, 0, 0]} maxBarSize={40} />
                        </BarChart>
                      </ResponsiveContainer>
                    </div>
                  </div>
                )}
              </div>
            </motion.div>
          )}

          {activeTab === 'products' && (
            <motion.div
              initial={{ opacity: 0, y: 10 }}
              animate={{ opacity: 1, y: 0 }}
              className="space-y-6"
            >
              {selectedProductId ? (
                <div className="space-y-8">
                  <button 
                    onClick={() => setSelectedProductId(null)}
                    className="flex items-center gap-2 text-slate-500 hover:text-slate-900 font-bold transition-colors"
                  >
                    <X className="w-5 h-5" /> Back to Catalogue
                  </button>

                  {(() => {
                    const product = products.find(p => p.id === selectedProductId);
                    if (!product) return null;
                    
                    let specs = {};
                    try { specs = product.specifications ? JSON.parse(product.specifications) : {}; } catch(e) { console.error("Invalid specs JSON", e); }
                    
                    let images = [];
                    try { images = product.images ? JSON.parse(product.images) : []; } catch(e) { console.error("Invalid images JSON", e); }
                    
                    return (
                      <div className="grid grid-cols-1 lg:grid-cols-2 gap-12">
                        {/* Product Images */}
                        <div className="space-y-4">
                          <div className="aspect-square bg-white rounded-3xl border border-slate-200 overflow-hidden flex items-center justify-center p-8">
                            {images[0] ? (
                              <img src={images[0]} alt={product.name} className="max-w-full max-h-full object-contain" />
                            ) : (
                              <Package className="w-32 h-32 text-slate-200" />
                            )}
                          </div>
                          {images.length > 1 && (
                            <div className="grid grid-cols-4 gap-4">
                              {images.slice(1).map((img: string, idx: number) => (
                                <div key={idx} className="aspect-square bg-white rounded-xl border border-slate-200 overflow-hidden p-2">
                                  <img src={img} alt={`${product.name} ${idx + 2}`} className="w-full h-full object-contain" />
                                </div>
                              ))}
                            </div>
                          )}
                        </div>

                        {/* Product Info */}
                        <div className="space-y-8">
                          <div>
                            <span className="text-xs font-black text-emerald-600 bg-emerald-50 px-3 py-1 rounded-full uppercase tracking-widest">{product.category}</span>
                            <h2 className="text-4xl font-black text-slate-900 mt-4">{product.name}</h2>
                            <div className="flex items-center gap-4 mt-4">
                              <div className="flex items-center gap-1 text-amber-500">
                                <Star className="w-5 h-5 fill-current" />
                                <span className="text-lg font-bold">{product.vendor_rating}</span>
                              </div>
                              <span className="text-slate-300">|</span>
                              <div className="flex items-center gap-2 text-slate-500">
                                <Building2 className="w-5 h-5" />
                                <span className="text-lg font-medium">{product.vendor_name}</span>
                              </div>
                            </div>
                          </div>

                          <div className="bg-white p-6 rounded-3xl border border-slate-200 shadow-sm">
                            <p className="text-xs font-bold text-slate-400 uppercase tracking-tighter mb-1">Price per unit</p>
                            <div className="flex items-baseline gap-2">
                              <span className="text-4xl font-black text-slate-900">₹{product.price.toLocaleString()}</span>
                              <span className="text-slate-400 text-sm font-medium">+ GST as applicable</span>
                            </div>
                            
                            <div className="mt-6 pt-6 border-t border-slate-100">
                              <div className="flex items-center justify-between mb-4">
                                <span className={cn(
                                  "text-sm font-bold px-3 py-1 rounded-full",
                                  (product.stock || 0) > 0 ? "bg-emerald-100 text-emerald-700" : "bg-red-100 text-red-700"
                                )}>
                                  {(product.stock || 0) > 0 ? `${product.stock} units available` : 'Out of stock'}
                                </span>
                              </div>

                              {user.role === 'FACILITY_ADMIN' && (
                                <div className="flex gap-4">
                                  <div className="flex items-center bg-slate-100 rounded-2xl p-1">
                                    <button 
                                      onClick={() => setProductQuantities(prev => ({...prev, [product.id]: Math.max(1, (prev[product.id] || 1) - 1)}))}
                                      className="p-3 hover:bg-white rounded-xl transition-colors"
                                    >
                                      <Minus className="w-4 h-4" />
                                    </button>
                                    <span className="w-12 text-center font-bold">{productQuantities[product.id] || 1}</span>
                                    <button 
                                      onClick={() => setProductQuantities(prev => ({...prev, [product.id]: (prev[product.id] || 1) + 1}))}
                                      className="p-3 hover:bg-white rounded-xl transition-colors"
                                    >
                                      <Plus className="w-4 h-4" />
                                    </button>
                                  </div>
                                  <button 
                                    onClick={() => addToCart(product)}
                                    disabled={(product.stock || 0) <= 0}
                                    className="flex-1 bg-emerald-600 hover:bg-emerald-700 disabled:bg-slate-300 text-white py-4 rounded-2xl font-bold transition-all shadow-lg shadow-emerald-600/20 flex items-center justify-center gap-2"
                                  >
                                    <ShoppingCart className="w-5 h-5" /> Add to Cart
                                  </button>
                                </div>
                              )}
                            </div>
                          </div>

                          <div className="space-y-6">
                            <div>
                              <h3 className="text-lg font-bold text-slate-900 mb-3">Description</h3>
                              <p className="text-slate-600 leading-relaxed">
                                {product.description || "No description available for this product."}
                              </p>
                            </div>

                            {Object.keys(specs).length > 0 && (
                              <div>
                                <h3 className="text-lg font-bold text-slate-900 mb-3">Specifications</h3>
                                <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                                  {Object.entries(specs).map(([key, value]: [string, any]) => (
                                    <div key={key} className="bg-slate-50 p-4 rounded-2xl border border-slate-100">
                                      <p className="text-[10px] font-bold text-slate-400 uppercase tracking-wider">{key}</p>
                                      <p className="font-bold text-slate-900">{String(value)}</p>
                                    </div>
                                  ))}
                                </div>
                              </div>
                            )}
                          </div>

                          {/* Reviews Section */}
                          <div className="pt-12 border-t border-slate-200 space-y-8">
                            <div className="flex items-center justify-between">
                              <h3 className="text-2xl font-bold text-slate-900">Customer Reviews</h3>
                              <div className="flex items-center gap-2 text-amber-500">
                                <Star className="w-6 h-6 fill-current" />
                                <span className="text-xl font-black">{product.vendor_rating}</span>
                              </div>
                            </div>

                            {user.role === 'FACILITY_ADMIN' && (
                              <div className="bg-slate-50 p-6 rounded-3xl border border-slate-200">
                                <h4 className="font-bold text-slate-900 mb-4">Write a Review</h4>
                                <form onSubmit={(e) => submitReview(e, product.id)} className="space-y-4">
                                  <div>
                                    <label className="block text-xs font-bold text-slate-500 uppercase mb-2">Rating</label>
                                    <select name="rating" className="w-full p-3 bg-white border border-slate-200 rounded-xl outline-none focus:ring-2 focus:ring-emerald-500/20">
                                      <option value="5">5 Stars - Excellent</option>
                                      <option value="4">4 Stars - Good</option>
                                      <option value="3">3 Stars - Average</option>
                                      <option value="2">2 Stars - Poor</option>
                                      <option value="1">1 Star - Terrible</option>
                                    </select>
                                  </div>
                                  <div>
                                    <label className="block text-xs font-bold text-slate-500 uppercase mb-2">Comment</label>
                                    <textarea name="comment" rows={3} className="w-full p-3 bg-white border border-slate-200 rounded-xl outline-none focus:ring-2 focus:ring-emerald-500/20" placeholder="Share your experience with this product..."></textarea>
                                  </div>
                                  <button type="submit" className="bg-slate-900 text-white px-6 py-3 rounded-xl font-bold hover:bg-slate-800 transition-colors">
                                    Post Review
                                  </button>
                                </form>
                              </div>
                            )}

                            <div className="space-y-6">
                              {productReviews.map((review) => (
                                <div key={review.id} className="bg-white p-6 rounded-3xl border border-slate-100 shadow-sm">
                                  <div className="flex justify-between items-start mb-4">
                                    <div>
                                      <p className="font-bold text-slate-900">{review.user_email}</p>
                                      <div className="flex gap-1 text-amber-500 mt-1">
                                        {[...Array(5)].map((_, i) => (
                                          <Star key={i} className={cn("w-3 h-3", i < review.rating ? "fill-current" : "text-slate-200")} />
                                        ))}
                                      </div>
                                    </div>
                                    <span className="text-xs text-slate-400">{new Date(review.created_at).toLocaleDateString()}</span>
                                  </div>
                                  <p className="text-slate-600 italic">"{review.comment}"</p>
                                </div>
                              ))}
                              {productReviews.length === 0 && (
                                <p className="text-center text-slate-500 py-8">No reviews yet. Be the first to review!</p>
                              )}
                            </div>
                          </div>
                        </div>
                      </div>
                    );
                  })()}
                </div>
              ) : (
                <>
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
                    <div>
                      <label className="block text-sm font-bold text-slate-700 mb-2">Initial Stock</label>
                      <input 
                        name="stock" 
                        type="number" 
                        placeholder="10" 
                        required 
                        className="w-full p-3 bg-slate-50 border border-slate-200 rounded-xl outline-none focus:ring-2 focus:ring-emerald-500/20 focus:border-emerald-500 transition-all"
                      />
                    </div>
                    <div className="md:col-span-4">
                      <label className="block text-sm font-bold text-slate-700 mb-2">Description</label>
                      <textarea 
                        name="description" 
                        placeholder="Detailed product description..." 
                        className="w-full p-3 bg-slate-50 border border-slate-200 rounded-xl outline-none focus:ring-2 focus:ring-emerald-500/20 focus:border-emerald-500 transition-all"
                      ></textarea>
                    </div>
                    <div className="md:col-span-2">
                      <label className="block text-sm font-bold text-slate-700 mb-2">Specifications (JSON)</label>
                      <input 
                        name="specifications" 
                        type="text" 
                        placeholder='{"Power": "220V", "Weight": "50kg"}' 
                        className="w-full p-3 bg-slate-50 border border-slate-200 rounded-xl outline-none focus:ring-2 focus:ring-emerald-500/20 focus:border-emerald-500 transition-all"
                      />
                    </div>
                    <div className="md:col-span-2">
                      <label className="block text-sm font-bold text-slate-700 mb-2">Images (JSON Array of URLs)</label>
                      <input 
                        name="images" 
                        type="text" 
                        placeholder='["https://example.com/img1.jpg"]' 
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

              <div className="flex flex-col gap-6 mb-8">
                <div className="relative w-full">
                  <Search className="absolute left-4 top-1/2 -translate-y-1/2 w-5 h-5 text-slate-400" />
                  <input 
                    type="text"
                    placeholder="Search by name, category, or supplier..."
                    value={search}
                    onChange={(e) => setSearch(e.target.value)}
                    className="w-full pl-12 pr-4 py-4 bg-white border border-slate-200 rounded-2xl outline-none focus:ring-2 focus:ring-emerald-500/20 focus:border-emerald-500 transition-all shadow-sm"
                  />
                </div>
                
                <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
                  <div className="flex items-center gap-2">
                    <Filter className="w-5 h-5 text-slate-400" />
                    <select 
                      value={categoryFilter}
                      onChange={(e) => setCategoryFilter(e.target.value)}
                      className="flex-1 p-4 bg-white border border-slate-200 rounded-2xl outline-none focus:ring-2 focus:ring-emerald-500/20 focus:border-emerald-500 transition-all shadow-sm appearance-none cursor-pointer font-medium text-slate-700"
                    >
                      <option value="All">All Categories</option>
                      {categories.filter(c => c !== 'All').map(cat => (
                        <option key={cat} value={cat}>{cat}</option>
                      ))}
                    </select>
                  </div>

                  <div className="flex items-center gap-2">
                    <Package className="w-5 h-5 text-slate-400" />
                    <select 
                      value={availabilityFilter}
                      onChange={(e) => setAvailabilityFilter(e.target.value)}
                      className="flex-1 p-4 bg-white border border-slate-200 rounded-2xl outline-none focus:ring-2 focus:ring-emerald-500/20 focus:border-emerald-500 transition-all shadow-sm appearance-none cursor-pointer font-medium text-slate-700"
                    >
                      <option value="All">All Availability</option>
                      <option value="In Stock">In Stock</option>
                      <option value="Out of Stock">Out of Stock</option>
                    </select>
                  </div>

                  <div className="flex items-center gap-2">
                    <Star className="w-5 h-5 text-slate-400" />
                    <select 
                      value={ratingFilter}
                      onChange={(e) => setRatingFilter(Number(e.target.value))}
                      className="flex-1 p-4 bg-white border border-slate-200 rounded-2xl outline-none focus:ring-2 focus:ring-emerald-500/20 focus:border-emerald-500 transition-all shadow-sm appearance-none cursor-pointer font-medium text-slate-700"
                    >
                      <option value={0}>All Ratings</option>
                      <option value={4}>4+ Stars</option>
                      <option value={4.5}>4.5+ Stars</option>
                      <option value={4.8}>4.8+ Stars</option>
                    </select>
                  </div>
                </div>
              </div>

              <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
                {filteredProducts.map((product) => (
                  <div key={product.id} className="group bg-white p-6 rounded-3xl shadow-sm border border-slate-200 hover:shadow-xl hover:border-emerald-500/30 transition-all duration-300 flex flex-col relative">
                    {user.role === 'VENDOR_ADMIN' && product.vendor_id === user.org_id && !editingProduct && (
                      <button 
                        onClick={() => setEditingProduct(product.id)}
                        className="absolute top-4 right-4 p-2 text-slate-400 hover:text-emerald-600 hover:bg-emerald-50 rounded-full transition-all opacity-0 group-hover:opacity-100"
                        title="Edit Product"
                      >
                        <Edit2 className="w-4 h-4" />
                      </button>
                    )}

                    {editingProduct === product.id ? (
                      <form onSubmit={(e) => updateProduct(e, product.id)} className="space-y-4">
                        <div className="flex justify-between items-center mb-2">
                          <h3 className="text-sm font-bold text-slate-900 uppercase tracking-wider">Edit Product</h3>
                          <button 
                            type="button" 
                            onClick={() => setEditingProduct(null)}
                            className="p-1 text-slate-400 hover:text-red-500 rounded-md"
                          >
                            <X className="w-4 h-4" />
                          </button>
                        </div>
                        <div>
                          <label className="block text-[10px] font-bold text-slate-500 uppercase mb-1">Name</label>
                          <input 
                            name="name" 
                            defaultValue={product.name} 
                            required 
                            className="w-full p-2 bg-slate-50 border border-slate-200 rounded-lg text-sm outline-none focus:ring-2 focus:ring-emerald-500/20"
                          />
                        </div>
                        <div>
                          <label className="block text-[10px] font-bold text-slate-500 uppercase mb-1">Category</label>
                          <input 
                            name="category" 
                            defaultValue={product.category} 
                            required 
                            className="w-full p-2 bg-slate-50 border border-slate-200 rounded-lg text-sm outline-none focus:ring-2 focus:ring-emerald-500/20"
                          />
                        </div>
                        <div className="grid grid-cols-2 gap-2">
                          <div>
                            <label className="block text-[10px] font-bold text-slate-500 uppercase mb-1">Price (₹)</label>
                            <input 
                              name="price" 
                              type="number" 
                              defaultValue={product.price} 
                              required 
                              className="w-full p-2 bg-slate-50 border border-slate-200 rounded-lg text-sm outline-none focus:ring-2 focus:ring-emerald-500/20"
                            />
                          </div>
                          <div>
                            <label className="block text-[10px] font-bold text-slate-500 uppercase mb-1">Stock</label>
                            <input 
                              name="stock" 
                              type="number" 
                              defaultValue={product.stock} 
                              required 
                              className="w-full p-2 bg-slate-50 border border-slate-200 rounded-lg text-sm outline-none focus:ring-2 focus:ring-emerald-500/20"
                            />
                          </div>
                        </div>
                        <div>
                          <label className="block text-[10px] font-bold text-slate-500 uppercase mb-1">Description</label>
                          <textarea 
                            name="description" 
                            defaultValue={product.description} 
                            className="w-full p-2 bg-slate-50 border border-slate-200 rounded-lg text-sm outline-none focus:ring-2 focus:ring-emerald-500/20"
                          ></textarea>
                        </div>
                        <div>
                          <label className="block text-[10px] font-bold text-slate-500 uppercase mb-1">Specifications (JSON)</label>
                          <input 
                            name="specifications" 
                            defaultValue={product.specifications} 
                            className="w-full p-2 bg-slate-50 border border-slate-200 rounded-lg text-sm outline-none focus:ring-2 focus:ring-emerald-500/20"
                          />
                        </div>
                        <div>
                          <label className="block text-[10px] font-bold text-slate-500 uppercase mb-1">Images (JSON Array)</label>
                          <input 
                            name="images" 
                            defaultValue={product.images} 
                            className="w-full p-2 bg-slate-50 border border-slate-200 rounded-lg text-sm outline-none focus:ring-2 focus:ring-emerald-500/20"
                          />
                        </div>
                        <button 
                          type="submit"
                          className="w-full bg-emerald-600 hover:bg-emerald-700 text-white py-2 rounded-xl font-bold text-sm transition-colors mt-4"
                        >
                          Save Changes
                        </button>
                      </form>
                    ) : (
                      <>
                        <div className="flex justify-between items-start mb-4">
                          <div className="flex-1">
                            <div className="flex items-center gap-2">
                              <span className="text-[10px] font-black text-emerald-600 bg-emerald-50 px-2 py-1 rounded-md uppercase tracking-widest">{product.category}</span>
                            </div>
                            <h3 className="text-xl font-bold text-slate-900 mt-3 group-hover:text-emerald-600 transition-colors">{product.name}</h3>
                            <div className="flex items-center gap-2 mt-2">
                              <div className="flex items-center gap-1 text-amber-500">
                                <Star className="w-3.5 h-3.5 fill-current" />
                                <span className="text-xs font-bold">{product.vendor_rating}</span>
                              </div>
                              <span className="text-slate-300">|</span>
                              <div className="flex items-center gap-2 text-slate-500">
                                <Building2 className="w-3.5 h-3.5" />
                                <span className="text-xs font-medium">{product.vendor_name}</span>
                              </div>
                            </div>
                            <div className="mt-2">
                              <span className={cn(
                                "text-[10px] font-bold px-2 py-0.5 rounded-full",
                                (product.stock || 0) > 0 ? "bg-emerald-100 text-emerald-700" : "bg-red-100 text-red-700"
                              )}>
                                {(product.stock || 0) > 0 ? `${product.stock} in stock` : 'Out of stock'}
                              </span>
                            </div>
                          </div>
                          <div className="text-right">
                            <p className="text-xs font-bold text-slate-400 uppercase tracking-tighter">Price</p>
                            <p className="text-xl font-black text-slate-900">₹{product.price.toLocaleString()}</p>
                          </div>
                        </div>
                        
                        <div className="mt-auto pt-6 border-t border-slate-50 flex flex-col gap-3">
                          <button 
                            onClick={() => {
                              setSelectedProductId(product.id);
                              fetchProductReviews(product.id);
                            }}
                            className="w-full bg-slate-100 hover:bg-slate-200 text-slate-700 py-3 rounded-xl font-bold text-sm transition-colors"
                          >
                            View Details
                          </button>
                          {user.role === 'FACILITY_ADMIN' ? (
                            <div className="flex flex-col gap-3">
                              <div className="flex items-center justify-between bg-slate-50 p-2 rounded-2xl border border-slate-100">
                                <span className="text-xs font-bold text-slate-500 ml-2">Quantity</span>
                                <div className="flex items-center gap-3">
                                  <button 
                                    onClick={() => updateProductQuantity(product.id, -1)}
                                    className="w-8 h-8 flex items-center justify-center bg-white rounded-xl shadow-sm hover:text-emerald-600 transition-colors"
                                  >
                                    <Minus className="w-3.5 h-3.5" />
                                  </button>
                                  <span className="w-6 text-center font-bold text-slate-900">{productQuantities[product.id] || 1}</span>
                                  <button 
                                    onClick={() => updateProductQuantity(product.id, 1)}
                                    className="w-8 h-8 flex items-center justify-center bg-white rounded-xl shadow-sm hover:text-emerald-600 transition-colors"
                                  >
                                    <Plus className="w-3.5 h-3.5" />
                                  </button>
                                </div>
                              </div>
                              <button 
                                onClick={() => addToCart(product)}
                                className="w-full bg-slate-900 hover:bg-emerald-600 text-white py-4 rounded-2xl font-bold transition-all flex items-center justify-center gap-2 shadow-lg shadow-slate-900/10 hover:shadow-emerald-600/20"
                              >
                                <ShoppingCart className="w-5 h-5" />
                                Add to Cart
                              </button>
                            </div>
                          ) : user.role === 'VENDOR_ADMIN' && product.vendor_id === user.org_id ? (
                            <button 
                              onClick={() => deleteProduct(product.id)}
                              className="w-full bg-red-50 hover:bg-red-100 text-red-600 py-4 rounded-2xl font-bold transition-all flex items-center justify-center gap-2"
                            >
                              <Trash2 className="w-5 h-5" />
                              Remove from Catalogue
                            </button>
                          ) : (
                            <div className="flex items-center justify-between text-xs font-medium text-slate-400">
                              <span>Product ID: #{product.id}</span>
                              <span>Available for Procurement</span>
                            </div>
                          )}
                        </div>
                      </>
                    )}
                  </div>
                ))}
                {filteredProducts.length === 0 && (
                  <div className="col-span-full py-20 text-center">
                    <div className="bg-slate-100 w-16 h-16 rounded-full flex items-center justify-center mx-auto mb-4">
                      <Search className="w-8 h-8 text-slate-400" />
                    </div>
                    <h3 className="text-lg font-bold text-slate-900">No products found</h3>
                    <p className="text-slate-500">Try adjusting your search or filters to find what you're looking for.</p>
                  </div>
                )}
              </div>
            </>
          )}
        </motion.div>
      )}

          {activeTab === 'cart' && (
            <motion.div
              initial={{ opacity: 0, y: 10 }}
              animate={{ opacity: 1, y: 0 }}
              className="space-y-6"
            >
              <div className="bg-white rounded-3xl shadow-sm border border-slate-200 overflow-hidden">
                {cart.length === 0 ? (
                  <div className="p-20 text-center">
                    <div className="bg-slate-100 w-16 h-16 rounded-full flex items-center justify-center mx-auto mb-4">
                      <ShoppingCart className="w-8 h-8 text-slate-400" />
                    </div>
                    <h3 className="text-lg font-bold text-slate-900">Your cart is empty</h3>
                    <p className="text-slate-500 mb-6">Browse the catalogue to add medical supplies to your cart.</p>
                    <button 
                      onClick={() => setActiveTab('products')}
                      className="bg-slate-900 hover:bg-slate-800 text-white px-6 py-3 rounded-xl font-bold transition-colors"
                    >
                      Browse Catalogue
                    </button>
                  </div>
                ) : (
                  <div className="divide-y divide-slate-100">
                    <div className="p-6 bg-slate-50 border-b border-slate-200 flex justify-between items-center">
                      <h3 className="font-bold text-slate-900">Items in Cart ({cart.length})</h3>
                      <button 
                        onClick={() => setCart([])}
                        className="text-xs font-bold text-red-500 hover:text-red-600 transition-colors"
                      >
                        Clear All
                      </button>
                    </div>
                    {cart.map((item) => (
                      <div key={item.product.id} className="p-6 flex items-center gap-6">
                        <div className="flex-1">
                          <span className="text-[10px] font-black text-emerald-600 bg-emerald-50 px-2 py-1 rounded-md uppercase tracking-widest">{item.product.category}</span>
                          <h4 className="text-lg font-bold text-slate-900 mt-1">{item.product.name}</h4>
                          <p className="text-xs text-slate-500 mt-1">Supplier: {item.product.vendor_name}</p>
                        </div>
                        <div className="flex items-center gap-3 bg-slate-100 p-1 rounded-xl">
                          <button 
                            onClick={() => updateCartQuantity(item.product.id, item.quantity - 1)}
                            className="w-8 h-8 flex items-center justify-center bg-white rounded-lg shadow-sm hover:text-emerald-600 transition-colors font-bold"
                          >
                            -
                          </button>
                          <span className="w-8 text-center font-bold text-slate-900">{item.quantity}</span>
                          <button 
                            onClick={() => updateCartQuantity(item.product.id, item.quantity + 1)}
                            className="w-8 h-8 flex items-center justify-center bg-white rounded-lg shadow-sm hover:text-emerald-600 transition-colors font-bold"
                          >
                            +
                          </button>
                        </div>
                        <div className="w-32 text-right">
                          <p className="text-xs font-bold text-slate-400 uppercase tracking-tighter">Subtotal</p>
                          <p className="text-lg font-black text-slate-900">₹{(item.product.price * item.quantity).toLocaleString()}</p>
                        </div>
                        <button 
                          onClick={() => removeFromCart(item.product.id)}
                          className="p-2 text-slate-300 hover:text-red-500 transition-colors"
                        >
                          <Trash2 className="w-5 h-5" />
                        </button>
                      </div>
                    ))}
                    <div className="p-8 bg-slate-50 flex flex-col items-end gap-4">
                      <div className="text-right space-y-1">
                        <div className="flex justify-between gap-20 text-slate-500 text-sm">
                          <span>Subtotal</span>
                          <span>₹{cart.reduce((acc, item) => acc + (item.product.price * item.quantity), 0).toLocaleString()}</span>
                        </div>
                        <div className="flex justify-between gap-20 text-slate-500 text-sm">
                          <span>GST (18%)</span>
                          <span>₹{(cart.reduce((acc, item) => acc + (item.product.price * item.quantity), 0) * 0.18).toLocaleString()}</span>
                        </div>
                        <div className="flex justify-between gap-20 text-slate-900 text-xl font-black pt-2 border-t border-slate-200">
                          <span>Total</span>
                          <span>₹{(cart.reduce((acc, item) => acc + (item.product.price * item.quantity), 0) * 1.18).toLocaleString()}</span>
                        </div>
                      </div>
                      <button 
                        onClick={checkout}
                        disabled={loading}
                        className="bg-emerald-600 hover:bg-emerald-700 text-white px-12 py-4 rounded-2xl font-bold shadow-lg shadow-emerald-600/20 transition-all flex items-center gap-2 disabled:opacity-50"
                      >
                        {loading ? <RefreshCw className="w-5 h-5 animate-spin" /> : <CheckCircle2 className="w-5 h-5" />}
                        Confirm Procurement
                      </button>
                    </div>
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
                            <div className="flex flex-col gap-2">
                              <span className={cn(
                                "w-fit px-3 py-1 rounded-full text-[10px] font-bold uppercase tracking-wider",
                                order.status === 'DELIVERED' ? "bg-emerald-100 text-emerald-700" :
                                order.status === 'SHIPPED' ? "bg-blue-100 text-blue-700" :
                                order.status === 'PROCESSING' ? "bg-indigo-100 text-indigo-700" :
                                order.status === 'CANCELLED' ? "bg-red-100 text-red-700" :
                                "bg-amber-100 text-amber-700"
                              )}>
                                {order.status.replace('_', ' ')}
                              </span>
                              {order.status !== 'CANCELLED' && (
                                <div className="flex items-center gap-1 mt-1" title="Order Tracking Progress">
                                  {[1, 2, 3, 4].map(step => {
                                    const currentStep = order.status === 'PENDING' ? 1 : order.status === 'PROCESSING' ? 2 : order.status === 'SHIPPED' ? 3 : order.status === 'DELIVERED' ? 4 : 0;
                                    return (
                                      <div key={step} className={cn(
                                        "h-1.5 w-8 rounded-full transition-colors",
                                        currentStep >= step ? "bg-emerald-500" : "bg-slate-200"
                                      )} />
                                    );
                                  })}
                                </div>
                              )}
                            </div>
                          </td>
                          <td className="p-4 flex gap-2">
                            {(order.status === 'SHIPPED' || order.status === 'DELIVERED') && (
                              <button 
                                onClick={() => downloadInvoice(order.id)}
                                className="p-2 text-slate-400 hover:text-emerald-600 hover:bg-emerald-50 rounded-lg transition-colors"
                                title="Download GST Invoice"
                              >
                                <FileText className="w-5 h-5" />
                              </button>
                            )}
                            {user.role === 'VENDOR_ADMIN' && (
                              <div className="flex gap-1">
                                {order.status === 'PENDING' && (
                                  <button 
                                    onClick={() => updateOrderStatus(order.id, 'PROCESSING')}
                                    className="p-2 text-slate-400 hover:text-indigo-600 hover:bg-indigo-50 rounded-lg transition-colors"
                                    title="Start Processing"
                                  >
                                    <RefreshCw className="w-5 h-5" />
                                  </button>
                                )}
                                {order.status === 'PROCESSING' && (
                                  <button 
                                    onClick={() => updateOrderStatus(order.id, 'SHIPPED')}
                                    className="p-2 text-slate-400 hover:text-blue-600 hover:bg-blue-50 rounded-lg transition-colors"
                                    title="Mark as Shipped"
                                  >
                                    <Truck className="w-5 h-5" />
                                  </button>
                                )}
                                {order.status === 'SHIPPED' && (
                                  <button 
                                    onClick={() => updateOrderStatus(order.id, 'DELIVERED')}
                                    className="p-2 text-slate-400 hover:text-emerald-600 hover:bg-emerald-50 rounded-lg transition-colors"
                                    title="Mark as Delivered"
                                  >
                                    <CheckCircle2 className="w-5 h-5" />
                                  </button>
                                )}
                                {['PENDING', 'PROCESSING'].includes(order.status) && (
                                  <button 
                                    onClick={() => updateOrderStatus(order.id, 'CANCELLED')}
                                    className="p-2 text-slate-400 hover:text-red-600 hover:bg-red-50 rounded-lg transition-colors"
                                    title="Cancel Order"
                                  >
                                    <X className="w-5 h-5" />
                                  </button>
                                )}
                              </div>
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
                {ordersTotalPages > 1 && (
                  <div className="p-4 border-t border-slate-200 flex items-center justify-between bg-slate-50">
                    <span className="text-sm text-slate-500 font-medium">
                      Page {ordersPage} of {ordersTotalPages}
                    </span>
                    <div className="flex gap-2">
                      <button 
                        onClick={() => setOrdersPage(p => Math.max(1, p - 1))}
                        disabled={ordersPage === 1}
                        className="px-4 py-2 text-sm font-bold text-slate-700 bg-white border border-slate-200 rounded-lg hover:bg-slate-50 disabled:opacity-50 transition-colors"
                      >
                        Previous
                      </button>
                      <button 
                        onClick={() => setOrdersPage(p => Math.min(ordersTotalPages, p + 1))}
                        disabled={ordersPage === ordersTotalPages}
                        className="px-4 py-2 text-sm font-bold text-slate-700 bg-white border border-slate-200 rounded-lg hover:bg-slate-50 disabled:opacity-50 transition-colors"
                      >
                        Next
                      </button>
                    </div>
                  </div>
                )}
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

          {activeTab === 'users' && (
            <motion.div
              initial={{ opacity: 0, y: 10 }}
              animate={{ opacity: 1, y: 0 }}
              className="space-y-8"
            >
              <div className="bg-white p-8 rounded-3xl shadow-sm border border-slate-200">
                <h3 className="text-xl font-bold text-slate-900 mb-6">Add New User</h3>
                <form onSubmit={addUser} className={cn(
                  "grid grid-cols-1 gap-4 items-end",
                  user.role === 'SUPER_ADMIN' ? "md:grid-cols-5" : "md:grid-cols-4"
                )}>
                  <div>
                    <label className="block text-xs font-bold text-slate-500 uppercase mb-2">Email</label>
                    <input name="email" type="email" required className="w-full p-3 bg-slate-50 border border-slate-200 rounded-xl outline-none focus:ring-2 focus:ring-emerald-500/20" placeholder="user@example.com" />
                  </div>
                  <div>
                    <label className="block text-xs font-bold text-slate-500 uppercase mb-2">Password</label>
                    <input name="password" type="password" required className="w-full p-3 bg-slate-50 border border-slate-200 rounded-xl outline-none focus:ring-2 focus:ring-emerald-500/20" placeholder="••••••••" />
                  </div>
                  <div>
                    <label className="block text-xs font-bold text-slate-500 uppercase mb-2">Role</label>
                    <select name="role" className="w-full p-3 bg-slate-50 border border-slate-200 rounded-xl outline-none focus:ring-2 focus:ring-emerald-500/20">
                      <option value="FACILITY_ADMIN">Facility Admin</option>
                      <option value="VENDOR_ADMIN">Vendor Admin</option>
                      <option value="COMPANY_ADMIN">Company Admin</option>
                      {user.role === 'SUPER_ADMIN' && <option value="SUPER_ADMIN">Super Admin</option>}
                      <option value="GOVERNMENT_VIEW">Government View</option>
                      <option value="ADMIN_VIEW">Admin View</option>
                    </select>
                  </div>
                  {user.role === 'SUPER_ADMIN' && (
                    <div>
                      <label className="block text-xs font-bold text-slate-500 uppercase mb-2">Org ID</label>
                      <input name="org_id" type="number" className="w-full p-3 bg-slate-50 border border-slate-200 rounded-xl outline-none focus:ring-2 focus:ring-emerald-500/20" placeholder="1" />
                    </div>
                  )}
                  <button type="submit" className="bg-emerald-600 hover:bg-emerald-700 text-white py-3 rounded-xl font-bold transition-colors">
                    Create User
                  </button>
                </form>
              </div>

              <div className="bg-white rounded-3xl shadow-sm border border-slate-200 overflow-hidden">
                <div className="overflow-x-auto">
                  <table className="w-full text-left border-collapse">
                    <thead>
                      <tr className="bg-slate-50 text-slate-500 text-xs uppercase tracking-wider">
                        <th className="p-4 font-bold border-b border-slate-200">User</th>
                        <th className="p-4 font-bold border-b border-slate-200">Role</th>
                        <th className="p-4 font-bold border-b border-slate-200">Organization</th>
                        <th className="p-4 font-bold border-b border-slate-200">Status</th>
                        <th className="p-4 font-bold border-b border-slate-200">Actions</th>
                      </tr>
                    </thead>
                    <tbody className="text-sm">
                      {users.map((u) => (
                        <tr key={u.id} className="border-b border-slate-100 hover:bg-slate-50/50 transition-colors">
                          <td className="p-4">
                            <div className="font-medium text-slate-900">{u.email}</div>
                            <div className="text-[10px] text-slate-400">Joined {new Date(u.created_at).toLocaleDateString()}</div>
                          </td>
                          <td className="p-4">
                            <span className="px-2 py-1 bg-slate-100 text-slate-600 rounded-md text-[10px] font-bold uppercase tracking-wider">
                              {u.role.replace('_', ' ')}
                            </span>
                          </td>
                          <td className="p-4 text-slate-600">{u.org_name || 'N/A'}</td>
                          <td className="p-4">
                            <span className={cn(
                              "px-2 py-1 rounded-full text-[10px] font-bold uppercase tracking-wider",
                              u.is_active ? "bg-emerald-100 text-emerald-700" : "bg-red-100 text-red-700"
                            )}>
                              {u.is_active ? 'Active' : 'Disabled'}
                            </span>
                          </td>
                          <td className="p-4">
                            <button 
                              onClick={() => toggleUserStatus(u.id, u.is_active)}
                              className={cn(
                                "text-xs font-bold transition-colors",
                                u.is_active ? "text-red-500 hover:text-red-600" : "text-emerald-500 hover:text-emerald-600"
                              )}
                            >
                              {u.is_active ? 'Disable' : 'Enable'}
                            </button>
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              </div>
            </motion.div>
          )}

          {activeTab === 'profile' && userProfile && (
            <motion.div
              initial={{ opacity: 0, y: 10 }}
              animate={{ opacity: 1, y: 0 }}
              className="max-w-2xl mx-auto space-y-8"
            >
              <div className="bg-white p-8 rounded-3xl shadow-sm border border-slate-200 text-center">
                <div className="w-24 h-24 bg-emerald-100 text-emerald-600 rounded-full flex items-center justify-center mx-auto mb-6">
                  <UserCircle className="w-16 h-16" />
                </div>
                <h3 className="text-2xl font-bold text-slate-900">{userProfile.email}</h3>
                <p className="text-slate-500 font-medium mt-1">{userProfile.role.replace('_', ' ')}</p>
                <div className="mt-6 pt-6 border-t border-slate-100 flex justify-center gap-8 text-sm">
                  <div>
                    <p className="text-slate-400 font-bold uppercase tracking-tighter text-[10px]">Member Since</p>
                    <p className="font-bold text-slate-900">{new Date(userProfile.created_at).toLocaleDateString()}</p>
                  </div>
                  <div>
                    <p className="text-slate-400 font-bold uppercase tracking-tighter text-[10px]">Organization ID</p>
                    <p className="font-bold text-slate-900">#{userProfile.org_id || 'N/A'}</p>
                  </div>
                </div>
              </div>

              <div className="bg-white p-8 rounded-3xl shadow-sm border border-slate-200">
                <div className="flex items-center gap-3 mb-6">
                  <div className="p-2 bg-slate-100 rounded-xl text-slate-600">
                    <Lock className="w-5 h-5" />
                  </div>
                  <h3 className="text-xl font-bold text-slate-900">Change Password</h3>
                </div>
                <form onSubmit={changePassword} className="space-y-4">
                  <div>
                    <label className="block text-xs font-bold text-slate-500 uppercase mb-2">Current Password</label>
                    <input name="currentPassword" type="password" required className="w-full p-3 bg-slate-50 border border-slate-200 rounded-xl outline-none focus:ring-2 focus:ring-emerald-500/20" placeholder="••••••••" />
                  </div>
                  <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                    <div>
                      <label className="block text-xs font-bold text-slate-500 uppercase mb-2">New Password</label>
                      <input name="newPassword" type="password" required className="w-full p-3 bg-slate-50 border border-slate-200 rounded-xl outline-none focus:ring-2 focus:ring-emerald-500/20" placeholder="••••••••" />
                    </div>
                    <div>
                      <label className="block text-xs font-bold text-slate-500 uppercase mb-2">Confirm New Password</label>
                      <input name="confirmPassword" type="password" required className="w-full p-3 bg-slate-50 border border-slate-200 rounded-xl outline-none focus:ring-2 focus:ring-emerald-500/20" placeholder="••••••••" />
                    </div>
                  </div>
                  <button type="submit" className="w-full bg-slate-900 hover:bg-slate-800 text-white py-4 rounded-2xl font-bold transition-all shadow-lg shadow-slate-900/10">
                    Update Password
                  </button>
                </form>
              </div>
            </motion.div>
          )}

        </div>
      </main>
    </div>
  );
}
