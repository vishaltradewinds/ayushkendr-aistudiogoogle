import React, { useState } from 'react';
import { motion } from 'motion/react';
import { Plus, Trash2, ShoppingCart, Search, AlertCircle } from 'lucide-react';
import { clsx, type ClassValue } from 'clsx';
import { twMerge } from 'tailwind-merge';

function cn(...inputs: ClassValue[]) {
  return twMerge(clsx(inputs));
}

interface Product {
  id: number;
  name: string;
  price: number;
  category: string;
  vendor_id: number;
  vendor_name?: string;
  vendor_rating?: number;
  stock?: number;
}

interface QuickOrderProps {
  products: Product[];
  onAddToCart: (product: Product, quantity: number) => void;
}

interface OrderRow {
  id: string;
  query: string;
  quantity: number;
  selectedProduct: Product | null;
  error?: string;
}

export default function QuickOrder({ products, onAddToCart }: QuickOrderProps) {
  const [rows, setRows] = useState<OrderRow[]>([
    { id: '1', query: '', quantity: 1, selectedProduct: null }
  ]);
  const [successMessage, setSuccessMessage] = useState('');

  const addRow = () => {
    setRows([...rows, { id: Math.random().toString(36).substr(2, 9), query: '', quantity: 1, selectedProduct: null }]);
  };

  const removeRow = (id: string) => {
    if (rows.length > 1) {
      setRows(rows.filter(row => row.id !== id));
    }
  };

  const updateRow = (id: string, field: keyof OrderRow, value: any) => {
    setRows(rows.map(row => {
      if (row.id === id) {
        const updatedRow = { ...row, [field]: value };
        
        // If query changes, try to find a matching product
        if (field === 'query') {
          const query = value.toLowerCase().trim();
          if (!query) {
            updatedRow.selectedProduct = null;
            updatedRow.error = undefined;
          } else {
            // Find exact match by ID (SKU) or partial match by name
            const match = products.find(p => 
              p.id.toString() === query || 
              p.name.toLowerCase().includes(query)
            );
            
            if (match) {
              updatedRow.selectedProduct = match;
              updatedRow.error = undefined;
            } else {
              updatedRow.selectedProduct = null;
              updatedRow.error = 'Product not found';
            }
          }
        }
        
        return updatedRow;
      }
      return row;
    }));
  };

  const handleAddAllToCart = () => {
    const validRows = rows.filter(row => row.selectedProduct && row.quantity > 0);
    
    if (validRows.length === 0) return;

    validRows.forEach(row => {
      if (row.selectedProduct) {
        onAddToCart(row.selectedProduct, row.quantity);
      }
    });

    setSuccessMessage(`Successfully added ${validRows.length} items to cart!`);
    setTimeout(() => setSuccessMessage(''), 3000);
    
    // Reset form
    setRows([{ id: Math.random().toString(36).substr(2, 9), query: '', quantity: 1, selectedProduct: null }]);
  };

  const totalItems = rows.filter(r => r.selectedProduct).reduce((sum, r) => sum + r.quantity, 0);
  const totalPrice = rows.filter(r => r.selectedProduct).reduce((sum, r) => sum + (r.selectedProduct!.price * r.quantity), 0);

  return (
    <motion.div
      initial={{ opacity: 0, y: 10 }}
      animate={{ opacity: 1, y: 0 }}
      className="max-w-4xl mx-auto"
    >
      <div className="bg-white p-8 rounded-3xl shadow-sm border border-slate-200">
        <div className="flex items-center justify-between mb-8">
          <div>
            <h2 className="text-2xl font-bold text-slate-900">Quick Order</h2>
            <p className="text-slate-500 mt-1">Enter Product ID (SKU) or Name to quickly add items to your cart.</p>
          </div>
          <button
            onClick={addRow}
            className="flex items-center gap-2 px-4 py-2 bg-slate-100 text-slate-700 rounded-xl font-medium hover:bg-slate-200 transition-colors"
          >
            <Plus className="w-4 h-4" /> Add Row
          </button>
        </div>

        {successMessage && (
          <div className="mb-6 p-4 bg-emerald-50 text-emerald-700 rounded-xl border border-emerald-100 flex items-center gap-2 font-medium">
            <ShoppingCart className="w-5 h-5" />
            {successMessage}
          </div>
        )}

        <div className="space-y-4 mb-8">
          <div className="grid grid-cols-12 gap-4 px-4 text-xs font-bold text-slate-500 uppercase tracking-wider">
            <div className="col-span-1 text-center">#</div>
            <div className="col-span-5">Product ID / Name</div>
            <div className="col-span-3">Matched Product</div>
            <div className="col-span-2 text-center">Qty</div>
            <div className="col-span-1 text-center">Action</div>
          </div>

          {rows.map((row, index) => (
            <div key={row.id} className="grid grid-cols-12 gap-4 items-center bg-slate-50 p-4 rounded-2xl border border-slate-100">
              <div className="col-span-1 text-center font-medium text-slate-400">
                {index + 1}
              </div>
              
              <div className="col-span-5 relative">
                <Search className="w-4 h-4 absolute left-3 top-1/2 -translate-y-1/2 text-slate-400" />
                <input
                  type="text"
                  value={row.query}
                  onChange={(e) => updateRow(row.id, 'query', e.target.value)}
                  placeholder="e.g. 101 or Surgical Masks"
                  className={cn(
                    "w-full pl-10 pr-4 py-3 bg-white border rounded-xl outline-none focus:ring-2 transition-all",
                    row.error ? "border-red-300 focus:ring-red-500/20" : "border-slate-200 focus:ring-emerald-500/20 focus:border-emerald-500"
                  )}
                />
                {row.error && (
                  <div className="absolute -bottom-5 left-0 text-[10px] text-red-500 font-medium flex items-center gap-1">
                    <AlertCircle className="w-3 h-3" /> {row.error}
                  </div>
                )}
              </div>

              <div className="col-span-3">
                {row.selectedProduct ? (
                  <div className="flex flex-col">
                    <span className="text-sm font-bold text-slate-900 truncate" title={row.selectedProduct.name}>
                      {row.selectedProduct.name}
                    </span>
                    <span className="text-xs text-emerald-600 font-medium">
                      ₹{row.selectedProduct.price.toLocaleString()}
                    </span>
                  </div>
                ) : (
                  <span className="text-sm text-slate-400 italic">No match</span>
                )}
              </div>

              <div className="col-span-2">
                <input
                  type="number"
                  min="1"
                  value={row.quantity}
                  onChange={(e) => updateRow(row.id, 'quantity', parseInt(e.target.value) || 1)}
                  className="w-full px-4 py-3 text-center bg-white border border-slate-200 rounded-xl outline-none focus:ring-2 focus:ring-emerald-500/20 focus:border-emerald-500"
                />
              </div>

              <div className="col-span-1 flex justify-center">
                <button
                  onClick={() => removeRow(row.id)}
                  disabled={rows.length === 1}
                  className="p-2 text-slate-400 hover:text-red-500 hover:bg-red-50 rounded-lg transition-colors disabled:opacity-50 disabled:hover:bg-transparent disabled:hover:text-slate-400"
                >
                  <Trash2 className="w-5 h-5" />
                </button>
              </div>
            </div>
          ))}
        </div>

        <div className="flex items-center justify-between pt-6 border-t border-slate-100">
          <div className="flex flex-col">
            <span className="text-sm font-bold text-slate-500 uppercase tracking-wider">Order Summary</span>
            <span className="text-2xl font-bold text-slate-900">
              {totalItems} items <span className="text-slate-300 mx-2">|</span> ₹{totalPrice.toLocaleString()}
            </span>
          </div>
          
          <button
            onClick={handleAddAllToCart}
            disabled={totalItems === 0}
            className="flex items-center gap-2 bg-emerald-600 hover:bg-emerald-700 disabled:bg-slate-300 text-white px-8 py-4 rounded-xl font-bold text-lg transition-all shadow-lg shadow-emerald-600/20 disabled:shadow-none"
          >
            <ShoppingCart className="w-5 h-5" />
            Add All to Cart
          </button>
        </div>
      </div>
    </motion.div>
  );
}
