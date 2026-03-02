import React, { useState } from 'react';
import { motion } from 'motion/react';
import { X, Star, Building2, ShoppingCart, Minus, Plus, Package, ChevronLeft, ChevronRight } from 'lucide-react';
import { clsx, type ClassValue } from 'clsx';
import { twMerge } from 'tailwind-merge';

function cn(...inputs: ClassValue[]) {
  return twMerge(clsx(inputs));
}

interface ProductDetailsProps {
  product: any;
  user: any;
  onClose: () => void;
  productQuantities: Record<number, number>;
  setProductQuantities: React.Dispatch<React.SetStateAction<Record<number, number>>>;
  addToCart: (product: any) => void;
  productReviews: any[];
  submitReview: (e: React.FormEvent<HTMLFormElement>, productId: number) => void;
  getCategoryColor: (category: string) => string;
}

export default function ProductDetails({
  product,
  user,
  onClose,
  productQuantities,
  setProductQuantities,
  addToCart,
  productReviews,
  submitReview,
  getCategoryColor
}: ProductDetailsProps) {
  const [selectedImageIndex, setSelectedImageIndex] = useState(0);
  const [isZoomed, setIsZoomed] = useState(false);
  const [mousePos, setMousePos] = useState({ x: 0, y: 0 });

  let specs = {};
  try { specs = product.specifications ? JSON.parse(product.specifications) : {}; } catch (e) { console.error("Invalid specs JSON", e); }

  let images: string[] = [];
  try { images = product.images ? JSON.parse(product.images) : []; } catch (e) { console.error("Invalid images JSON", e); }

  const handleMouseMove = (e: React.MouseEvent<HTMLDivElement>) => {
    if (!isZoomed) return;
    const { left, top, width, height } = e.currentTarget.getBoundingClientRect();
    const x = ((e.clientX - left) / width) * 100;
    const y = ((e.clientY - top) / height) * 100;
    setMousePos({ x, y });
  };

  return (
    <div className="space-y-8">
      <button
        onClick={onClose}
        className="flex items-center gap-2 text-slate-500 hover:text-slate-900 font-bold transition-colors"
      >
        <X className="w-5 h-5" /> Back to Catalogue
      </button>

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-12">
        {/* Product Images Gallery */}
        <div className="space-y-4">
          <div 
            className="aspect-square bg-white rounded-3xl border border-slate-200 overflow-hidden flex items-center justify-center relative cursor-zoom-in group"
            onMouseEnter={() => setIsZoomed(true)}
            onMouseLeave={() => setIsZoomed(false)}
            onMouseMove={handleMouseMove}
          >
            {images[selectedImageIndex] ? (
              <>
                <img 
                  src={images[selectedImageIndex]} 
                  alt={product.name} 
                  className={cn(
                    "max-w-full max-h-full object-contain transition-opacity duration-300",
                    isZoomed ? "opacity-0" : "opacity-100"
                  )} 
                />
                {isZoomed && (
                  <div 
                    className="absolute inset-0 bg-no-repeat"
                    style={{
                      backgroundImage: `url(${images[selectedImageIndex]})`,
                      backgroundPosition: `${mousePos.x}% ${mousePos.y}%`,
                      backgroundSize: '200%',
                    }}
                  />
                )}
              </>
            ) : (
              <Package className="w-32 h-32 text-slate-200" />
            )}
            
            {images.length > 1 && (
              <>
                <button 
                  onClick={(e) => { e.stopPropagation(); setSelectedImageIndex(prev => prev === 0 ? images.length - 1 : prev - 1); }}
                  className="absolute left-4 top-1/2 -translate-y-1/2 bg-white/80 backdrop-blur-sm p-2 rounded-full shadow-sm hover:bg-white transition-colors opacity-0 group-hover:opacity-100"
                >
                  <ChevronLeft className="w-5 h-5" />
                </button>
                <button 
                  onClick={(e) => { e.stopPropagation(); setSelectedImageIndex(prev => prev === images.length - 1 ? 0 : prev + 1); }}
                  className="absolute right-4 top-1/2 -translate-y-1/2 bg-white/80 backdrop-blur-sm p-2 rounded-full shadow-sm hover:bg-white transition-colors opacity-0 group-hover:opacity-100"
                >
                  <ChevronRight className="w-5 h-5" />
                </button>
              </>
            )}
          </div>
          
          {images.length > 1 && (
            <div className="grid grid-cols-5 gap-4">
              {images.map((img: string, idx: number) => (
                <button 
                  key={idx} 
                  onClick={() => setSelectedImageIndex(idx)}
                  className={cn(
                    "aspect-square bg-white rounded-xl border overflow-hidden p-2 transition-all",
                    selectedImageIndex === idx ? "border-emerald-500 ring-2 ring-emerald-500/20" : "border-slate-200 hover:border-emerald-300"
                  )}
                >
                  <img src={img} alt={`${product.name} ${idx + 1}`} className="w-full h-full object-contain" />
                </button>
              ))}
            </div>
          )}
        </div>

        {/* Product Info */}
        <div className="space-y-8">
          <div>
            <span className={cn(
              "text-xs font-black px-3 py-1 rounded-full uppercase tracking-widest border",
              getCategoryColor(product.category)
            )}>
              {product.category}
            </span>
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
                      onClick={() => setProductQuantities(prev => ({ ...prev, [product.id]: Math.max(1, (prev[product.id] || 1) - 1) }))}
                      className="p-3 hover:bg-white rounded-xl transition-colors"
                    >
                      <Minus className="w-4 h-4" />
                    </button>
                    <span className="w-12 text-center font-bold">{productQuantities[product.id] || 1}</span>
                    <button
                      onClick={() => setProductQuantities(prev => ({ ...prev, [product.id]: (prev[product.id] || 1) + 1 }))}
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
    </div>
  );
}
