import React from 'react';
import { motion } from 'motion/react';
import { ShieldCheck, Truck, FileText, Activity, ArrowRight, Globe, Building2, Stethoscope, ChevronDown } from 'lucide-react';
import LanguageSwitcher from './LanguageSwitcher';

interface LandingProps {
  onEnterPortal: () => void;
}

export default function Landing({ onEnterPortal }: LandingProps) {
  return (
    <div className="min-h-screen bg-slate-50 font-sans text-slate-900 overflow-x-hidden">
      {/* Ecosystem Banner */}
      <div className="bg-slate-900 text-white text-xs py-2 px-6 relative z-[60]">
        <div className="max-w-7xl mx-auto w-full flex justify-between items-center">
          <span className="flex items-center gap-2 font-medium tracking-wide">
            <Globe className="w-3 h-3 text-emerald-400" /> A Venture of ALLIANCEVENTURES
          </span>
          <div className="relative group">
            <button className="flex items-center gap-1 hover:text-emerald-400 transition-colors font-medium">
              Explore Verticals <ChevronDown className="w-3 h-3" />
            </button>
            <div className="absolute right-0 top-full mt-2 w-56 bg-white text-slate-900 rounded-xl shadow-xl border border-slate-200 opacity-0 invisible group-hover:opacity-100 group-hover:visible transition-all overflow-hidden">
              <a href="https://rupaykg.com" target="_blank" rel="noopener noreferrer" className="block px-4 py-3 hover:bg-emerald-50 hover:text-emerald-700 text-sm font-medium border-b border-slate-100 transition-colors">RupayKg (Sustainability)</a>
              <a href="https://vyaparkendra.com" target="_blank" rel="noopener noreferrer" className="block px-4 py-3 hover:bg-emerald-50 hover:text-emerald-700 text-sm font-medium border-b border-slate-100 transition-colors">VyaparKendra (Commerce)</a>
              <a href="#" className="block px-4 py-3 hover:bg-emerald-50 hover:text-emerald-700 text-sm font-bold transition-colors">AyushKendra (Health-Tech)</a>
            </div>
          </div>
        </div>
      </div>

      {/* Navigation */}
      <nav className="sticky top-0 w-full bg-white/80 backdrop-blur-md border-b border-slate-200 z-50">
        <div className="max-w-7xl mx-auto px-6 h-20 flex items-center justify-between">
          <div className="flex items-center gap-3">
            <div className="bg-emerald-500 text-white p-2 rounded-xl">
              <Activity className="w-6 h-6" />
            </div>
            <span className="text-2xl font-bold text-slate-900 tracking-tight">AyushKendra</span>
          </div>
          <div className="hidden md:flex items-center gap-8 text-sm font-medium text-slate-600">
            <a href="#features" className="hover:text-emerald-600 transition-colors">Features</a>
            <a href="#about" className="hover:text-emerald-600 transition-colors">About Us</a>
            <a href="#contact" className="hover:text-emerald-600 transition-colors">Contact</a>
          </div>
          <div className="flex items-center gap-4">
            <LanguageSwitcher />
            <button 
              onClick={onEnterPortal}
              className="bg-slate-900 hover:bg-slate-800 text-white px-6 py-2.5 rounded-xl font-medium transition-all flex items-center gap-2"
            >
              Enter Portal <ArrowRight className="w-4 h-4" />
            </button>
          </div>
        </div>
      </nav>

      {/* Hero Section */}
      <section className="pt-40 pb-24 px-6 relative">
        <div className="absolute inset-0 bg-[url('https://picsum.photos/seed/medical/1920/1080?blur=10')] bg-cover bg-center opacity-5" />
        <div className="max-w-7xl mx-auto relative z-10 text-center">
          <motion.div
            initial={{ opacity: 0, y: 20 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ duration: 0.6 }}
          >
            <h1 className="text-5xl md:text-7xl font-bold text-slate-900 tracking-tight mb-8 leading-tight">
              India's Integrated <br />
              <span className="text-emerald-600">Medical Device</span> Supply
            </h1>
            <p className="text-xl text-slate-600 max-w-3xl mx-auto mb-12 leading-relaxed">
              A sovereign B2B procurement platform connecting healthcare facilities, clinics, and individuals with verified medical device manufacturers. Built for scale, compliance, and transparency.
            </p>
            <div className="flex flex-col sm:flex-row items-center justify-center gap-4">
              <button 
                onClick={onEnterPortal}
                className="w-full sm:w-auto bg-emerald-600 hover:bg-emerald-700 text-white px-8 py-4 rounded-2xl font-bold text-lg transition-all shadow-lg shadow-emerald-600/20 flex items-center justify-center gap-2"
              >
                Start Procuring <ArrowRight className="w-5 h-5" />
              </button>
              <button 
                onClick={onEnterPortal}
                className="w-full sm:w-auto bg-white hover:bg-slate-50 text-slate-900 border border-slate-200 px-8 py-4 rounded-2xl font-bold text-lg transition-all flex items-center justify-center gap-2"
              >
                Become a Vendor <Building2 className="w-5 h-5" />
              </button>
            </div>
          </motion.div>
        </div>
      </section>

      {/* Features Section */}
      <section id="features" className="py-24 bg-white px-6">
        <div className="max-w-7xl mx-auto">
          <div className="text-center mb-16">
            <h2 className="text-3xl md:text-4xl font-bold text-slate-900 mb-4">Enterprise-Grade Infrastructure</h2>
            <p className="text-slate-600 max-w-2xl mx-auto">Everything you need to manage institutional healthcare procurement securely and efficiently.</p>
          </div>
          
          <div className="grid md:grid-cols-3 gap-8">
            {[
              {
                icon: <ShieldCheck className="w-8 h-8 text-emerald-600" />,
                title: "Verified Suppliers",
                desc: "Every vendor undergoes strict KYC and quality compliance checks before listing."
              },
              {
                icon: <FileText className="w-8 h-8 text-emerald-600" />,
                title: "Automated GST Invoicing",
                desc: "Instant, compliant PDF invoices generated automatically for every transaction."
              },
              {
                icon: <Truck className="w-8 h-8 text-emerald-600" />,
                title: "End-to-End Tracking",
                desc: "Real-time visibility into your orders from dispatch to delivery."
              },
              {
                icon: <Globe className="w-8 h-8 text-emerald-600" />,
                title: "Pan-India Reach",
                desc: "Connecting rural healthcare facilities with top-tier medical manufacturers."
              },
              {
                icon: <Activity className="w-8 h-8 text-emerald-600" />,
                title: "Real-time Analytics",
                desc: "Comprehensive dashboards for procurement tracking and spending analysis."
              },
              {
                icon: <Stethoscope className="w-8 h-8 text-emerald-600" />,
                title: "Specialized Catalogue",
                desc: "Curated selection of modern medical devices, diagnostic equipment, and surgical tools."
              }
            ].map((feature, i) => (
              <motion.div 
                key={i}
                initial={{ opacity: 0, y: 20 }}
                whileInView={{ opacity: 1, y: 0 }}
                viewport={{ once: true }}
                transition={{ delay: i * 0.1 }}
                className="p-8 rounded-3xl bg-slate-50 border border-slate-100 hover:shadow-xl hover:shadow-slate-200/50 transition-all"
              >
                <div className="bg-emerald-100 w-16 h-16 rounded-2xl flex items-center justify-center mb-6">
                  {feature.icon}
                </div>
                <h3 className="text-xl font-bold text-slate-900 mb-3">{feature.title}</h3>
                <p className="text-slate-600 leading-relaxed">{feature.desc}</p>
              </motion.div>
            ))}
          </div>
        </div>
      </section>

      {/* Featured Products Preview */}
      <section className="py-24 bg-slate-50 px-6">
        <div className="max-w-7xl mx-auto">
          <div className="flex flex-col md:flex-row justify-between items-end mb-12 gap-6">
            <div>
              <h2 className="text-3xl md:text-4xl font-bold text-slate-900 mb-4">Specialized Medical Catalogue</h2>
              <p className="text-slate-600 max-w-xl">Browse our curated selection of high-quality medical devices and AYUSH healthcare supplies from verified manufacturers.</p>
            </div>
            <button 
              onClick={onEnterPortal}
              className="text-emerald-600 font-bold flex items-center gap-2 hover:gap-3 transition-all"
            >
              View Full Catalogue <ArrowRight className="w-5 h-5" />
            </button>
          </div>

          <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-6">
            {[
              { name: 'Digital Sphygmomanometer', cat: 'Diagnostic', price: '₹2,450', img: 'https://picsum.photos/seed/bp/400/400' },
              { name: 'Ashwagandha Extract', cat: 'Ayurveda', price: '₹850', img: 'https://picsum.photos/seed/ashwa/400/400' },
              { name: 'Pulse Oximeter OLED', cat: 'Diagnostic', price: '₹1,800', img: 'https://picsum.photos/seed/oximeter/400/400' },
              { name: 'Arnica Montana Gel', cat: 'Homeopathy', price: '₹320', img: 'https://picsum.photos/seed/arnica/400/400' }
            ].map((p, i) => (
              <motion.div 
                key={i}
                initial={{ opacity: 0, scale: 0.95 }}
                whileInView={{ opacity: 1, scale: 1 }}
                viewport={{ once: true }}
                transition={{ delay: i * 0.1 }}
                className="bg-white p-4 rounded-3xl border border-slate-200 hover:shadow-xl transition-all group cursor-pointer"
                onClick={onEnterPortal}
              >
                <div className="aspect-square bg-slate-50 rounded-2xl mb-4 overflow-hidden flex items-center justify-center p-4">
                  <img src={p.img} alt={p.name} className="max-w-full max-h-full object-contain group-hover:scale-110 transition-transform duration-500" referrerPolicy="no-referrer" />
                </div>
                <span className="text-[10px] font-bold text-emerald-600 bg-emerald-50 px-2 py-1 rounded-md uppercase tracking-widest">{p.cat}</span>
                <h3 className="font-bold text-slate-900 mt-2 line-clamp-1">{p.name}</h3>
                <p className="text-lg font-black text-slate-900 mt-1">{p.price}</p>
              </motion.div>
            ))}
          </div>
        </div>
      </section>

      {/* CTA Section */}
      <section className="py-24 px-6 bg-slate-900 text-white text-center">
        <div className="max-w-4xl mx-auto">
          <h2 className="text-4xl md:text-5xl font-bold mb-6">Ready to transform your supply chain?</h2>
          <p className="text-xl text-slate-400 mb-10">Join thousands of healthcare institutions already using AyushKendra.</p>
          <button 
            onClick={onEnterPortal}
            className="bg-emerald-500 hover:bg-emerald-400 text-slate-900 px-10 py-5 rounded-2xl font-bold text-xl transition-all shadow-lg shadow-emerald-500/20"
          >
            Access the Portal Now
          </button>
        </div>
      </section>

      {/* Footer */}
      <footer className="bg-white border-t border-slate-200 py-12 px-6">
        <div className="max-w-7xl mx-auto flex flex-col md:flex-row items-center justify-between gap-6">
          <div className="flex items-center gap-2">
            <Activity className="w-6 h-6 text-emerald-600" />
            <span className="text-xl font-bold text-slate-900">AyushKendra</span>
          </div>
          <p className="text-slate-500 text-sm">
            © {new Date().getFullYear()} AyushKendra. Powered by <a href="https://allianceventures.com" target="_blank" rel="noopener noreferrer" className="text-emerald-600 hover:underline">ALLIANCEVENTURES</a>.
          </p>
          <div className="flex gap-6 text-sm text-slate-500">
            <a href="#" className="hover:text-emerald-600">Privacy Policy</a>
            <a href="#" className="hover:text-emerald-600">Terms of Service</a>
          </div>
        </div>
      </footer>
    </div>
  );
}
