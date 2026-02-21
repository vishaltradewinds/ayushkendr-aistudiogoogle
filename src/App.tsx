import { Activity, Leaf, Building2, ShieldCheck, TrendingUp, ArrowRight, CheckCircle2, Stethoscope, HeartPulse, Syringe, FileText, Map, Globe, Shield } from 'lucide-react';
import { motion } from 'motion/react';

export default function App() {
  return (
    <div className="min-h-screen bg-slate-50 font-sans text-slate-900 selection:bg-emerald-200 selection:text-emerald-900">
      {/* Navbar */}
      <nav className="sticky top-0 z-50 bg-white/80 backdrop-blur-md border-b border-slate-200">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 h-16 flex items-center justify-between">
          <div className="flex items-center gap-2">
            <div className="bg-emerald-600 text-white p-1.5 rounded-lg">
              <Activity className="w-6 h-6" />
            </div>
            <span className="text-xl font-bold tracking-tight text-slate-900">AyushKendra</span>
          </div>
          <div className="hidden md:flex items-center gap-8 text-sm font-medium text-slate-600">
            <a href="#services" className="hover:text-emerald-600 transition-colors">Services</a>
            <a href="#business-model" className="hover:text-emerald-600 transition-colors">Business Model</a>
            <a href="#compliance" className="hover:text-emerald-600 transition-colors">Compliance</a>
            <a href="#roadmap" className="hover:text-emerald-600 transition-colors">Roadmap</a>
          </div>
          <div className="flex items-center gap-4">
            <button className="hidden md:block text-sm font-medium text-slate-600 hover:text-slate-900 transition-colors">
              Login
            </button>
            <button className="bg-emerald-600 hover:bg-emerald-700 text-white px-4 py-2 rounded-lg text-sm font-medium transition-colors shadow-sm shadow-emerald-600/20">
              Partner With Us
            </button>
          </div>
        </div>
      </nav>

      {/* Hero Section */}
      <section className="relative pt-24 pb-32 overflow-hidden">
        <div className="absolute inset-0 bg-[radial-gradient(ellipse_at_top_right,_var(--tw-gradient-stops))] from-emerald-100/50 via-slate-50 to-slate-50 -z-10"></div>
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 relative">
          <div className="max-w-3xl">
            <motion.div 
              initial={{ opacity: 0, y: 20 }}
              animate={{ opacity: 1, y: 0 }}
              transition={{ duration: 0.5 }}
              className="inline-flex items-center gap-2 px-3 py-1 rounded-full bg-emerald-100 text-emerald-800 text-sm font-medium mb-6"
            >
              <span className="relative flex h-2 w-2">
                <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-emerald-400 opacity-75"></span>
                <span className="relative inline-flex rounded-full h-2 w-2 bg-emerald-500"></span>
              </span>
              B2B-First Healthcare Supply Platform
            </motion.div>
            
            <motion.h1 
              initial={{ opacity: 0, y: 20 }}
              animate={{ opacity: 1, y: 0 }}
              transition={{ duration: 0.5, delay: 0.1 }}
              className="text-5xl md:text-6xl font-bold tracking-tight text-slate-900 leading-[1.1] mb-6"
            >
              Powering modern and AYUSH healthcare with <span className="text-emerald-600">trusted infrastructure.</span>
            </motion.h1>
            
            <motion.p 
              initial={{ opacity: 0, y: 20 }}
              animate={{ opacity: 1, y: 0 }}
              transition={{ duration: 0.5, delay: 0.2 }}
              className="text-xl text-slate-600 mb-8 leading-relaxed max-w-2xl"
            >
              AyushKendra is India's institution-grade medical devices supply platform, making reliable, affordable, and compliant equipment accessible to clinics, hospitals, and AYUSH practitioners.
            </motion.p>
            
            <motion.div 
              initial={{ opacity: 0, y: 20 }}
              animate={{ opacity: 1, y: 0 }}
              transition={{ duration: 0.5, delay: 0.3 }}
              className="flex flex-wrap items-center gap-4"
            >
              <button className="bg-slate-900 hover:bg-slate-800 text-white px-6 py-3 rounded-xl font-medium transition-colors flex items-center gap-2">
                Explore Catalogue <ArrowRight className="w-4 h-4" />
              </button>
              <button className="bg-white hover:bg-slate-50 text-slate-700 border border-slate-200 px-6 py-3 rounded-xl font-medium transition-colors">
                View Institutional Pricing
              </button>
            </motion.div>
          </div>
        </div>
      </section>

      {/* Mission */}
      <section className="py-16 bg-white border-y border-slate-200">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
          <div className="flex flex-col md:flex-row gap-8 items-center justify-between">
            <div className="md:w-1/3">
              <h2 className="text-3xl font-bold tracking-tight text-slate-900">Our Mission</h2>
              <div className="h-1 w-12 bg-emerald-500 mt-4 rounded-full"></div>
            </div>
            <div className="md:w-2/3">
              <p className="text-xl text-slate-600 leading-relaxed font-medium">
                To democratize access to quality medical devices for every level of healthcare—urban hospitals to rural clinics—while supporting India's AYUSH and primary care expansion with dependable infrastructure.
              </p>
            </div>
          </div>
        </div>
      </section>

      {/* What We Deliver */}
      <section id="services" className="py-24 bg-slate-50">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
          <div className="text-center max-w-2xl mx-auto mb-16">
            <h2 className="text-3xl font-bold tracking-tight text-slate-900 mb-4">What AyushKendra Delivers</h2>
            <p className="text-lg text-slate-600">Comprehensive supply solutions bridging modern medical devices with traditional healthcare ecosystems.</p>
          </div>

          <div className="grid md:grid-cols-3 gap-8">
            {/* Pillar 1 */}
            <motion.div 
              whileHover={{ y: -5 }}
              className="bg-white p-8 rounded-2xl shadow-sm border border-slate-200"
            >
              <div className="w-12 h-12 bg-blue-100 text-blue-600 rounded-xl flex items-center justify-center mb-6">
                <HeartPulse className="w-6 h-6" />
              </div>
              <h3 className="text-xl font-bold text-slate-900 mb-4">Medical Devices & Equipment Supply</h3>
              <ul className="space-y-3">
                {[
                  "Diagnostic devices (BP monitors, glucometers, pulse oximeters, ECGs)",
                  "Patient care & monitoring equipment",
                  "Hospital & clinic infrastructure essentials",
                  "Consumables & disposables (PPE, syringes, testing kits)"
                ].map((item, i) => (
                  <li key={i} className="flex items-start gap-3 text-slate-600">
                    <CheckCircle2 className="w-5 h-5 text-blue-500 shrink-0 mt-0.5" />
                    <span className="text-sm leading-relaxed">{item}</span>
                  </li>
                ))}
              </ul>
            </motion.div>

            {/* Pillar 2 */}
            <motion.div 
              whileHover={{ y: -5 }}
              className="bg-white p-8 rounded-2xl shadow-sm border border-slate-200"
            >
              <div className="w-12 h-12 bg-emerald-100 text-emerald-600 rounded-xl flex items-center justify-center mb-6">
                <Leaf className="w-6 h-6" />
              </div>
              <h3 className="text-xl font-bold text-slate-900 mb-4">AYUSH Clinic Enablement</h3>
              <ul className="space-y-3">
                {[
                  "Equipment and instruments tailored for Ayurveda, Yoga, Unani, Siddha, and Homeopathy",
                  "Standardized kits for AYUSH clinics and wellness centers",
                  "Support for government and private AYUSH facilities"
                ].map((item, i) => (
                  <li key={i} className="flex items-start gap-3 text-slate-600">
                    <CheckCircle2 className="w-5 h-5 text-emerald-500 shrink-0 mt-0.5" />
                    <span className="text-sm leading-relaxed">{item}</span>
                  </li>
                ))}
              </ul>
            </motion.div>

            {/* Pillar 3 */}
            <motion.div 
              whileHover={{ y: -5 }}
              className="bg-white p-8 rounded-2xl shadow-sm border border-slate-200"
            >
              <div className="w-12 h-12 bg-indigo-100 text-indigo-600 rounded-xl flex items-center justify-center mb-6">
                <Building2 className="w-6 h-6" />
              </div>
              <h3 className="text-xl font-bold text-slate-900 mb-4">Institutional & Government Procurement</h3>
              <ul className="space-y-3">
                {[
                  "Bulk supply to hospitals, nursing homes, and labs",
                  "Participation in state & central government tenders",
                  "Compliance-ready documentation (GST, MDR, ISO where applicable)"
                ].map((item, i) => (
                  <li key={i} className="flex items-start gap-3 text-slate-600">
                    <CheckCircle2 className="w-5 h-5 text-indigo-500 shrink-0 mt-0.5" />
                    <span className="text-sm leading-relaxed">{item}</span>
                  </li>
                ))}
              </ul>
            </motion.div>
          </div>
        </div>
      </section>

      {/* Business Model */}
      <section id="business-model" className="py-24 bg-slate-900 text-white">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
          <div className="text-center max-w-2xl mx-auto mb-16">
            <h2 className="text-3xl font-bold tracking-tight mb-4">Business Model</h2>
            <p className="text-lg text-slate-400">A structured approach to institutional healthcare supply.</p>
          </div>

          <div className="overflow-x-auto">
            <table className="w-full text-left border-collapse">
              <thead>
                <tr className="border-b border-slate-800">
                  <th className="py-4 px-6 text-sm font-semibold text-slate-400 uppercase tracking-wider w-1/4">Layer</th>
                  <th className="py-4 px-6 text-sm font-semibold text-slate-400 uppercase tracking-wider">Description</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-800/50">
                {[
                  { layer: "Customer Segments", desc: "Clinics, hospitals, diagnostic labs, AYUSH centers, NGOs, government health programs" },
                  { layer: "Revenue", desc: "Product sales, bulk contracts, AMC & repeat consumables" },
                  { layer: "Sourcing", desc: "Certified manufacturers, OEM partnerships, import substitution focus" },
                  { layer: "Distribution", desc: "Direct B2B sales + digital ordering via www.ayushkendra.com" },
                  { layer: "Margin Strategy", desc: "Volume-led pricing, institutional discounts, recurring supply" }
                ].map((row, i) => (
                  <tr key={i} className="hover:bg-slate-800/30 transition-colors">
                    <td className="py-5 px-6 font-medium text-emerald-400">{row.layer}</td>
                    <td className="py-5 px-6 text-slate-300">{row.desc}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      </section>

      {/* Compliance & Strategic Advantage */}
      <section id="compliance" className="py-24 bg-white">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
          <div className="grid md:grid-cols-2 gap-16">
            
            {/* Compliance Stack */}
            <div>
              <div className="flex items-center gap-3 mb-8">
                <ShieldCheck className="w-8 h-8 text-emerald-600" />
                <h2 className="text-3xl font-bold tracking-tight text-slate-900">Compliance & Trust Stack</h2>
              </div>
              <div className="space-y-6">
                {[
                  { title: "MDR Aligned", desc: "Compliant with Indian Medical Device Rules." },
                  { title: "Quality First", desc: "Strict vendor onboarding and vetting processes." },
                  { title: "Transparent Supply", desc: "Clear pricing and fully traceable supply chain." },
                  { title: "Audit Ready", desc: "Prepared for CSR, PSU, and government audits." }
                ].map((item, i) => (
                  <div key={i} className="flex gap-4">
                    <div className="w-10 h-10 rounded-full bg-slate-100 flex items-center justify-center shrink-0">
                      <Shield className="w-5 h-5 text-slate-600" />
                    </div>
                    <div>
                      <h4 className="text-lg font-semibold text-slate-900">{item.title}</h4>
                      <p className="text-slate-600">{item.desc}</p>
                    </div>
                  </div>
                ))}
              </div>
            </div>

            {/* Strategic Advantage */}
            <div>
              <div className="flex items-center gap-3 mb-8">
                <TrendingUp className="w-8 h-8 text-blue-600" />
                <h2 className="text-3xl font-bold tracking-tight text-slate-900">Strategic Advantage</h2>
              </div>
              <div className="grid gap-4">
                {[
                  "Bridges modern medical devices + AYUSH infrastructure",
                  "Focus on Tier-2 / Tier-3 cities and rural healthcare",
                  "Scalable catalogue: devices → consumables → long-term supply contracts",
                  "Positioned for public health missions & preventive care growth"
                ].map((item, i) => (
                  <div key={i} className="bg-slate-50 p-5 rounded-xl border border-slate-200 flex items-start gap-3">
                    <CheckCircle2 className="w-5 h-5 text-blue-600 shrink-0 mt-0.5" />
                    <span className="font-medium text-slate-700">{item}</span>
                  </div>
                ))}
              </div>
            </div>

          </div>
        </div>
      </section>

      {/* Roadmap */}
      <section id="roadmap" className="py-24 bg-slate-50 border-t border-slate-200">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
          <div className="text-center max-w-2xl mx-auto mb-16">
            <h2 className="text-3xl font-bold tracking-tight text-slate-900 mb-4">Growth Roadmap</h2>
            <p className="text-lg text-slate-600">Our path to scaling healthcare infrastructure across India.</p>
          </div>

          <div className="grid md:grid-cols-5 gap-4">
            {[
              { icon: Map, title: "Network", desc: "Nationwide B2B distributor network" },
              { icon: Globe, title: "Platform", desc: "Digital catalogue + order management" },
              { icon: Building2, title: "Projects", desc: "Government & CSR healthcare projects" },
              { icon: Activity, title: "Private Label", desc: "Phase-2 private-label devices" },
              { icon: Syringe, title: "Integration", desc: "Allied platforms integration" }
            ].map((step, i) => (
              <div key={i} className="relative">
                <div className="bg-white p-6 rounded-2xl border border-slate-200 shadow-sm h-full flex flex-col items-center text-center z-10 relative">
                  <div className="w-12 h-12 bg-emerald-50 text-emerald-600 rounded-full flex items-center justify-center mb-4">
                    <step.icon className="w-6 h-6" />
                  </div>
                  <h4 className="font-bold text-slate-900 mb-2">{step.title}</h4>
                  <p className="text-sm text-slate-600">{step.desc}</p>
                </div>
                {i < 4 && (
                  <div className="hidden md:block absolute top-1/2 -right-2 w-4 h-0.5 bg-slate-300 z-0"></div>
                )}
              </div>
            ))}
          </div>
        </div>
      </section>

      {/* CTA */}
      <section className="py-20 bg-emerald-600 text-white">
        <div className="max-w-4xl mx-auto px-4 sm:px-6 lg:px-8 text-center">
          <h2 className="text-3xl md:text-4xl font-bold mb-6">Ready to upgrade your healthcare infrastructure?</h2>
          <p className="text-emerald-100 text-lg mb-8 max-w-2xl mx-auto">
            Join thousands of clinics, hospitals, and AYUSH centers trusting AyushKendra for their medical device needs.
          </p>
          <div className="flex flex-col sm:flex-row items-center justify-center gap-4">
            <button className="bg-white text-emerald-700 hover:bg-emerald-50 px-8 py-4 rounded-xl font-bold text-lg transition-colors w-full sm:w-auto">
              Partner With Us
            </button>
            <button className="bg-emerald-700 text-white hover:bg-emerald-800 border border-emerald-500 px-8 py-4 rounded-xl font-bold text-lg transition-colors w-full sm:w-auto">
              Contact Sales
            </button>
          </div>
        </div>
      </section>

      {/* Footer */}
      <footer className="bg-slate-950 text-slate-400 py-12 border-t border-slate-900">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
          <div className="grid md:grid-cols-4 gap-8 mb-8">
            <div className="col-span-2">
              <div className="flex items-center gap-2 mb-4">
                <div className="bg-emerald-600 text-white p-1 rounded-md">
                  <Activity className="w-5 h-5" />
                </div>
                <span className="text-xl font-bold text-white">AyushKendra</span>
              </div>
              <p className="text-sm leading-relaxed max-w-sm">
                India's institution-grade medical devices supply platform—powering modern and AYUSH healthcare with trusted, affordable infrastructure.
              </p>
            </div>
            <div>
              <h4 className="text-white font-semibold mb-4">Platform</h4>
              <ul className="space-y-2 text-sm">
                <li><a href="#" className="hover:text-emerald-400 transition-colors">Medical Devices</a></li>
                <li><a href="#" className="hover:text-emerald-400 transition-colors">AYUSH Enablement</a></li>
                <li><a href="#" className="hover:text-emerald-400 transition-colors">Institutional Procurement</a></li>
                <li><a href="#" className="hover:text-emerald-400 transition-colors">Digital Catalogue</a></li>
              </ul>
            </div>
            <div>
              <h4 className="text-white font-semibold mb-4">Company</h4>
              <ul className="space-y-2 text-sm">
                <li><a href="#" className="hover:text-emerald-400 transition-colors">About Us</a></li>
                <li><a href="#" className="hover:text-emerald-400 transition-colors">Contact</a></li>
                <li><a href="#" className="hover:text-emerald-400 transition-colors">Privacy Policy</a></li>
                <li><a href="#" className="hover:text-emerald-400 transition-colors">Terms of Service</a></li>
              </ul>
            </div>
          </div>
          <div className="pt-8 border-t border-slate-800 text-sm flex flex-col md:flex-row items-center justify-between">
            <p>© {new Date().getFullYear()} AyushKendra. All rights reserved.</p>
            <p className="mt-2 md:mt-0">www.ayushkendra.com</p>
          </div>
        </div>
      </footer>
    </div>
  );
}
