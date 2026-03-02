import React, { useState, useEffect, useRef } from 'react';
import { Globe, ChevronDown } from 'lucide-react';
import { clsx, type ClassValue } from 'clsx';
import { twMerge } from 'tailwind-merge';

function cn(...inputs: ClassValue[]) {
  return twMerge(clsx(inputs));
}

const languages = [
  { code: 'en', name: 'English' },
  { code: 'hi', name: 'हिंदी (Hindi)' },
  { code: 'bn', name: 'বাংলা (Bengali)' },
  { code: 'te', name: 'తెలుగు (Telugu)' },
  { code: 'mr', name: 'मराठी (Marathi)' },
  { code: 'ta', name: 'தமிழ் (Tamil)' },
  { code: 'ur', name: 'اردو (Urdu)' },
  { code: 'gu', name: 'ગુજરાતી (Gujarati)' },
  { code: 'kn', name: 'ಕನ್ನಡ (Kannada)' },
  { code: 'ml', name: 'മലയാളം (Malayalam)' },
  { code: 'pa', name: 'ਪੰਜਾਬੀ (Punjabi)' },
  { code: 'or', name: 'ଓଡ଼ିଆ (Odia)' },
  { code: 'as', name: 'অসমীয়া (Assamese)' },
  { code: 'sa', name: 'संस्कृतम् (Sanskrit)' },
];

export default function LanguageSwitcher() {
  const [isOpen, setIsOpen] = useState(false);
  const [currentLang, setCurrentLang] = useState('en');
  const dropdownRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    // Try to get current language from Google Translate cookie
    const match = document.cookie.match(/(^|;) ?googtrans=([^;]*)(;|$)/);
    if (match && match[2]) {
      const lang = match[2].split('/')[2];
      if (lang && languages.some(l => l.code === lang)) {
        setCurrentLang(lang);
      }
    }

    const handleClickOutside = (event: MouseEvent) => {
      if (dropdownRef.current && !dropdownRef.current.contains(event.target as Node)) {
        setIsOpen(false);
      }
    };

    document.addEventListener('mousedown', handleClickOutside);
    return () => document.removeEventListener('mousedown', handleClickOutside);
  }, []);

  const handleLanguageChange = (langCode: string) => {
    setCurrentLang(langCode);
    setIsOpen(false);
    
    // Find the Google Translate select element
    const select = document.querySelector('.goog-te-combo') as HTMLSelectElement;
    if (select) {
      select.value = langCode;
      select.dispatchEvent(new Event('change'));
    } else {
      // If select is not found, try to set the cookie and reload
      document.cookie = `googtrans=/en/${langCode}; path=/`;
      window.location.reload();
    }
  };

  return (
    <div className="relative z-50" ref={dropdownRef}>
      <button 
        onClick={() => setIsOpen(!isOpen)}
        className="flex items-center gap-2 px-4 py-2.5 bg-white border border-slate-200 text-slate-700 rounded-xl text-sm font-medium hover:bg-slate-50 transition-colors shadow-sm"
      >
        <Globe className="w-4 h-4 text-emerald-600" />
        <span className="hidden sm:inline">{languages.find(l => l.code === currentLang)?.name.split(' ')[0] || 'English'}</span>
        <ChevronDown className={cn("w-4 h-4 text-slate-400 transition-transform", isOpen && "rotate-180")} />
      </button>
      
      {isOpen && (
        <div className="absolute right-0 top-full mt-2 w-48 bg-white text-slate-900 rounded-xl shadow-xl border border-slate-200 overflow-hidden z-50 max-h-96 overflow-y-auto">
          {languages.map((lang) => (
            <button
              key={lang.code}
              onClick={() => handleLanguageChange(lang.code)}
              className={cn(
                "w-full text-left px-4 py-2.5 text-sm font-medium transition-colors hover:bg-emerald-50 hover:text-emerald-700",
                currentLang === lang.code ? "bg-emerald-50 text-emerald-700" : "text-slate-700 border-b border-slate-50 last:border-0"
              )}
            >
              {lang.name}
            </button>
          ))}
        </div>
      )}
    </div>
  );
}
