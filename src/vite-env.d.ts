/// <reference types="vite/client" />
/// <reference types="vite-plugin-pwa/client" />

declare global {
  interface Window {
    googleTranslateElementInit: () => void;
    google: any;
  }
}
