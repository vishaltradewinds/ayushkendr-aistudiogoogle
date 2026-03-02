import React, { useEffect } from 'react';

const GoogleTranslate = () => {
  useEffect(() => {
    // Check if the script is already added
    if (!document.querySelector('#google-translate-script')) {
      const script = document.createElement('script');
      script.id = 'google-translate-script';
      script.src = '//translate.google.com/translate_a/element.js?cb=googleTranslateElementInit';
      script.async = true;
      document.body.appendChild(script);

      window.googleTranslateElementInit = () => {
        new window.google.translate.TranslateElement(
          {
            pageLanguage: 'en',
            includedLanguages: 'hi,bn,te,mr,ta,ur,gu,kn,ml,pa,or,as,mai,sa,sd,ks,ne,doi,brx,mni,kok,sat,en',
            layout: window.google.translate.TranslateElement.InlineLayout.SIMPLE,
          },
          'google_translate_element'
        );
      };
    } else if (window.google && window.google.translate) {
      // If script is already loaded and we remounted, we might need to re-initialize
      // However, Google Translate widget doesn't support re-initialization easily on the same ID.
      // Usually, keeping it in the DOM or hiding/showing is better.
    }
  }, []);

  return <div id="google_translate_element" className="inline-block"></div>;
};

export default GoogleTranslate;
