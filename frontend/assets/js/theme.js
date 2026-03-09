/**
 * assets/js/theme.js
 * ───────────────────
 * Dark / Light theme toggle.
 *
 * NetScanner defaults to dark (cyberpunk) theme.
 * A light mode variant is available as a user preference.
 *
 * Usage:
 *   Theme.init()       — call on DOMContentLoaded (or inline in <body>)
 *   Theme.toggle()     — flip between dark/light
 *   Theme.get()        — returns 'dark' | 'light'
 *   Theme.set('light') — programmatically set theme
 */
const Theme = (() => {
    'use strict';
  
    const KEY   = 'theme';
    const DARK  = 'dark';
    const LIGHT = 'light';
  
    function get() {
      return localStorage.getItem(KEY) || DARK; // default dark
    }
  
    function set(value) {
      localStorage.setItem(KEY, value);
      _apply(value);
      _updateToggleUI(value);
      // Notify charts if present
      if (window.Charts && typeof Charts.updateTheme === 'function') {
        Charts.updateTheme(value);
      }
    }
  
    function toggle() {
      set(get() === DARK ? LIGHT : DARK);
    }
  
    function _apply(value) {
      if (value === LIGHT) {
        document.body.classList.add('theme-light');
        document.body.classList.remove('theme-dark');
      } else {
        document.body.classList.add('theme-dark');
        document.body.classList.remove('theme-light');
      }
    }
  
    function _updateToggleUI(value) {
      const btn   = document.getElementById('themeToggle');
      const icon  = document.getElementById('themeIcon');
      const label = document.getElementById('themeLabel');
      if (!btn) return;
  
      if (value === DARK) {
        if (icon)  icon.textContent  = '◑';
        if (label) label.textContent = 'Light Mode';
        btn.setAttribute('title', 'Switch to light mode');
      } else {
        if (icon)  icon.textContent  = '●';
        if (label) label.textContent = 'Dark Mode';
        btn.setAttribute('title', 'Switch to dark mode');
      }
    }
  
    function init() {
      // Apply theme immediately to prevent flash
      _apply(get());
      _updateToggleUI(get());
  
      // Wire up toggle button if present
      const btn = document.getElementById('themeToggle');
      if (btn) {
        btn.addEventListener('click', e => {
          e.preventDefault();
          toggle();
        });
      }
    }
  
    // Apply theme as early as possible (before DOM is ready)
    // to avoid flash of unstyled content
    _apply(get());
  
    return { get, set, toggle, init };
  })();
  
  // Auto-init on DOM ready
  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', Theme.init);
  } else {
    Theme.init();
  }