/**
 * assets/js/api.js
 * ─────────────────
 * Centralised API client.
 *
 * Usage:
 *   const data = await Api.get('/api/scans');
 *   await Api.post('/api/scans', { target: '192.168.1.1', ... });
 *   Api.toast('Scan started', 'success');
 */
const Api = (() => {
    'use strict';
  
    const CSRF_KEY  = 'csrf_token';
    const AUTH_KEY  = 'auth';
    const THEME_KEY = 'theme';
  
    // ── CSRF ─────────────────────────────────────────────────────────────────
  
    function getCsrf() {
      return localStorage.getItem(CSRF_KEY) || '';
    }
  
    function setCsrf(token) {
      if (token) localStorage.setItem(CSRF_KEY, token);
    }
  
    // ── Core fetch ────────────────────────────────────────────────────────────
  
    async function request(method, url, body) {
      const headers = { 'Content-Type': 'application/json' };
      const csrf = getCsrf();
      if (csrf && /^(POST|PUT|PATCH|DELETE)$/i.test(method)) {
        headers['X-CSRF-Token'] = csrf;
      }
  
      const opts = { method, headers, credentials: 'include' };
      if (body !== undefined) opts.body = JSON.stringify(body);
  
      const res = await fetch(url, opts);
  
      if (res.status === 401) {
        localStorage.removeItem(AUTH_KEY);
        window.location.replace('/login');
        return null;
      }
  
      return res;
    }
  
    async function get(url)              { return request('GET',    url); }
    async function post(url, body)       { return request('POST',   url, body); }
    async function patch(url, body)      { return request('PATCH',  url, body); }
    async function del(url)              { return request('DELETE', url); }
  
    // Convenience: fetch + parse JSON in one call
    async function getJSON(url) {
      const res = await get(url);
      if (!res) return null;
      if (!res.ok) return null;
      return res.json();
    }
  
    // ── Auth refresh ──────────────────────────────────────────────────────────
  
    /**
     * Refresh session info from /api/auth/me.
     * Updates csrf_token in localStorage.
     * Returns user data object, or {} on failure.
     */
    async function refreshAuth() {
      try {
        const res = await fetch('/api/auth/me', { credentials: 'include' });
        if (res.status === 401) {
          localStorage.removeItem(AUTH_KEY);
          window.location.replace('/login');
          return {};
        }
        const data = await res.json();
        if (data && data.csrf_token) setCsrf(data.csrf_token);
        return data || {};
      } catch (_) {
        return {};
      }
    }
  
    // ── Toast notifications ───────────────────────────────────────────────────
  
    function toast(message, type = 'info', duration = 4000) {
      let stack = document.getElementById('toastStack');
      if (!stack) {
        stack = document.createElement('div');
        stack.id = 'toastStack';
        stack.className = 'toast-stack';
        document.body.appendChild(stack);
      }
  
      const el = document.createElement('div');
      el.className = `toast toast-${type}`;
      el.innerHTML = `<span class="toast-dot"></span><span>${_esc(message)}</span>`;
      stack.appendChild(el);
  
      setTimeout(() => {
        el.style.opacity = '0';
        el.style.transform = 'translateX(20px)';
        el.style.transition = 'opacity 0.3s, transform 0.3s';
        setTimeout(() => el.remove(), 350);
      }, duration);
    }
  
    // ── HTML escape ───────────────────────────────────────────────────────────
  
    function _esc(s) {
      const d = document.createElement('div');
      d.textContent = String(s);
      return d.innerHTML;
    }

    // ── Theme (dark/light) ────────────────────────────────────────────────────

    function getTheme() {
      return localStorage.getItem(THEME_KEY) || 'dark';
    }

    function applyTheme(theme) {
      const next = theme === 'light' ? 'light' : 'dark';
      document.body.classList.toggle('theme-light', next === 'light');
      document.body.classList.toggle('theme-dark', next !== 'light');
      localStorage.setItem(THEME_KEY, next);
      updateThemeToggleUI(next);
    }

    function toggleTheme() {
      applyTheme(getTheme() === 'dark' ? 'light' : 'dark');
    }

    function updateThemeToggleUI(theme) {
      const icon = document.getElementById('themeIcon');
      const label = document.getElementById('themeLabel');
      const btn = document.getElementById('themeToggle');
      if (icon) icon.textContent = theme === 'light' ? '●' : '◑';
      if (label) label.textContent = theme === 'light' ? 'Dark Mode' : 'Light Mode';
      if (btn) btn.title = theme === 'light' ? 'Switch to dark mode' : 'Switch to light mode';
    }

    function ensureThemeToggle() {
      const sidebarFooter = document.querySelector('.sidebar-footer');
      if (!sidebarFooter || document.getElementById('themeToggle')) return;

      const btn = document.createElement('a');
      btn.href = '#';
      btn.id = 'themeToggle';
      btn.className = 'nav-link';
      btn.innerHTML = '<span id="themeIcon">◑</span><span id="themeLabel">Light Mode</span>';
      btn.addEventListener('click', (e) => {
        e.preventDefault();
        toggleTheme();
      });
      sidebarFooter.insertBefore(btn, sidebarFooter.firstChild);
      updateThemeToggleUI(getTheme());
    }
  
    // ── Sidebar admin nav reveal ──────────────────────────────────────────────
  
    async function initPage() {
      ensureThemeToggle();
      applyTheme(getTheme());

      const data = await refreshAuth();
      if (!data || !data.authenticated) return data;
  
      // Show admin nav if admin
      const navAdmin = document.getElementById('navAdmin');
      if (navAdmin && data.role === 'admin') navAdmin.classList.remove('hidden');
  
      // Populate user badge
      const userName  = document.getElementById('sidebarUsername');
      const userRole  = document.getElementById('sidebarRole');
      const userAvatar = document.getElementById('sidebarAvatar');
      if (userName)  userName.textContent  = data.username || '';
      if (userRole)  userRole.textContent  = data.role     || 'user';
      if (userAvatar) {
        userAvatar.textContent = (data.username || 'U')[0].toUpperCase();
        if (data.avatar_color) userAvatar.style.borderColor = data.avatar_color;
      }

      // Sidebar toggle (mobile)
      const sidebar = document.querySelector('.sidebar');
      const toggle  = document.getElementById('sidebarToggle');
      if (sidebar && toggle && !toggle.dataset.bound) {
        toggle.dataset.bound = '1';
        toggle.addEventListener('click', () => {
          const isOpen = sidebar.classList.toggle('is-open');
          document.body.classList.toggle('sidebar-open', isOpen);
        });
      }
  
      return data;
    }
  
    // ── Logout ────────────────────────────────────────────────────────────────
  
    async function logout() {
      try { await post('/api/auth/logout'); } catch (_) {}
      localStorage.removeItem(AUTH_KEY);
      localStorage.removeItem(CSRF_KEY);
      window.location.replace('/login');
    }
  
    // ── Public API ────────────────────────────────────────────────────────────
  
    return { get, post, patch, del, getJSON, request, getCsrf, setCsrf,
             refreshAuth, toast, initPage, logout, _esc, getTheme, applyTheme, toggleTheme };
  })();