/**
 * assets/js/auth.js
 * ──────────────────
 * Lightweight frontend auth state helpers.
 *
 * Responsibilities:
 *   - Guard pages: redirect to login if not authenticated
 *   - setAuth() / clearAuth() for login/logout flows
 *   - isAuthenticated() for inline checks
 *
 * NOTE: Real authentication is server-side (session cookie).
 * localStorage.auth is only a client-side hint to skip the
 * initial /api/auth/me call when we know we're logged out.
 * api.js always validates against the server on initPage().
 */
const Auth = (() => {
    'use strict';
  
    const AUTH_KEY = 'auth';
    const LOGIN_URL = '/pages/auth/login.html';
  
    /**
     * Mark user as authenticated in localStorage.
     * Called after a successful login response.
     */
    function setAuth() {
      localStorage.setItem(AUTH_KEY, 'true');
    }
  
    /**
     * Clear auth flag and redirect to login.
     * Also fires POST /api/auth/logout to destroy server session.
     */
    async function logout() {
      try {
        await fetch('/api/auth/logout', {
          method: 'POST',
          credentials: 'include',
          headers: { 'Content-Type': 'application/json' },
        });
      } catch (_) {
        // ignore network error — still clear local state
      }
      localStorage.removeItem(AUTH_KEY);
      localStorage.removeItem('csrf_token');
      window.location.href = LOGIN_URL;
    }
  
    /**
     * Returns true if the client-side auth flag is set.
     * This is only a hint — the server always validates.
     */
    function isAuthenticated() {
      return localStorage.getItem(AUTH_KEY) === 'true';
    }
  
    /**
     * Redirect to login if the auth flag is not set.
     * Call at the top of every protected page (or use the
     * inline <script> guard instead for zero-flash redirect).
     */
    function requireAuth() {
      if (!isAuthenticated()) {
        window.location.href = LOGIN_URL;
      }
    }
  
    /**
     * Redirect to dashboard if already logged in.
     * Call on login/signup pages to skip them if already authenticated.
     */
    function redirectIfAuth() {
      if (isAuthenticated()) {
        window.location.href = '/';
      }
    }
  
    return { setAuth, logout, isAuthenticated, requireAuth, redirectIfAuth, AUTH_KEY };
  })();