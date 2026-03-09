/**
 * assets/js/dashboard.js
 * ────────────────────────
 * Dashboard page logic.
 *
 * - Fetches stats from /api/admin/stats (admin) or /api/scans + /api/profile/stats (user)
 * - Populates stat cards, activity chart, status donut chart
 * - Renders recent scans table
 * - Polls every 10s if any scans are active
 *
 * Depends on: api.js, charts.js
 */
const Dashboard = (() => {
    'use strict';
  
    let _pollTimer  = null;
    let _isAdmin    = false;
  
    // ── Helpers ──────────────────────────────────────────────────────────────
  
    function _set(id, value) {
      const el = document.getElementById(id);
      if (el) el.textContent = value ?? '—';
    }
  
    function _esc(s) {
      const d = document.createElement('div');
      d.textContent = s || '';
      return d.innerHTML;
    }
  
    function _badge(status) {
      const map = {
        completed: 'badge-completed', running: 'badge-running',
        pending:   'badge-pending',   failed:  'badge-failed',
      };
      return `<span class="badge ${map[status] || 'badge-pending'}">${_esc(status)}</span>`;
    }
  
    function _scanTypeTag(type) {
      return `<span class="scan-type-tag ${_esc(type)}">${_esc(type)}</span>`;
    }
  
    // ── Admin dashboard ───────────────────────────────────────────────────────
  
    async function _loadAdmin() {
      const stats = await Api.getJSON('/api/admin/stats');
      if (!stats) return;
  
      _set('statTotal',     stats.total_scans);
      _set('statActive',    stats.active_scans);
      _set('statUsers',     stats.total_users);
      _set('statScheduled', '—');
  
      if (window.Charts) {
        Charts.setActivityData(stats.daily_counts     || []);
        Charts.setStatusData(stats.status_breakdown   || {});
      }
  
      // Poll if active scans
      _schedulePoll(stats.active_scans > 0);
    }
  
    // ── Regular user dashboard ────────────────────────────────────────────────
  
    async function _loadUser() {
      const [scanData, profileStats] = await Promise.all([
        Api.getJSON('/api/scans/'),
        Api.getJSON('/api/profile/stats'),
      ]);
  
      const scans = scanData?.scans || [];
      const active = scans.filter(s => s.status === 'running' || s.status === 'pending').length;
  
      _set('statTotal',     scans.length);
      _set('statActive',    active);
      _set('statUsers',     '—');
      _set('statScheduled', profileStats?.scheduled_scans ?? 0);
  
      if (window.Charts && scans.length) {
        // Build 7-day counts from scan data
        const counts = Array(7).fill(0);
        const now = new Date();
        scans.forEach(s => {
          const d = s.created_at ? new Date(s.created_at) : null;
          if (!d || isNaN(d)) return;
          for (let i = 0; i < 7; i++) {
            const ref = new Date(now);
            ref.setDate(ref.getDate() - (6 - i));
            if (d.toDateString() === ref.toDateString()) { counts[i]++; break; }
          }
        });
        Charts.setActivityData(counts);
        Charts.setStatusData({
          completed: scans.filter(s => s.status === 'completed').length,
          running:   scans.filter(s => s.status === 'running').length,
          pending:   scans.filter(s => s.status === 'pending').length,
          failed:    scans.filter(s => s.status === 'failed').length,
        });
      }
  
      _schedulePoll(active > 0);
      return scans;
    }
  
    // ── Recent scans table ────────────────────────────────────────────────────
  
    async function _loadRecentScans() {
      const data = await Api.getJSON('/api/scans/');
      const scans = (data?.scans || []).slice(0, 10);
      const tbody = document.getElementById('recentScansBody');
      if (!tbody) return;
  
      if (!scans.length) {
        tbody.innerHTML = `
          <tr>
            <td colspan="7">
              <div class="empty-state">
                <span class="empty-icon">◎</span>
                <div class="empty-title">No scans yet</div>
                <div class="empty-sub"><a href="/scan.html">Launch your first scan →</a></div>
              </div>
            </td>
          </tr>`;
        return;
      }
  
      tbody.innerHTML = scans.map(s => `
        <tr>
          <td class="mono">${s.id}</td>
          <td class="text-cyan mono">${_esc(s.target)}</td>
          <td>${_scanTypeTag(s.scan_type)}</td>
          <td class="mono" style="color:var(--text-muted)">${_esc(s.ports)}</td>
          <td>${_badge(s.status)}</td>
          <td class="mono">${s.duration_seconds != null ? s.duration_seconds + 's' : '—'}</td>
          <td class="mono" style="color:var(--text-muted)">${(s.date || '').slice(0, 10)}</td>
        </tr>`
      ).join('');
    }
  
    // ── Polling ───────────────────────────────────────────────────────────────
  
    function _schedulePoll(shouldPoll) {
      if (shouldPoll && !_pollTimer) {
        _pollTimer = setInterval(load, 10000);
      } else if (!shouldPoll && _pollTimer) {
        clearInterval(_pollTimer);
        _pollTimer = null;
      }
    }
  
    // ── Timestamp ────────────────────────────────────────────────────────────
  
    function _updateTimestamp(username) {
      const el = document.getElementById('dashboardTs');
      if (el) {
        el.textContent = `SYSTEM TIME ${new Date().toLocaleString()} // USER: ${(username || '').toUpperCase()}`;
      }
    }
  
    // ── Public: load ─────────────────────────────────────────────────────────
  
    async function load() {
      if (_isAdmin) {
        await _loadAdmin();
      } else {
        await _loadUser();
      }
      await _loadRecentScans();
    }
  
    // ── Public: init ─────────────────────────────────────────────────────────
  
    async function init() {
      const me = await Api.initPage();
      if (!me || !me.authenticated) return;
  
      _isAdmin = me.role === 'admin';
      _updateTimestamp(me.username);
  
      // Wire logout
      const logoutBtn = document.getElementById('logoutBtn');
      if (logoutBtn) {
        logoutBtn.addEventListener('click', e => { e.preventDefault(); Api.logout(); });
      }
  
      // Init charts
      if (window.Charts) {
        Charts.initActivity('activityChart');
        Charts.initStatus('statusChart');
      }
  
      await load();
    }
  
    return { init, load };
  })();
  
  // Auto-init
  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', Dashboard.init);
  } else {
    Dashboard.init();
  }