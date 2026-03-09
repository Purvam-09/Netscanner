/**
 * assets/js/socket.js
 * ─────────────────────
 * WebSocket client for real-time scan progress updates.
 *
 * Requires socket.io client (loaded from CDN).
 *
 * Usage:
 *   WS.init();                          // call on page load
 *   WS.onScanUpdate(cb);               // cb({ scan_id, status, progress, ... })
 *   WS.offScanUpdate(cb);              // remove listener
 */
const WS = (() => {
    'use strict';
  
    let _socket      = null;
    let _listeners   = [];
    let _connected   = false;
    let _retries     = 0;
    const MAX_RETRIES = 5;
  
    function init() {
      if (typeof io === 'undefined') {
        console.warn('[WS] socket.io not loaded');
        return;
      }
  
      _socket = io({
        path: '/socket.io',
        transports: ['websocket', 'polling'],
        reconnectionAttempts: MAX_RETRIES,
        reconnectionDelay: 1500,
      });
  
      _socket.on('connect', () => {
        _connected = true;
        _retries   = 0;
        _socket.emit('join_room', {});
        console.info('[WS] Connected, joined room');
      });
  
      _socket.on('disconnect', () => {
        _connected = false;
        console.info('[WS] Disconnected');
      });
  
      _socket.on('reconnect_failed', () => {
        console.warn('[WS] Reconnect failed after', MAX_RETRIES, 'attempts');
      });
  
      _socket.on('scan_update', (payload) => {
        console.debug('[WS] scan_update', payload);
        _listeners.forEach(cb => {
          try { cb(payload); } catch (e) { console.error('[WS] listener error', e); }
        });
      });
  
      _socket.on('connect_error', (err) => {
        console.warn('[WS] connect error:', err.message);
      });
    }
  
    function onScanUpdate(cb) {
      if (!_listeners.includes(cb)) _listeners.push(cb);
    }
  
    function offScanUpdate(cb) {
      _listeners = _listeners.filter(l => l !== cb);
    }
  
    function isConnected() { return _connected; }
  
    return { init, onScanUpdate, offScanUpdate, isConnected };
  })();