/**
 * assets/js/terminal.js
 * ───────────────────────
 * Terminal-style output renderer for the scan page.
 *
 * Features:
 *   - Append lines with syntax-coloured spans
 *   - Auto-scroll to bottom
 *   - Typed-text animation for single lines
 *   - Clear, header, separator helpers
 *   - Renders open port results as a formatted table
 *
 * Usage:
 *   Terminal.init('terminalElementId');
 *   Terminal.line('Scanning target…');
 *   Terminal.line('Port 80 open', 'green');
 *   Terminal.renderPorts(openPortsArray);
 *   Terminal.clear();
 */
const Terminal = (() => {
    'use strict';
  
    let _el  = null;  // DOM element
    let _buf = [];    // line buffer
  
    // ── Colour map ────────────────────────────────────────────────────────────
    const COLOURS = {
      green:  'var(--accent-green)',
      cyan:   'var(--accent-cyan)',
      red:    'var(--accent-red)',
      yellow: 'var(--accent-yellow)',
      muted:  'var(--text-muted)',
      white:  'var(--text-primary)',
      purple: 'var(--accent-purple)',
    };
  
    // ── Escape HTML ───────────────────────────────────────────────────────────
    function _esc(s) {
      const d = document.createElement('div');
      d.textContent = String(s || '');
      return d.innerHTML;
    }
  
    // ── Core append ───────────────────────────────────────────────────────────
  
    /**
     * Append a line to the terminal.
     * @param {string}  text    - Content (will be HTML-escaped unless raw=true)
     * @param {string}  colour  - Key from COLOURS map, or CSS colour string
     * @param {boolean} raw     - If true, text is inserted as raw HTML
     * @param {string}  prefix  - Optional prefix (e.g. '>', '[INFO]')
     */
    function line(text, colour, raw, prefix) {
      if (!_el) return;
  
      const col   = COLOURS[colour] || colour || COLOURS.white;
      const pre   = prefix ? `<span style="color:var(--text-muted)">${_esc(prefix)} </span>` : '';
      const body  = raw ? text : `<span style="color:${col}">${_esc(text)}</span>`;
      const html  = `<div class="t-line">${pre}${body}</div>`;
  
      _el.insertAdjacentHTML('beforeend', html);
      _el.scrollTop = _el.scrollHeight;
    }
  
    function info(text)    { line(text, 'cyan',   false, '[INFO]');  }
    function success(text) { line(text, 'green',  false, '[OK]');    }
    function error(text)   { line(text, 'red',    false, '[ERR]');   }
    function warn(text)    { line(text, 'yellow', false, '[WARN]');  }
    function dim(text)     { line(text, 'muted');                    }
    function sep()         { dim('─'.repeat(52));                    }
  
    /**
     * Print a header block.
     * @param {string} title
     */
    function header(title) {
      sep();
      line(`  ${title.toUpperCase()}`, 'green');
      sep();
    }
  
    /**
     * Render a scan start summary.
     */
    function scanStart(target, portRange, scanType) {
      header('SCAN INITIATED');
      line(`TARGET    ${target}`,    'cyan');
      line(`PORTS     ${portRange}`, 'cyan');
      line(`TYPE      ${scanType}`,  'cyan');
      line(`TIME      ${new Date().toISOString()}`, 'muted');
      sep();
      dim('Resolving target…');
    }
  
    /**
     * Render open ports table from results array.
     * @param {Array} ports  — [ { port, protocol, service, banner, state }, ... ]
     */
    function renderPorts(ports) {
      sep();
      if (!ports || !ports.length) {
        warn('No open ports found on target.');
        sep();
        return;
      }
  
      success(`${ports.length} open port(s) discovered:`);
      sep();
  
      // Column widths
      const COL_PORT    = 7;
      const COL_PROTO   = 6;
      const COL_SERVICE = 14;
      const COL_STATE   = 14;
  
      function pad(s, n) { return String(s).padEnd(n); }
  
      // Header row
      const hdr = `${pad('PORT', COL_PORT)}${pad('PROTO', COL_PROTO)}${pad('SERVICE', COL_SERVICE)}${pad('STATE', COL_STATE)}BANNER`;
      dim(hdr);
      dim('─'.repeat(52));
  
      ports.forEach(p => {
        const row = `${pad(p.port, COL_PORT)}${pad(p.protocol || 'tcp', COL_PROTO)}${pad(p.service || '?', COL_SERVICE)}${pad(p.state || 'open', COL_STATE)}${(p.banner || '').slice(0, 30)}`;
        // Colour by service type
        let col = 'green';
        if (['http','http-alt','http-alt2'].includes(p.service)) col = 'cyan';
        else if (['ssh','telnet','rdp','vnc'].includes(p.service))    col = 'yellow';
        else if (['mysql','postgresql','mssql','mongodb','redis'].includes(p.service)) col = 'purple';
        else if (p.service === 'unknown') col = 'muted';
        line(row, col);
      });
  
      sep();
    }
  
    /**
     * Render scan completion summary.
     */
    function scanComplete(duration, openCount) {
      success(`Scan completed in ${duration}s`);
      line(`${openCount} open port(s) found`, openCount > 0 ? 'yellow' : 'muted');
      dim(`View full results → /results.html`);
      sep();
    }
  
    function scanFailed(errorMsg) {
      error(`Scan failed: ${errorMsg}`);
      sep();
    }
  
    // ── Typed text effect ─────────────────────────────────────────────────────
  
    /**
     * Append text one character at a time.
     * @param {string}   text      - Text to type
     * @param {string}   colour    - Colour key
     * @param {number}   delay     - ms per character (default 18)
     * @returns {Promise}          - Resolves when typing is done
     */
    function type(text, colour, delay = 18) {
      return new Promise(resolve => {
        if (!_el) { resolve(); return; }
        const col = COLOURS[colour] || colour || COLOURS.white;
        const span = document.createElement('span');
        span.style.color = col;
        const wrapper = document.createElement('div');
        wrapper.className = 't-line';
        wrapper.appendChild(span);
        _el.appendChild(wrapper);
  
        let i = 0;
        const interval = setInterval(() => {
          span.textContent += text[i++];
          _el.scrollTop = _el.scrollHeight;
          if (i >= text.length) {
            clearInterval(interval);
            resolve();
          }
        }, delay);
      });
    }
  
    // ── Clear ─────────────────────────────────────────────────────────────────
  
    function clear() {
      if (_el) _el.innerHTML = '';
    }
  
    // ── Init ──────────────────────────────────────────────────────────────────
  
    function init(elementId) {
      _el = document.getElementById(elementId);
      if (!_el) console.warn(`[Terminal] element #${elementId} not found`);
      return Terminal; // allow chaining
    }
  
    // ── Public API ────────────────────────────────────────────────────────────
  
    return {
      init,
      line, info, success, error, warn, dim, sep, header, type, clear,
      scanStart, renderPorts, scanComplete, scanFailed,
    };
  })();