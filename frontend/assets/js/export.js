/**
 * assets/js/export.js
 * ─────────────────────
 * Export helpers — trigger CSV and PDF downloads for scan results.
 *
 * Usage:
 *   Export.csv(scanId)          — download single scan as CSV
 *   Export.pdf(scanId)          — download single scan as PDF
 *   Export.allCsv()             — download all user scans as CSV
 *   Export.bindButtons(scanId)  — wire up #exportCsvBtn / #exportPdfBtn in DOM
 *
 * Downloads are triggered by navigating to the export API endpoint.
 * The backend sets Content-Disposition: attachment so the browser
 * saves the file rather than rendering it.
 */
const Export = (() => {
    'use strict';
  
    // ── Core download trigger ─────────────────────────────────────────────────
  
    /**
     * Trigger a file download by creating a temporary <a> tag.
     * @param {string} url      - The download URL
     * @param {string} filename - Suggested filename (may be overridden by server)
     */
    function _download(url, filename) {
      const a = document.createElement('a');
      a.href     = url;
      a.download = filename || '';
      a.style.display = 'none';
      document.body.appendChild(a);
      a.click();
      setTimeout(() => document.body.removeChild(a), 200);
    }
  
    // ── Single scan exports ───────────────────────────────────────────────────
  
    /**
     * Download a single scan as CSV.
     * @param {number|string} scanId
     */
    function csv(scanId) {
      if (!scanId) return;
      _download(`/api/export/scans/${scanId}/csv`, `scan_${scanId}.csv`);
      if (window.Api) Api.toast('CSV download started', 'success');
    }
  
    /**
     * Download a single scan as PDF.
     * @param {number|string} scanId
     */
    function pdf(scanId) {
      if (!scanId) return;
      _download(`/api/export/scans/${scanId}/pdf`, `scan_${scanId}.pdf`);
      if (window.Api) Api.toast('PDF download started', 'success');
    }
  
    // ── Bulk export ───────────────────────────────────────────────────────────
  
    /**
     * Download all user scans as a single CSV file.
     */
    function allCsv() {
      _download('/api/export/scans/csv', 'all_scans.csv');
      if (window.Api) Api.toast('Bulk CSV download started', 'success');
    }
  
    // ── DOM binding helpers ───────────────────────────────────────────────────
  
    /**
     * Bind export buttons by ID to a specific scan.
     * Looks for: #exportCsvBtn, #exportPdfBtn
     *
     * @param {number|string} scanId
     */
    function bindButtons(scanId) {
      const csvBtn = document.getElementById('exportCsvBtn');
      const pdfBtn = document.getElementById('exportPdfBtn');
  
      if (csvBtn) {
        csvBtn.addEventListener('click', e => {
          e.preventDefault();
          csv(scanId);
        });
      }
  
      if (pdfBtn) {
        pdfBtn.addEventListener('click', e => {
          e.preventDefault();
          pdf(scanId);
        });
      }
    }
  
    /**
     * Bind an "Export All CSV" button by ID.
     * Looks for: #exportAllBtn
     */
    function bindAllButton() {
      const btn = document.getElementById('exportAllBtn');
      if (btn) {
        btn.addEventListener('click', e => {
          e.preventDefault();
          allCsv();
        });
      }
    }
  
    /**
     * Attach export handlers to dynamically rendered rows.
     * Looks for buttons with data-export="csv|pdf" and data-scan-id="<id>".
     *
     * Example markup:
     *   <button data-export="csv" data-scan-id="42">CSV</button>
     *   <button data-export="pdf" data-scan-id="42">PDF</button>
     */
    function delegateTableButtons(containerEl) {
      if (!containerEl) return;
      containerEl.addEventListener('click', e => {
        const btn = e.target.closest('[data-export]');
        if (!btn) return;
        const type   = btn.dataset.export;
        const scanId = btn.dataset.scanId;
        if (!scanId) return;
        if (type === 'csv') csv(scanId);
        if (type === 'pdf') pdf(scanId);
      });
    }
  
    // ── Public API ────────────────────────────────────────────────────────────
  
    return { csv, pdf, allCsv, bindButtons, bindAllButton, delegateTableButtons };
  })();