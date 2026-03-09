/**
 * assets/js/charts.js
 * ─────────────────────
 * Dashboard charts using Chart.js.
 * Cyberpunk colour palette.
 */
const Charts = (() => {
    'use strict';
  
    const GREEN  = '#00ff9f';
    const CYAN   = '#00d4ff';
    const RED    = '#ff3c5a';
    const YELLOW = '#ffd700';
    const PURPLE = '#b347ea';
    const GRID   = 'rgba(0,255,159,0.08)';
    const TICK   = '#3d5a6e';
  
    function _baseOptions(yBegin = true) {
      return {
        responsive: true,
        maintainAspectRatio: false,
        animation: { duration: 600, easing: 'easeInOutQuart' },
        plugins: {
          legend: { display: false },
          tooltip: {
            backgroundColor: '#0a1628',
            borderColor: 'rgba(0,255,159,0.4)',
            borderWidth: 1,
            titleFont: { family: "'Share Tech Mono', monospace", size: 11 },
            bodyFont:  { family: "'Share Tech Mono', monospace", size: 11 },
            titleColor: '#00ff9f',
            bodyColor:  '#e0f0ff',
          },
        },
        scales: {
          x: {
            grid:  { color: GRID },
            ticks: { color: TICK, font: { family: "'Share Tech Mono', monospace", size: 10 }, maxRotation: 0 },
            border: { color: 'rgba(0,255,159,0.15)' },
          },
          y: {
            beginAtZero: yBegin,
            grid:  { color: GRID },
            ticks: { color: TICK, font: { family: "'Share Tech Mono', monospace", size: 10 } },
            border: { color: 'rgba(0,255,159,0.15)' },
          },
        },
      };
    }
  
    function _last7Labels() {
      const labels = [];
      for (let i = 6; i >= 0; i--) {
        const d = new Date();
        d.setDate(d.getDate() - i);
        labels.push(d.toLocaleDateString('en-US', { weekday: 'short', month: 'short', day: 'numeric' }));
      }
      return labels;
    }
  
    // ── Activity line chart ────────────────────────────────────────────────────
  
    let activityChart = null;
  
    function initActivity(canvasId) {
      const canvas = document.getElementById(canvasId);
      if (!canvas || typeof Chart === 'undefined') return;
  
      activityChart = new Chart(canvas.getContext('2d'), {
        type: 'line',
        data: {
          labels: _last7Labels(),
          datasets: [{
            label: 'Scans',
            data: [0,0,0,0,0,0,0],
            borderColor: GREEN,
            backgroundColor: 'rgba(0,255,159,0.06)',
            fill: true,
            tension: 0.35,
            pointBackgroundColor: GREEN,
            pointBorderColor: GREEN,
            pointRadius: 4,
            pointHoverRadius: 6,
          }],
        },
        options: _baseOptions(),
      });
    }
  
    function setActivityData(counts) {
      if (!activityChart) return;
      activityChart.data.labels = _last7Labels();
      activityChart.data.datasets[0].data = counts.slice(0, 7);
      activityChart.update();
    }
  
    // ── Status donut chart ────────────────────────────────────────────────────
  
    let statusChart = null;
  
    function initStatus(canvasId) {
      const canvas = document.getElementById(canvasId);
      if (!canvas || typeof Chart === 'undefined') return;
  
      statusChart = new Chart(canvas.getContext('2d'), {
        type: 'doughnut',
        data: {
          labels: ['Completed','Running','Pending','Failed'],
          datasets: [{
            data: [0,0,0,0],
            backgroundColor: [
              'rgba(0,255,159,0.7)',
              'rgba(255,215,0,0.7)',
              'rgba(0,212,255,0.7)',
              'rgba(255,60,90,0.7)',
            ],
            borderColor: ['#00ff9f','#ffd700','#00d4ff','#ff3c5a'],
            borderWidth: 1,
            hoverOffset: 6,
          }],
        },
        options: {
          responsive: true,
          maintainAspectRatio: false,
          cutout: '65%',
          plugins: {
            legend: {
              display: true,
              position: 'bottom',
              labels: {
                color: '#7a9ab0',
                font: { family: "'Share Tech Mono', monospace", size: 10 },
                padding: 12,
                boxWidth: 10,
              },
            },
            tooltip: {
              backgroundColor: '#0a1628',
              borderColor: 'rgba(0,255,159,0.4)',
              borderWidth: 1,
              titleFont: { family: "'Share Tech Mono', monospace", size: 11 },
              bodyFont:  { family: "'Share Tech Mono', monospace", size: 11 },
              titleColor: '#00ff9f',
              bodyColor:  '#e0f0ff',
            },
          },
        },
      });
    }
  
    function setStatusData(breakdown) {
      if (!statusChart) return;
      statusChart.data.datasets[0].data = [
        breakdown.completed || 0,
        breakdown.running   || 0,
        breakdown.pending   || 0,
        breakdown.failed    || 0,
      ];
      statusChart.update();
    }
  
    return { initActivity, setActivityData, initStatus, setStatusData };
  })();