/* dashboard.js */

/* ── TOAST (shared pattern) ── */
function showToast(msg, type = 'info') {
    const container = document.getElementById('toastContainer');
    if (!container) return;
    const icons = { success: '✅', error: '🚨', warn: '⚠️', info: 'ℹ️' };
    const el = document.createElement('div');
    el.className = `toast toast-${type === 'error' ? 'error' : type === 'warn' ? 'warn' : 'success'}`;
    el.innerHTML = `<span>${icons[type] || 'ℹ️'}</span> ${msg}`;
    container.appendChild(el);
    setTimeout(() => el.remove(), 4000);
  }
  
  /* ── TIER LOGIC (mirrors phishguard.js) ── */
  function getTier(score, threatLevel) {
    const lvl = (threatLevel || '').toUpperCase();
    if (lvl === 'HIGH'   || score >= 60) return 'danger';
    if (lvl === 'MEDIUM' || score >= 30) return 'caution';
    if (score < 10)                       return 'safe';
    return 'info';
  }
  
  const QS_TIER_CONFIG = {
    danger:  { icon: '🚨', label: 'HIGH RISK',  bg: 'var(--danger-bg)',  border: 'var(--danger-border)',  color: 'var(--danger)' },
    caution: { icon: '⚠️', label: 'CAUTION',    bg: 'var(--caution-bg)', border: 'var(--caution-border)', color: 'var(--caution)' },
    info:    { icon: '🔵', label: 'INFO',       bg: 'var(--info-bg)',    border: 'var(--info-border)',    color: 'var(--info)' },
    safe:    { icon: '✅', label: 'CLEAN',      bg: 'var(--safe-bg)',    border: 'var(--safe-border)',    color: 'var(--safe)' },
  };
  
  /* ── QUICK SCAN ── */
  async function quickScan() {
    const input = (document.getElementById('qsInput').value || '').trim();
    const resultEl = document.getElementById('qsResult');
    const spinner  = document.getElementById('qsSpinner');
    const btnText  = document.getElementById('qsBtnText');
  
    if (!input) {
      showToast('Paste an email or URL first.', 'warn');
      return;
    }
  
    spinner.style.display = 'block';
    btnText.textContent   = 'Scanning…';
    resultEl.style.display = 'none';
  
    // Determine endpoint dynamically — falls back gracefully if not present
    const endpoint = (window.DASH_API_URL || 'http://127.0.0.1:5000/analyze');
  
    try {
      const res = await fetch(endpoint, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ email: input }),
      });
      if (!res.ok) throw new Error(`Server ${res.status}`);
      const data = await res.json();
      renderQuickResult(data, input);
    } catch (err) {
      // Demo fallback — heuristic based on keywords so it still feels "smart"
      const lower = input.toLowerCase();
      let score = 6;
      let tactics = [];
      let level = 'LOW';
      if (lower.includes('urgent') || lower.includes('verify') || lower.includes('click here')) {
        score = 65; tactics = ['Urgency', 'Click Bait']; level = 'HIGH';
      } else if (lower.includes('login') || lower.includes('password') || lower.includes('confirm')) {
        score = 42; tactics = ['Credential Theft']; level = 'MEDIUM';
      }
      renderQuickResult({ risk_score: score, tactics, threat_level: level }, input);
      showToast('API unreachable — showing heuristic demo result.', 'warn');
    } finally {
      spinner.style.display = 'none';
      btnText.textContent   = '⚡ Quick Scan';
    }
  }
  
  function renderQuickResult(data, inputText) {
    const score = data.risk_score ?? 0;
    const tier  = getTier(score, data.threat_level);
    const cfg   = QS_TIER_CONFIG[tier];
  
    const resultEl = document.getElementById('qsResult');
    resultEl.style.display    = 'block';
    resultEl.style.background = cfg.bg;
    resultEl.style.border     = `1px solid ${cfg.border}`;
    resultEl.style.color      = cfg.color;
    resultEl.innerHTML = `
      <div style="display:flex;align-items:center;gap:8px;margin-bottom:4px">
        <span>${cfg.icon}</span>
        <span style="font-family:'JetBrains Mono',monospace;font-size:11px;letter-spacing:1px;text-transform:uppercase">${cfg.label}</span>
        <span style="margin-left:auto;font-family:'Space Grotesk',sans-serif;font-weight:700;font-size:15px">${score}/100</span>
      </div>
      <div style="font-size:12px;opacity:0.85;line-height:1.5">
        ${tactics_summary(data.tactics)}
      </div>
    `;
  
    // Push into the Recent Threats table at the top
    prependRecentThreat(inputText, score, tier);
  
    // Bump stat counters
    bumpStat(tier);
  }
  
  function tactics_summary(tactics) {
    if (!tactics || tactics.length === 0) return 'No phishing tactics detected.';
    return `Detected: ${tactics.join(', ')}`;
  }
  
  /* ── PREPEND TO RECENT THREATS TABLE ── */
  function prependRecentThreat(text, score, tier) {
    const tbody = document.getElementById('recentThreats');
    if (!tbody) return;
    const badgeClass = { danger: 'badge-danger', caution: 'badge-caution', info: 'badge-info', safe: 'badge-safe' }[tier];
    const row = document.createElement('tr');
    row.innerHTML = `
      <td class="threat-subject">${text.substring(0, 50)}${text.length > 50 ? '…' : ''}</td>
      <td><span class="badge badge-accent">Quick Scan</span></td>
      <td><span class="badge ${badgeClass}">${score}</span></td>
      <td class="threat-time">just now</td>
    `;
    tbody.insertBefore(row, tbody.firstChild);
  
    // Keep table from growing unbounded
    while (tbody.children.length > 8) {
      tbody.removeChild(tbody.lastChild);
    }
  }
  
  /* ── STAT COUNTER BUMP ── */
  function bumpStat(tier) {
    const map = { danger: 'statHighRisk', caution: 'statCaution', safe: 'statClean', info: 'statClean' };
    const id = map[tier];
    if (!id) return;
    const el = document.getElementById(id);
    if (!el) return;
    const current = parseInt(el.textContent, 10) || 0;
    el.textContent = current + 1;
    el.style.transition = 'color 0.3s';
    el.style.color = 'var(--accent)';
    setTimeout(() => { el.style.color = ''; }, 600);
  }
  
  /* ── ENTER KEY SUBMIT ── */
  document.addEventListener('DOMContentLoaded', () => {
    const qsInput = document.getElementById('qsInput');
    if (qsInput) {
      qsInput.addEventListener('keydown', e => {
        if ((e.ctrlKey || e.metaKey) && e.key === 'Enter') quickScan();
      });
    }
  });
  
  /* ── LIVE HEALTH PING (cosmetic) ── */
  function pulseHealthRow() {
    const rows = document.querySelectorAll('.health-row .badge-safe');
    rows.forEach(b => {
      b.style.transition = 'opacity 0.4s';
      b.style.opacity = '0.4';
      setTimeout(() => { b.style.opacity = '1'; }, 400);
    });
  }
  setInterval(pulseHealthRow, 15000);
