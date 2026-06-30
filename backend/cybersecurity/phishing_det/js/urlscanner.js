/* urlscanner.js */

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
  
  function setLoading(on) {
    const btn     = document.getElementById('scanBtn');
    const spinner = document.getElementById('scanSpinner');
    const txt     = document.getElementById('scanBtnText');
    if (!btn) return;
    btn.disabled          = on;
    spinner.style.display = on ? 'block' : 'none';
    txt.textContent       = on ? 'Scanning…' : '🔍 Scan URL';
  }
  
  function getTier(score, threatLevel) {
    const lvl = (threatLevel || '').toUpperCase();
    if (lvl === 'HIGH'   || score >= 60) return 'danger';
    if (lvl === 'MEDIUM' || score >= 30) return 'caution';
    if (score < 10)                       return 'safe';
    return 'info';
  }
  
  const TIER_CONFIG = {
    danger:  { icon: '🚨', label: 'HIGH RISK',  headline: 'Malicious URL detected',          desc: 'This URL has been flagged by threat engines or exhibits typosquatting patterns. Do not visit or share this link.' },
    caution: { icon: '⚠️', label: 'CAUTION',    headline: 'Suspicious URL — proceed with care', desc: 'This URL belongs to an unfamiliar domain or exhibits minor risk signals. Verify before clicking.' },
    safe:    { icon: '✅', label: 'CLEAN',       headline: 'URL appears safe',                desc: 'No malicious signals found. This domain has a clean threat intelligence record.' },
    info:    { icon: '🔵', label: 'EXTERNAL',   headline: 'External URL — standard caution', desc: 'This URL is external. No major threat signals detected, but exercise normal caution.' },
  };
  
  async function scanURL() {
    const urlInput = (document.getElementById('urlInput').value || '').trim();
    const errEl = document.getElementById('usError');
  
    if (!urlInput) {
      errEl.textContent = '⚠ Enter a URL to scan.';
      errEl.style.display = 'block';
      return;
    }
  
    errEl.style.display = 'none';
    setLoading(true);
    document.getElementById('usResultPanel').style.display = 'none';
  
    try {
      const res = await fetch(SCAN_API_URL, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ email: urlInput }), // re-uses same endpoint
      });
      if (!res.ok) throw new Error(`Server ${res.status}`);
      const data = await res.json();
      renderScanResult(data, urlInput);
    } catch (err) {
      // Demo data
      const score = urlInput.includes('microsofft') || urlInput.includes('paypa1') ? 88 : 12;
      renderScanResult({
        risk_score: score,
        tactics: score > 60 ? ['Typosquatting', 'Credential Theft'] : [],
        threat_level: score > 60 ? 'HIGH' : 'LOW',
        url_details: [{
          domain: new URL(urlInput.startsWith('http') ? urlInput : 'https://' + urlInput).hostname,
          ip: '203.0.113.42',
          city: 'Unknown',
          country: 'Unknown',
          isp: 'Unknown ISP',
          malicious_engines: score > 60 ? '3' : 'Unknown',
          suspicious_engines: 'Unknown',
        }],
      }, urlInput);
      errEl.textContent = `⚡ API unreachable — demo result shown.`;
      errEl.style.display = 'block';
    } finally {
      setLoading(false);
    }
  }
  
  function renderScanResult(data, url) {
    const score      = data.risk_score   ?? 0;
    const tactics    = data.tactics      ?? [];
    const urlDetails = data.url_details  ?? [];
    const tier       = getTier(score, data.threat_level);
    const cfg        = TIER_CONFIG[tier];
  
    // Banner
    const banner = document.getElementById('usResultBanner');
    banner.className = `us-result-banner tier-${tier}`;
    document.getElementById('usResultIcon').textContent     = cfg.icon;
    document.getElementById('usResultTier').textContent     = cfg.label;
    document.getElementById('usResultHeadline').textContent = cfg.headline;
    document.getElementById('usResultDesc').textContent     = cfg.desc;
  
    // Domain table
    const table = document.getElementById('domainTable');
    const fields = [['domain','Domain'],['ip','IP'],['city','City'],['country','Country'],['isp','ISP']];
    let rows = '<thead><tr><th>Field</th><th>Value</th></tr></thead><tbody>';
    (urlDetails[0] ? [urlDetails[0]] : []).forEach(u => {
      fields.forEach(([key, label]) => {
        if (u[key] != null) rows += `<tr><td>${label}</td><td class="val">${u[key]}</td></tr>`;
      });
      const malBad = u.malicious_engines && u.malicious_engines !== 'Unknown' && u.malicious_engines !== '0';
      rows += `<tr><td>Malicious Engines</td><td><span class="badge ${malBad ? 'badge-danger' : 'badge-safe'}">${u.malicious_engines ?? 'Unknown'}</span></td></tr>`;
      rows += `<tr><td>Suspicious Engines</td><td><span class="badge badge-info">${u.suspicious_engines ?? 'Unknown'}</span></td></tr>`;
    });
    rows += '</tbody>';
    table.innerHTML = rows;
  
    // Signals
    const signals = document.getElementById('threatSignals');
    const allSignals = [];
    if (score >= 60) allSignals.push({ cls:'signal-danger',  icon:'🚨', text:'<strong>High risk score</strong> — significant phishing indicators found.' });
    if (tactics.includes('Typosquatting')) allSignals.push({ cls:'signal-danger', icon:'🔡', text:'<strong>Typosquatting detected</strong> — domain closely mimics a trusted brand.' });
    if (tactics.includes('Credential Theft')) allSignals.push({ cls:'signal-danger', icon:'🔑', text:'<strong>Credential theft pattern</strong> — page likely harvests login data.' });
    if (score >= 30 && score < 60) allSignals.push({ cls:'signal-caution', icon:'⚠️', text:'<strong>Unfamiliar domain</strong> — not previously seen in your scan history.' });
    if (score < 30)  allSignals.push({ cls:'signal-safe',   icon:'✅', text:'<strong>Clean record</strong> — no threat engine flags found.' });
  
    signals.innerHTML = allSignals.map(s =>
      `<div class="us-signal ${s.cls}"><span class="us-signal-icon">${s.icon}</span><span class="us-signal-text">${s.text}</span></div>`
    ).join('');
  
    document.getElementById('usResultPanel').style.display = 'block';
  
    // Add to history table
    addHistoryRow(url, score, tier, data.threat_level);
  }
  
  function addHistoryRow(url, score, tier, lvl) {
    const body = document.getElementById('usHistoryBody');
    const badgeClass = { danger:'badge-danger', caution:'badge-caution', info:'badge-info', safe:'badge-safe' }[tier];
    const verdict = { danger:'Malicious', caution:'Suspicious', info:'External', safe:'Clean' }[tier];
    const row = document.createElement('tr');
    row.innerHTML = `
      <td class="us-url-cell">${url}</td>
      <td><span class="badge ${badgeClass}">${score}</span></td>
      <td><span class="badge ${badgeClass}">${verdict}</span></td>
      <td class="us-time">just now</td>
    `;
    body.insertBefore(row, body.firstChild);
  }
  
  document.getElementById('urlInput').addEventListener('keydown', e => {
    if (e.key === 'Enter') scanURL();
  });