/* reports.js */

let currentTypeFilter  = 'all';
let currentLevelFilter = 'all';
let currentSearchTerm  = '';

/* ── TOAST ── */
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

/* ── FILTER BY TYPE ── */
function filterReports(btnEl, type) {
  currentTypeFilter = type;
  document.querySelectorAll('.rp-filter-btn[data-filter]').forEach(b => b.classList.remove('active'));
  btnEl.classList.add('active');
  applyFilters();
}

/* ── FILTER BY THREAT LEVEL ── */
function filterLevel(btnEl, level) {
  currentLevelFilter = level;
  document.querySelectorAll('.rp-filter-btn[data-level]').forEach(b => b.classList.remove('active'));
  btnEl.classList.add('active');
  applyFilters();
}

/* ── SEARCH ── */
function searchReports(term) {
  currentSearchTerm = term.trim().toLowerCase();
  applyFilters();
}

/* ── APPLY ALL FILTERS TOGETHER ── */
function applyFilters() {
  const rows = document.querySelectorAll('.rp-row');
  let visibleCount = 0;

  rows.forEach(row => {
    const matchesType  = currentTypeFilter === 'all' || row.dataset.type === currentTypeFilter;
    const matchesLevel = currentLevelFilter === 'all' || row.dataset.level === currentLevelFilter;
    const matchesSearch = !currentSearchTerm || row.dataset.subject.includes(currentSearchTerm);

    const visible = matchesType && matchesLevel && matchesSearch;
    row.classList.toggle('hidden', !visible);
    if (visible) visibleCount++;
  });

  const countEl = document.getElementById('reportCount');
  if (countEl) countEl.textContent = `${visibleCount} record${visibleCount === 1 ? '' : 's'}`;
}

/* ── EXPORT SINGLE REPORT AS PDF ── */
async function exportSinglePDF(reportId) {
  showToast(`Generating PDF for ${reportId}…`, 'info');
  try {
    const res = await fetch(`/export-report/${reportId}`, { method: 'GET' });
    if (!res.ok) throw new Error('Export failed');
    const blob = await res.blob();
    downloadBlob(blob, `${reportId}.pdf`);
    showToast(`${reportId}.pdf downloaded.`, 'success');
  } catch (err) {
    // Demo fallback: generate a plain text stand-in so the action is never a dead click
    console.warn('PDF export endpoint unavailable, generating fallback file:', err.message);
    const row = document.querySelector(`.rp-row td.rp-id`);
    const text = buildFallbackReportText(reportId);
    const blob = new Blob([text], { type: 'text/plain' });
    downloadBlob(blob, `${reportId}.txt`);
    showToast(`Report endpoint not connected — exported as .txt instead.`, 'warn');
  }
}

/* ── EXPORT ALL REPORTS AS PDF ── */
async function exportAllPDF() {
  showToast('Generating full report bundle…', 'info');
  try {
    const res = await fetch('/export-report/all', { method: 'GET' });
    if (!res.ok) throw new Error('Export failed');
    const blob = await res.blob();
    downloadBlob(blob, `securevault_reports_${Date.now()}.pdf`);
    showToast('All reports exported as PDF.', 'success');
  } catch (err) {
    console.warn('Bulk PDF export endpoint unavailable:', err.message);
    const rows = document.querySelectorAll('.rp-row:not(.hidden)');
    let text = 'SecureVault — Threat Report Export\n';
    text += `Generated: ${new Date().toISOString()}\n`;
    text += '='.repeat(50) + '\n\n';
    rows.forEach(row => {
      const cells = row.querySelectorAll('td');
      text += `ID: ${cells[0].textContent.trim()}\n`;
      text += `Subject: ${cells[1].textContent.trim()}\n`;
      text += `Type: ${cells[2].textContent.trim()}\n`;
      text += `Score: ${cells[3].textContent.trim()}\n`;
      text += `Threat Level: ${cells[4].textContent.trim()}\n`;
      text += `Status: ${cells[6].textContent.trim()}\n`;
      text += `Time: ${cells[7].textContent.trim()}\n`;
      text += '-'.repeat(40) + '\n';
    });
    const blob = new Blob([text], { type: 'text/plain' });
    downloadBlob(blob, `securevault_reports_${Date.now()}.txt`);
    showToast('PDF endpoint not connected — exported as .txt instead.', 'warn');
  }
}

/* ── HELPERS ── */
function downloadBlob(blob, filename) {
  const a = document.createElement('a');
  a.href = URL.createObjectURL(blob);
  a.download = filename;
  document.body.appendChild(a);
  a.click();
  a.remove();
  URL.revokeObjectURL(a.href);
}

function buildFallbackReportText(reportId) {
  const row = [...document.querySelectorAll('.rp-row')].find(r =>
    r.querySelector('.rp-id').textContent.trim() === reportId
  );
  if (!row) return `SecureVault Report\nID: ${reportId}\nNo data found.`;

  const cells = row.querySelectorAll('td');
  return [
    'SecureVault — Threat Report',
    '='.repeat(40),
    `Report ID:     ${cells[0].textContent.trim()}`,
    `Subject:       ${cells[1].textContent.trim()}`,
    `Type:          ${cells[2].textContent.trim()}`,
    `Risk Score:    ${cells[3].textContent.trim()}`,
    `Threat Level:  ${cells[4].textContent.trim()}`,
    `Status:        ${cells[6].textContent.trim()}`,
    `Timestamp:     ${cells[7].textContent.trim()}`,
    '',
    `Generated:     ${new Date().toISOString()}`,
  ].join('\n');
}

/* ── INIT COUNT ── */
document.addEventListener('DOMContentLoaded', applyFilters);