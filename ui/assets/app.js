// app.js — Shared utilities for WebVulnScanner UI

function truncate(s, n) {
  return s && s.length > n ? s.slice(0, n) + '…' : (s || '');
}

function riskClass(r) {
  if (r >= 70) return 'critical';
  if (r >= 40) return 'orange';
  if (r >= 20) return 'yellow';
  return 'cyan';
}

function severityClass(s) {
  const m = { CRITICAL: 'critical', HIGH: 'orange', MEDIUM: 'yellow', LOW: 'cyan' };
  return m[s] || 'dim';
}

function renderVulnTable(vulns) {
  if (!vulns || !vulns.length) {
    return `<div class="table-empty">No vulnerabilities found</div>`;
  }
  return `
    <table class="data-table">
      <thead>
        <tr>
          <th>TYPE</th><th>SEV</th><th>URL</th>
          <th>PARAM</th><th>CVSS</th><th>CWE</th><th>CONFIDENCE</th>
        </tr>
      </thead>
      <tbody>
        ${vulns.map(v => `
          <tr class="vuln-row" onclick="toggleEvidence(this)">
            <td>${v.type}</td>
            <td><span class="badge badge-sev-${v.severity}">${v.severity}</span></td>
            <td class="url-cell mono" title="${v.url}">${truncate(v.url, 45)}</td>
            <td class="mono dim">${v.parameter || '—'}</td>
            <td class="${riskClass((v.cvss_score||0)*10)}">${v.cvss_score || '—'}</td>
            <td class="mono dim">${v.cwe || '—'}</td>
            <td>
              <div class="conf-bar">
                <div class="conf-fill" style="width:${(v.confidence||0)*100}%"></div>
              </div>
              <span class="dim">${((v.confidence||0)*100).toFixed(0)}%</span>
            </td>
          </tr>
          <tr class="evidence-row" style="display:none">
            <td colspan="7" class="evidence-cell">
              <div class="evidence-content">
                <span class="evidence-label">EVIDENCE:</span> ${v.evidence || 'N/A'}<br>
                ${v.payload ? `<span class="evidence-label">PAYLOAD:</span> <code>${escapeHtml(v.payload)}</code>` : ''}
              </div>
            </td>
          </tr>
        `).join('')}
      </tbody>
    </table>
  `;
}

function toggleEvidence(row) {
  const next = row.nextElementSibling;
  if (next && next.classList.contains('evidence-row')) {
    next.style.display = next.style.display === 'none' ? '' : 'none';
  }
}

function escapeHtml(s) {
  return String(s)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;');
}