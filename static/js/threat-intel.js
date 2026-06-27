"""OSINT istihbarat paneli — tarama bitince otomatik yenile."""

document.addEventListener('DOMContentLoaded', () => {
  const card = document.getElementById('threatIntelCard');
  if (!card || !window.SCAN_INTEL_API) return;

  const statusBadge = card.querySelector('.card-header .badge');
  let pollTimer = null;

  function scoreRow(row, i) {
    const reasons = (row.live_reasons || [])
      .map((r) => `<span class="badge badge-default badge-sm badge-modern-muted">${r}</span>`)
      .join('');
    return `
      <tr>
        <td class="text-muted">${i + 1}</td>
        <td><a href="?host=${encodeURIComponent(row.hostname)}" class="text-info font-weight-bold">${row.hostname}</a></td>
        <td>
          <div class="score-cell">
            <div class="score-ring score-ring-${row.threat_level}" title="${row.risk_score}/100">
              <span>${row.risk_score}</span>
            </div>
            <div class="score-micro-bar">
              <div class="score-micro-bar-fill score-fill-${row.threat_level}" style="width:${row.risk_score}%"></div>
            </div>
          </div>
        </td>
        <td><span class="badge ${row.badge_class} badge-modern">${row.threat_label}</span></td>
        <td>
          <div class="live-status-cell">
            <span class="live-pulse-dot" title="Canlı"></span>
            ${reasons}
          </div>
        </td>
        <td class="small text-muted">${(row.summary || '').slice(0, 80)}</td>
      </tr>`;
  }

  function renderTopCritical(data) {
    if (!data.top_critical || !data.top_critical.length) return;
    const body = card.querySelector('.card-body');
    if (!body) return;
    const rows = data.top_critical.map((row, i) => scoreRow(row, i)).join('');
    body.innerHTML = `
      <p class="text-muted small mb-3">${data.queried} canlı alt alan skorlandı.</p>
      <h6 class="text-danger mb-3"><i class="tim-icons icon-trophy mr-1"></i>Top 5 Kritik Hedef</h6>
      <div class="table-responsive">
        <table class="table table-dark table-hover table-sm threat-intel-table mb-0">
          <thead><tr><th>#</th><th>Alt Alan</th><th>Skor</th><th>Durum</th><th>Canlılık</th><th>Özet</th></tr></thead>
          <tbody>${rows}</tbody>
        </table>
      </div>`;
    if (statusBadge) {
      statusBadge.className = 'badge badge-success badge-modern-success';
      statusBadge.textContent = 'Tamamlandı';
    }
  }

  async function poll() {
    try {
      const res = await fetch(window.SCAN_INTEL_API);
      const data = await res.json();
      if (!data.ok) return;
      if (data.status === 'running') {
        pollTimer = setTimeout(poll, 4000);
        return;
      }
      if (data.status === 'completed' && data.top_critical?.length) {
        renderTopCritical(data);
        clearTimeout(pollTimer);
      }
    } catch (e) {
      pollTimer = setTimeout(poll, 6000);
    }
  }

  if (statusBadge && statusBadge.textContent.includes('Sorgulanıyor')) {
    poll();
  }
});
