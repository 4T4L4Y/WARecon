"""OSINT istihbarat paneli — tarama bitince otomatik yenile."""

document.addEventListener("DOMContentLoaded", () => {
  const card = document.getElementById('threatIntelCard');
  if (!card || !window.SCAN_INTEL_API) return;

  const statusBadge = card.querySelector('.card-header .badge');
  let pollTimer = null;

  function renderTopCritical(data) {
    if (!data.top_critical || !data.top_critical.length) return;
    const body = card.querySelector('.card-body');
    if (!body) return;
    const rows = data.top_critical.map((row, i) => `
      <tr>
        <td>${i + 1}</td>
        <td><a href="?host=${encodeURIComponent(row.hostname)}" class="text-info">${row.hostname}</a></td>
        <td><span class="threat-score threat-score-${row.threat_level}">${row.risk_score}</span></td>
        <td><span class="badge ${row.badge_class}">${row.threat_label}</span></td>
        <td>${(row.live_reasons || []).map((r) => `<span class="badge badge-default badge-sm">${r}</span>`).join(' ')}</td>
        <td class="small text-muted">${(row.summary || '').slice(0, 80)}</td>
      </tr>`).join('');
    body.innerHTML = `
      <p class="text-muted small mb-3">${data.queried} canlı alt alan skorlandı.</p>
      <h6 class="text-danger mb-3">Top 5 Kritik Hedef</h6>
      <div class="table-responsive">
        <table class="table table-dark table-striped table-sm threat-intel-table mb-0">
          <thead><tr><th>#</th><th>Alt Alan</th><th>Skor</th><th>Durum</th><th>Canlılık</th><th>Özet</th></tr></thead>
          <tbody>${rows}</tbody>
        </table>
      </div>`;
    if (statusBadge) {
      statusBadge.className = 'badge badge-success';
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
