document.addEventListener('DOMContentLoaded', () => {
  const bar = document.getElementById('progressBar');
  const msg = document.getElementById('progressMessage');
  const pct = document.getElementById('progressPercent');
  const badge = document.getElementById('statusBadge');
  const moduleInfo = document.getElementById('moduleInfo');

  const source = new EventSource(window.SCAN_EVENTS_URL);

  source.onmessage = (event) => {
    const data = JSON.parse(event.data);
    bar.style.width = `${data.percent}%`;
    bar.classList.remove('progress-bar-indeterminate');
    pct.textContent = `${data.percent}%`;
    msg.textContent = data.message || 'İşleniyor…';
    if (data.module) {
      moduleInfo.textContent = `Aktif modül: ${data.module}`;
    }
    if (data.status === 'completed') {
      badge.textContent = 'Tamamlandı';
      badge.className = 'badge badge-success';
      source.close();
      setTimeout(() => { window.location.href = window.SCAN_DETAIL_URL; }, 800);
    } else if (data.status === 'failed') {
      badge.textContent = 'Başarısız';
      badge.className = 'badge badge-danger';
      msg.textContent = data.error || data.message || 'Tarama başarısız.';
      source.close();
    }
  };

  source.onerror = () => {
    source.close();
  };
});
