document.addEventListener('DOMContentLoaded', () => {
  const bell = document.getElementById('notificationBell');
  const countEl = document.getElementById('notificationCount');
  if (!bell) return;

  function poll() {
    fetch('/api/notifications/')
      .then((r) => r.json())
      .then((data) => {
        const count = data.count || 0;
        if (countEl) {
          countEl.textContent = count;
          countEl.classList.toggle('d-none', count === 0);
        }
        if (count > 0) {
          bell.title = data.items?.[0]?.title || 'Yeni bildirim';
        }
      })
      .catch(() => {});
  }

  bell.addEventListener('click', (e) => {
    e.preventDefault();
    fetch('/notifications/read/', {
      method: 'POST',
      headers: { 'X-CSRFToken': getCsrfToken() },
    }).finally(() => {
      poll();
      window.location.href = '/history/';
    });
  });

  poll();
  setInterval(poll, 30000);
});

function getCsrfToken() {
  const match = document.cookie.match(/csrftoken=([^;]+)/);
  return match ? match[1] : '';
}
