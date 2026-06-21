document.addEventListener('DOMContentLoaded', () => {
  const bell = document.getElementById('notificationBell');
  const countEl = document.getElementById('notificationCount');
  const listEl = document.getElementById('notificationList');
  const dropdown = document.getElementById('notificationDropdown');
  if (!bell || !listEl) return;

  let latestItems = [];

  function escapeHtml(text) {
    const div = document.createElement('div');
    div.textContent = text || '';
    return div.innerHTML;
  }

  function levelClass(level) {
    if (level === 'critical') return 'text-danger';
    if (level === 'warning') return 'text-warning';
    if (level === 'success') return 'text-success';
    return 'text-info';
  }

  function renderList(items) {
    latestItems = items || [];
    if (!latestItems.length) {
      listEl.innerHTML = '<span class="dropdown-item text-muted disabled">Bildirim yok</span>';
      return;
    }
    listEl.innerHTML = latestItems.map((item) => {
      const href = item.scan_id ? `/history/${item.scan_id}/` : '/history/';
      const unread = item.is_read ? '' : ' notification-item-unread';
      return `
        <a href="${href}" class="dropdown-item notification-item${unread}" data-id="${item.id}">
          <div class="notification-item-title ${levelClass(item.level)}">${escapeHtml(item.title)}</div>
          <div class="notification-item-message text-muted">${escapeHtml(item.message)}</div>
          <div class="notification-item-time">${escapeHtml(item.time)}</div>
        </a>`;
    }).join('');
  }

  function poll() {
    return fetch('/api/notifications/')
      .then((r) => r.json())
      .then((data) => {
        const count = data.count || 0;
        if (countEl) {
          countEl.textContent = count;
          countEl.classList.toggle('d-none', count === 0);
        }
        renderList(data.items || []);
        if (count > 0) {
          bell.title = `${count} okunmamış bildirim`;
        } else {
          bell.title = 'Bildirimler';
        }
      })
      .catch(() => {});
  }

  function markRead() {
    return fetch('/notifications/read/', {
      method: 'POST',
      headers: { 'X-CSRFToken': getCsrfToken() },
    }).then(() => poll()).catch(() => poll());
  }

  if (dropdown && typeof $ !== 'undefined') {
    $(dropdown).on('show.bs.dropdown', () => {
      poll().then(() => {
        if ((countEl && !countEl.classList.contains('d-none')) || latestItems.some((i) => !i.is_read)) {
          markRead();
        }
      });
    });
  }

  listEl.addEventListener('click', (e) => {
    const link = e.target.closest('.notification-item');
    if (!link) return;
    e.preventDefault();
    const href = link.getAttribute('href');
    markRead().finally(() => {
      window.location.href = href;
    });
  });

  poll();
  setInterval(poll, 30000);
});

function getCsrfToken() {
  const match = document.cookie.match(/csrftoken=([^;]+)/);
  if (match) return match[1];
  const input = document.querySelector('input[name="csrfmiddlewaretoken"]');
  return input ? input.value : '';
}
