/**
 * Modern UI: terminal panelleri, panoya kopyala, çıktı satır hover.
 */
document.addEventListener('DOMContentLoaded', () => {
  document.querySelectorAll('.result-output-rich').forEach((panel, index) => {
    if (panel.closest('.terminal-panel')) return;

    const wrapper = document.createElement('div');
    wrapper.className = 'terminal-panel';
    panel.parentNode.insertBefore(wrapper, panel);
    wrapper.appendChild(panel);

    const header = document.createElement('div');
    header.className = 'terminal-panel-header';
    header.innerHTML = `
      <div class="terminal-window-chrome">
        <span class="terminal-dot terminal-dot-red"></span>
        <span class="terminal-dot terminal-dot-yellow"></span>
        <span class="terminal-dot terminal-dot-green"></span>
      </div>
      <span class="terminal-panel-title">modül çıktısı</span>
      <button type="button" class="terminal-copy-btn" title="Panoya kopyala" aria-label="Panoya kopyala">
        <i class="fas fa-copy"></i><span>Kopyala</span>
      </button>`;
    wrapper.insertBefore(header, panel);

    panel.classList.add('terminal-body');

    const tabPane = panel.closest('.tab-pane');
    const tabLink = tabPane?.id
      ? document.querySelector(`[href="#${tabPane.id}"]`)
      : null;
    const title = header.querySelector('.terminal-panel-title');
    if (title && tabLink) {
      title.textContent = tabLink.textContent.trim() || `çıktı-${index + 1}`;
    }

    header.querySelector('.terminal-copy-btn')?.addEventListener('click', async () => {
      const text = panel.innerText || '';
      try {
        await navigator.clipboard.writeText(text);
        const btn = header.querySelector('.terminal-copy-btn');
        btn.classList.add('copied');
        const span = btn.querySelector('span');
        const prev = span.textContent;
        span.textContent = 'Kopyalandı';
        setTimeout(() => {
          btn.classList.remove('copied');
          span.textContent = prev;
        }, 1600);
      } catch (e) {
        /* fallback */
      }
    });
  });

  document.querySelectorAll('.output-rich .output-line').forEach((line) => {
    line.classList.add('terminal-line');
  });
});
