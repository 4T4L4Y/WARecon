document.addEventListener('DOMContentLoaded', () => {
  const sidebarMenu = document.getElementById('sidebar-menu');
  const backdrop = document.getElementById('sidebar-backdrop');
  const openBtn = document.getElementById('sidebar-open-btn');
  const closeBtn = document.getElementById('sidebar-close-btn');
  const collapseBtn = document.getElementById('sidebar-collapse-btn');
  const MOBILE_BP = 992;

  if (!sidebarMenu) return;

  const isMobile = () => window.innerWidth < MOBILE_BP;

  function openSidebar() {
    if (!isMobile()) return;
    sidebarMenu.classList.add('show');
    backdrop?.classList.add('show');
    document.body.classList.add('sidebar-open');
  }

  function closeSidebar() {
    sidebarMenu.classList.remove('show');
    backdrop?.classList.remove('show');
    document.body.classList.remove('sidebar-open');
  }

  openBtn?.addEventListener('click', (e) => {
    e.preventDefault();
    if (sidebarMenu.classList.contains('show')) {
      closeSidebar();
    } else {
      openSidebar();
    }
  });

  closeBtn?.addEventListener('click', (e) => {
    e.preventDefault();
    closeSidebar();
  });

  backdrop?.addEventListener('click', closeSidebar);

  sidebarMenu.querySelectorAll('.nav-link').forEach((link) => {
    link.addEventListener('click', () => {
      if (isMobile()) closeSidebar();
    });
  });

  collapseBtn?.addEventListener('click', () => {
    document.body.classList.toggle('sidebar-collapse');
    const icon = collapseBtn.querySelector('i');
    if (icon) {
      icon.classList.toggle('ti-layout-sidebar-left-collapse');
      icon.classList.toggle('ti-layout-sidebar-left-expand');
    }
  });

  window.addEventListener('resize', () => {
    if (!isMobile()) closeSidebar();
  });

  document.addEventListener('keydown', (e) => {
    if (e.key === 'Escape') closeSidebar();
  });
});
