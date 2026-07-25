(function () {
  const year = document.getElementById('year');
  if (year) year.textContent = String(new Date().getFullYear());

  const cfg = window.VELORA_SITE || {};
  const versionLabel = document.getElementById('versionLabel');
  if (versionLabel && cfg.version) versionLabel.textContent = `v${cfg.version}`;

  const downloadBtn = document.getElementById('downloadBtn');
  const portableBtn = document.getElementById('portableBtn');

  const owner = 'Harne123';
  const repo = 'velora1';
  const ver = cfg.version || '1.3.1';
  const fallbackSetup = `https://github.com/${owner}/${repo}/releases/latest/download/Velora-${ver}-x64.exe`;
  const fallbackPortable = `https://github.com/${owner}/${repo}/releases/latest/download/Velora-${ver}-Portable.exe`;

  if (downloadBtn) {
    downloadBtn.setAttribute('href', cfg.downloadUrl || fallbackSetup);
    downloadBtn.setAttribute('download', '');
  }
  if (portableBtn) {
    portableBtn.setAttribute('href', cfg.portableUrl || fallbackPortable);
  }
  // cache-bust hint in console for support
  console.info('[Velora site]', ver, cfg.downloadUrl || fallbackSetup);

  const io = new IntersectionObserver(
    (entries) => {
      entries.forEach((entry) => {
        if (entry.isIntersecting) entry.target.classList.add('visible');
      });
    },
    { threshold: 0.12 }
  );
  document.querySelectorAll('.reveal').forEach((el) => io.observe(el));
})();
