/* ═══════════════════════════════════════════════════════
   VaultX – Main JavaScript (Bug Fixed)
   ═══════════════════════════════════════════════════════ */

// ── TOAST NOTIFICATIONS ──────────────────────────────────
let toastContainer = null;
function getToastContainer() {
  if (!toastContainer) {
    toastContainer = document.createElement('div');
    toastContainer.className = 'toast-container';
    document.body.appendChild(toastContainer);
  }
  return toastContainer;
}

function showToast(message, type = 'success') {
  const container = getToastContainer();
  const toast = document.createElement('div');
  toast.className = 'toast' + (type === 'error' ? ' error' : '');
  toast.innerHTML = `<span>${type === 'error' ? '✗' : '✓'}</span><span>${message}</span>`;
  container.appendChild(toast);
  setTimeout(() => {
    toast.style.opacity = '0';
    toast.style.transition = 'opacity 0.3s';
    setTimeout(() => toast.remove(), 300);
  }, 3000);
}

// ── DOM READY ─────────────────────────────────────────────
document.addEventListener('DOMContentLoaded', () => {

  // ── SIDEBAR TOGGLE (mobile) ───────────────────────────
  const sidebar = document.getElementById('sidebar');
  const mobileBtn = document.getElementById('mobileMenuBtn');
  if (mobileBtn && sidebar) {
    mobileBtn.addEventListener('click', (e) => {
      e.stopPropagation();
      sidebar.classList.toggle('open');
    });
    document.addEventListener('click', (e) => {
      if (sidebar && !sidebar.contains(e.target) && mobileBtn && !mobileBtn.contains(e.target)) {
        sidebar.classList.remove('open');
      }
    });
  }

  // ── PANIC BUTTON ──────────────────────────────────────
  const panicBtn = document.getElementById('panicBtn');
  const panicModal = document.getElementById('panicModal');
  const confirmPanic = document.getElementById('confirmPanic');

  if (panicBtn && panicModal) {
    panicBtn.addEventListener('click', () => {
      panicModal.style.display = 'flex';
    });
    panicModal.addEventListener('click', (e) => {
      if (e.target === panicModal) panicModal.style.display = 'none';
    });
  }

  if (confirmPanic) {
    confirmPanic.addEventListener('click', async () => {
      try {
        confirmPanic.disabled = true;
        confirmPanic.textContent = 'Activating...';
        const r = await fetch('/panic', { method: 'POST' });
        const d = await r.json();
        if (d.redirect) window.location.href = d.redirect;
        else window.location.href = '/auth/logout';
      } catch (e) {
        window.location.href = '/auth/logout';
      }
    });
  }

  // ── GLOBAL SEARCH ─────────────────────────────────────
  const searchInput = document.getElementById('globalSearch');
  const searchResults = document.getElementById('searchResults');
  let searchTimer = null;

  if (searchInput && searchResults) {
    searchInput.addEventListener('input', () => {
      clearTimeout(searchTimer);
      const q = searchInput.value.trim();
      if (q.length < 2) { searchResults.classList.remove('show'); return; }
      searchTimer = setTimeout(async () => {
        try {
          const r = await fetch(`/api/search?q=${encodeURIComponent(q)}`);
          const d = await r.json();
          if (!d.results || d.results.length === 0) {
            searchResults.classList.remove('show');
            return;
          }
          searchResults.innerHTML = d.results.map(item => `
            <div class="search-result-item" onclick="window.location.href='${item.url}'">
              <span class="search-type">${item.type}</span>
              <span>${item.title}</span>
              <span class="text-muted" style="font-size:11px;margin-left:auto">${item.category}</span>
            </div>`).join('');
          searchResults.classList.add('show');
        } catch (e) { /* silent fail */ }
      }, 350);
    });

    document.addEventListener('click', (e) => {
      if (!searchInput.contains(e.target) && !searchResults.contains(e.target)) {
        searchResults.classList.remove('show');
      }
    });

    searchInput.addEventListener('keydown', (e) => {
      if (e.key === 'Escape') searchResults.classList.remove('show');
    });
  }

  // ── SESSION TIMER ─────────────────────────────────────
  const timerEl = document.getElementById('sessionTimer');
  if (timerEl) {
    let sessionSeconds = 30 * 60; // 30 minutes
    let lastActivity = Date.now();

    const tick = setInterval(() => {
      sessionSeconds--;
      if (sessionSeconds <= 0) {
        clearInterval(tick);
        showToast('Session expired — logging out', 'error');
        setTimeout(() => { window.location.href = '/auth/logout'; }, 2000);
        return;
      }
      const m = Math.floor(sessionSeconds / 60);
      const s = sessionSeconds % 60;
      timerEl.textContent = `${m}:${s.toString().padStart(2, '0')}`;
      if (sessionSeconds === 60) showToast('Session expires in 1 minute!', 'error');
    }, 1000);

    // Reset timer on any user activity
    const resetTimer = async () => {
      if (Date.now() - lastActivity > 30000) { // ping every 30s max
        lastActivity = Date.now();
        try {
          const r = await fetch('/api/ping');
          if (r.ok) sessionSeconds = 30 * 60;
        } catch (e) { /* silent */ }
      }
    };
    ['mousemove', 'keydown', 'click', 'scroll', 'touchstart'].forEach(ev => {
      document.addEventListener(ev, resetTimer, { passive: true });
    });
  }

  // ── VAULT UNLOCK ANIMATION ────────────────────────────
  const overlay = document.getElementById('unlockOverlay');
  if (overlay && !sessionStorage.getItem('vault_unlocked')) {
    sessionStorage.setItem('vault_unlocked', '1');
    overlay.classList.add('show');
    setTimeout(() => {
      overlay.style.opacity = '0';
      overlay.style.transition = 'opacity 0.6s ease';
      setTimeout(() => {
        overlay.style.display = 'none';
        overlay.classList.remove('show');
      }, 600);
    }, 2000);
  }

  // ── AUTO-DISMISS FLASH MESSAGES ───────────────────────
  document.querySelectorAll('.flash').forEach(el => {
    setTimeout(() => {
      el.style.opacity = '0';
      el.style.transition = 'opacity 0.5s';
      setTimeout(() => el.remove(), 500);
    }, 5000);
  });

  // ── SOUND ON BUTTON CLICKS ────────────────────────────
  document.querySelectorAll('.btn-primary').forEach(btn => {
    btn.addEventListener('click', playClick);
  });

});

// ── CLICK SOUND ───────────────────────────────────────────
function playClick() {
  try {
    const ctx = new (window.AudioContext || window.webkitAudioContext)();
    const osc = ctx.createOscillator();
    const gain = ctx.createGain();
    osc.connect(gain);
    gain.connect(ctx.destination);
    osc.frequency.setValueAtTime(900, ctx.currentTime);
    osc.frequency.exponentialRampToValueAtTime(500, ctx.currentTime + 0.05);
    gain.gain.setValueAtTime(0.06, ctx.currentTime);
    gain.gain.exponentialRampToValueAtTime(0.001, ctx.currentTime + 0.1);
    osc.start();
    osc.stop(ctx.currentTime + 0.1);
  } catch (e) { /* audio not supported */ }
}

// ── CLIPBOARD CLEAR ON PAGE HIDE ─────────────────────────
document.addEventListener('visibilitychange', () => {
  if (document.hidden) {
    try { navigator.clipboard.writeText('').catch(() => {}); } catch (e) {}
  }
});
