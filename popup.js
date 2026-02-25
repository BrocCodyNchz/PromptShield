/**
 * PromptShield Popup Script
 * Displays session warning counts by category and provides enable/disable toggle.
 * Cross-browser: Chrome/Edge use chrome.*, Firefox/Safari use browser.*
 */

(function () {
  'use strict';

  const toggleEl = document.getElementById('toggle-enabled');
  const countsEl = document.getElementById('warning-counts');

  // Cross-browser storage API
  const storage = (typeof chrome !== 'undefined' && chrome.storage)
    ? chrome.storage
    : (typeof browser !== 'undefined' && browser.storage)
      ? browser.storage
      : null;

  const STORAGE_DEFAULTS = { enabled: true, sessionCounts: {} };

  async function loadState() {
    if (!storage) return STORAGE_DEFAULTS;
    try {
      const sessionStorage = storage.session || storage.local;
      const [localData, sessionData] = await Promise.all([
        Promise.resolve(storage.local.get(['enabled'])).then((r) => r || {}),
        Promise.resolve(sessionStorage.get(['sessionCounts'])).then((r) => r || {}),
      ]);
      return {
        enabled: (localData.enabled ?? true) !== false,
        sessionCounts: sessionData.sessionCounts || {},
      };
    } catch (e) {
      const msg = String(e?.message || e || '');
      if (msg.includes('Extension context invalidated') || msg.includes('context invalidated')) return STORAGE_DEFAULTS;
      throw e;
    }
  }

  async function setStorage(items) {
    if (!storage) return;
    try {
      const result = storage.local.set(items);
      if (result && typeof result.then === 'function') await result;
    } catch (e) {
      const msg = String(e?.message || e || '');
      if (msg.includes('Extension context invalidated') || msg.includes('context invalidated')) return;
      throw e;
    }
  }

  // ---------------------------------------------------------------------------
  // Load saved state and render
  // ---------------------------------------------------------------------------

  const VALID_CATEGORIES = new Set([
    'API keys', 'Private keys', 'Passwords', 'Credit cards', 'Social Security Numbers',
    'Bulk email addresses', 'Internal IP addresses', 'JWT tokens', '.env file contents',
    'Connection strings',
  ]);

  function renderCounts(sessionCounts) {
    if (!sessionCounts || typeof sessionCounts !== 'object') {
      countsEl.innerHTML = '<p class="empty-state">No warnings yet</p>';
      return;
    }
    const entries = Object.entries(sessionCounts)
      .filter(([cat, n]) => VALID_CATEGORIES.has(cat) && typeof n === 'number' && n > 0);
    if (entries.length === 0) {
      countsEl.innerHTML = '<p class="empty-state">No warnings yet</p>';
      return;
    }
    countsEl.innerHTML = entries
      .sort((a, b) => b[1] - a[1])
      .map(
        ([cat, n]) =>
          `<div class="warning-item"><span class="category">${escapeHtml(cat)}</span><span class="count">${escapeHtml(String(Math.floor(n)))}</span></div>`
      )
      .join('');
  }

  function escapeHtml(str) {
    const div = document.createElement('div');
    div.textContent = str;
    return div.innerHTML;
  }

  async function init() {
    const { enabled, sessionCounts } = await loadState();
    toggleEl.checked = enabled;
    renderCounts(sessionCounts);
  }

  // ---------------------------------------------------------------------------
  // Toggle handler — persist enabled state
  // ---------------------------------------------------------------------------

  toggleEl.addEventListener('change', () => {
    setStorage({ enabled: toggleEl.checked });
  });

  // ---------------------------------------------------------------------------
  // Listen for storage changes (e.g. from content script) to refresh counts
  // ---------------------------------------------------------------------------

  if (!storage) {
    init();
    return;
  }

  storage.onChanged.addListener((changes, area) => {
    try {
      const sessionArea = storage.session ? 'session' : 'local';
      if (area === sessionArea && changes.sessionCounts) {
        renderCounts(changes.sessionCounts.newValue || {});
      }
      if (area === 'local' && changes.enabled) {
        toggleEl.checked = changes.enabled.newValue !== false;
      }
    } catch (e) {
      const msg = String(e?.message || e || '');
      if (!msg.includes('Extension context invalidated') && !msg.includes('context invalidated')) throw e;
    }
  });

  init();
})();
