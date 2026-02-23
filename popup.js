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

  async function loadState() {
    if (!storage) return { enabled: true, sessionCounts: {} };
    const keys = ['enabled', 'sessionCounts'];
    const getResult = storage.local.get(keys);
    const data = await (getResult && typeof getResult.then === 'function'
      ? getResult
      : new Promise((resolve) => storage.local.get(keys, resolve)));
    return {
      enabled: data.enabled !== false,
      sessionCounts: data.sessionCounts || {},
    };
  }

  async function setStorage(items) {
    if (!storage) return;
    const result = storage.local.set(items);
    if (result && typeof result.then === 'function') await result;
  }

  // ---------------------------------------------------------------------------
  // Load saved state and render
  // ---------------------------------------------------------------------------

  function renderCounts(sessionCounts) {
    const entries = Object.entries(sessionCounts).filter(([, n]) => n > 0);
    if (entries.length === 0) {
      countsEl.innerHTML = '<p class="empty-state">No warnings yet</p>';
      return;
    }
    countsEl.innerHTML = entries
      .sort((a, b) => b[1] - a[1])
      .map(
        ([cat, n]) =>
          `<div class="warning-item"><span class="category">${escapeHtml(cat)}</span><span class="count">${n}</span></div>`
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
    if (area === 'local' && changes.sessionCounts) {
      renderCounts(changes.sessionCounts.newValue || {});
    }
    if (area === 'local' && changes.enabled) {
      toggleEl.checked = changes.enabled.newValue !== false;
    }
  });

  init();
})();
