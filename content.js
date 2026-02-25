/**
 * PromptShield Content Script
 * Monitors AI chat inputs for sensitive data and shows a warning before submission.
 * All scanning happens locally — zero data leaves the browser.
 */

(function () {
  'use strict';

  // ---------------------------------------------------------------------------
  // CATEGORY CONSTANTS — Used for reporting and display
  // ---------------------------------------------------------------------------
  const CATEGORIES = {
    API_KEY: 'API keys',
    PRIVATE_KEY: 'Private keys',
    PASSWORD: 'Passwords',
    CREDIT_CARD: 'Credit cards',
    SSN: 'Social Security Numbers',
    BULK_EMAIL: 'Bulk email addresses',
    INTERNAL_IP: 'Internal IP addresses',
    JWT: 'JWT tokens',
    ENV_FILE: '.env file contents',
    CONNECTION_STRING: 'Connection strings',
  };

  const BANNER_BOTTOM_PX = 120;
  const BANNER_Z_INDEX = 2147483647;
  const BANNER_WIDTH_OFFSET_PX = 24;
  const SEND_BUTTON_ANCESTOR_LIMIT = 8;
  const SEND_RETRY_DELAY_MS = 50;
  const INPUT_DEBOUNCE_MS = 400;
  const PASTE_SCAN_DELAY_MS = 10;

  // ---------------------------------------------------------------------------
  // SENSITIVE DATA PATTERNS — Regex and validation logic
  // ---------------------------------------------------------------------------

  /**
   * Luhn algorithm for credit card validation.
   * Returns true if the number passes the checksum.
   */
  function luhnCheck(numStr) {
    const digits = numStr.replace(/\D/g, '');
    if (digits.length < 13 || digits.length > 19) return false;
    let sum = 0;
    let isEven = false;
    for (let i = digits.length - 1; i >= 0; i--) {
      let digit = parseInt(digits[i], 10);
      if (isEven) {
        digit *= 2;
        if (digit > 9) digit -= 9;
      }
      sum += digit;
      isEven = !isEven;
    }
    return sum % 10 === 0;
  }

  /**
   * Pattern definitions: { name, regex, validate (optional) }
   * validate receives the match and returns true if it's a real hit
   */
  const PATTERNS = [
    {
      name: CATEGORIES.API_KEY,
      regex: /\b(?:AKIA|ghp_|gho_|ghu_|ghs_|ghr_|sk_live_|sk_test_|pk_live_|pk_test_|sk-[A-Za-z0-9]{20,}|AIza[0-9A-Za-z_-]{35}|openai-[a-zA-Z0-9]{48})\b/g,
    },
    {
      name: CATEGORIES.PRIVATE_KEY,
      regex: /-----BEGIN\s+(?:RSA\s+)?(?:DSA\s+)?(?:EC\s+)?(?:OPENSSH\s+)?(?:PGP\s+)?PRIVATE KEY-----/g,
    },
    {
      name: CATEGORIES.PASSWORD,
      regex: /\b(?:password|pwd|passwd|secret)\s*[:=]\s*["']?[^\s"']{6,}["']?/gi,
    },
    {
      name: CATEGORIES.PASSWORD,
      regex: /\bpassword\s*[:=]?\s*\S{6,}/gi,
    },
    {
      name: CATEGORIES.CREDIT_CARD,
      regex: /\b\d{13,19}\b/g,
      validate: (m) => luhnCheck(m),
    },
    {
      name: CATEGORIES.CREDIT_CARD,
      regex: /\b\d{4}\s\d{4}\s\d{4}\s\d{4}\b/g,
      validate: (m) => luhnCheck(m),
    },
    {
      name: CATEGORIES.CREDIT_CARD,
      regex: /\b\d{4}-\d{4}-\d{4}-\d{4}\b/g,
      validate: (m) => luhnCheck(m),
    },
    {
      name: CATEGORIES.CREDIT_CARD,
      regex: /\b\d{4}[\s-]\d{6}[\s-]\d{5}\b/g,
      validate: (m) => luhnCheck(m),
    },
    {
      name: CATEGORIES.SSN,
      regex: /\b\d{3}[-\s]?\d{2}[-\s]?\d{4}\b/g,
    },
    {
      name: CATEGORIES.BULK_EMAIL,
      regex: /[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}/g,
      validate: (_m, allMatches) => allMatches.length >= 3,
    },
    {
      name: CATEGORIES.INTERNAL_IP,
      regex: /\b(?:10\.\d{1,3}\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3}|172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3})\b/g,
    },
    {
      name: CATEGORIES.JWT,
      regex: /\beyJ[A-Za-z0-9_-]*\.eyJ[A-Za-z0-9_-]*\.[A-Za-z0-9_-]+\b/g,
    },
    {
      name: CATEGORIES.ENV_FILE,
      regex: /^[A-Z_][A-Z0-9_]*\s*=\s*.+$/gm,
      validate: (_m, _all, text) => text.includes('=') && /(?:API_KEY|SECRET|PASSWORD|TOKEN|PRIVATE)/i.test(text),
    },
    {
      name: CATEGORIES.CONNECTION_STRING,
      regex: /\b(?:mongodb|postgres|mysql|redis):\/\/[^\s'"]+/gi,
    },
  ];

  // ---------------------------------------------------------------------------
  // SCAN LOGIC — Runs locally, returns matches by category
  // ---------------------------------------------------------------------------

  const MAX_SCAN_LENGTH = 500000; // Mitigate ReDoS on very large inputs

  /**
   * Scans text for sensitive data. Returns object of category -> count.
   */
  function scanText(text) {
    if (!text || typeof text !== 'string') return {};
    if (text.length > MAX_SCAN_LENGTH) return {};
    const results = {};
    const emailMatches = [];

    for (const pattern of PATTERNS) {
      const regex = new RegExp(pattern.regex.source, pattern.regex.flags);
      let match;
      const seen = new Set();

      while ((match = regex.exec(text)) !== null) {
        let isValid = true;
        if (pattern.validate) {
          if (pattern.name === CATEGORIES.BULK_EMAIL) {
            emailMatches.push(match[0]);
            continue;
          }
          if (pattern.name === CATEGORIES.ENV_FILE) {
            isValid = pattern.validate(match[0], null, text);
          } else {
            isValid = pattern.validate(match[0], null);
          }
        }
        if (isValid && !seen.has(match[0])) {
          seen.add(match[0]);
          results[pattern.name] = (results[pattern.name] || 0) + 1;
        }
      }
    }

    // Bulk email: only flag if 3+ unique emails
    if (emailMatches.length >= 3) {
      const unique = new Set(emailMatches);
      if (unique.size >= 3) {
        results[CATEGORIES.BULK_EMAIL] = unique.size;
      }
    }

    return results;
  }

  // ---------------------------------------------------------------------------
  // STORAGE — Session warning counts and enabled state
  // Cross-browser: Chrome/Edge use chrome.*, Firefox/Safari use browser.*
  // ---------------------------------------------------------------------------

  const storage = (typeof chrome !== 'undefined' && chrome.storage)
    ? chrome.storage
    : (typeof browser !== 'undefined' && browser.storage)
      ? browser.storage
      : null;

  const STORAGE_DEFAULTS = { enabled: true, sessionCounts: {} };

  async function getStorage() {
    if (!storage) return STORAGE_DEFAULTS;
    try {
      const sessionStorage = storage.session || storage.local;
      const [local, session] = await Promise.all([
        Promise.resolve(storage.local.get(['enabled'])).then((r) => r || {}),
        Promise.resolve(sessionStorage.get(['sessionCounts'])).then((r) => r || {}),
      ]);
      return {
        enabled: (local.enabled ?? true) !== false,
        sessionCounts: session.sessionCounts || {},
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

  async function setSessionCounts(counts) {
    const sessionStorage = storage?.session || storage?.local;
    if (!sessionStorage) return;
    try {
      const { sessionCounts } = await getStorage();
      for (const [cat, n] of Object.entries(counts)) {
        sessionCounts[cat] = (sessionCounts[cat] || 0) + n;
      }
      const setResult = sessionStorage.set({ sessionCounts });
      if (setResult && typeof setResult.then === 'function') await setResult;
    } catch (e) {
      const msg = String(e?.message || e || '');
      if (msg.includes('Extension context invalidated') || msg.includes('context invalidated')) return;
      throw e;
    }
  }

  async function incrementSessionCounts(counts) {
    try {
      await setSessionCounts(counts);
    } catch (e) {
      const msg = String(e?.message || e || '');
      if (msg.includes('Extension context invalidated') || msg.includes('context invalidated')) return;
      throw e;
    }
  }

  // ---------------------------------------------------------------------------
  // DOM HELPERS — Find prompt input and send button
  // ---------------------------------------------------------------------------

  /**
   * Finds the main prompt input (textarea or contenteditable).
   */
  function findPromptInput() {
    const textareas = document.querySelectorAll('textarea');
    for (const ta of textareas) {
      if (ta.offsetParent !== null && ta.offsetWidth > 0) {
        return ta;
      }
    }
    const editables = document.querySelectorAll('[contenteditable="true"]');
    for (const el of editables) {
      if (el.offsetParent !== null && el.offsetWidth > 0) {
        return el;
      }
    }
    const roleTextbox = document.querySelectorAll('[role="textbox"]');
    for (const el of roleTextbox) {
      if (el.offsetParent !== null && el.offsetWidth > 0 && (el.isContentEditable || el.getAttribute('contenteditable') === 'true')) {
        return el;
      }
    }
    return null;
  }

  /**
   * Gets text from input (textarea or contenteditable).
   */
  function getInputText(input) {
    if (!input) return '';
    if (input.tagName === 'TEXTAREA') return input.value;
    return input.innerText || input.textContent || '';
  }

  /**
   * Checks if the clicked element (or its ancestors) looks like a send button.
   */
  function isSendButton(el) {
    if (!el) return false;
    let node = el;
    for (let i = 0; i < SEND_BUTTON_ANCESTOR_LIMIT && node; i++) {
      const text = (node.textContent || '').trim().toLowerCase();
      const role = (node.getAttribute?.('role') || '').toLowerCase();
      const ariaLabel = (node.getAttribute?.('aria-label') || '').toLowerCase();
      const dataTestId = (node.getAttribute?.('data-testid') || '').toLowerCase();
      if (
        node.tagName === 'BUTTON' ||
        role === 'button' ||
        /send|submit|post|go/.test(text) ||
        /send|submit/.test(ariaLabel) ||
        /send|submit/.test(dataTestId)
      ) {
        return true;
      }
      node = node.parentElement;
    }
    return false;
  }

  // ---------------------------------------------------------------------------
  // WARNING BANNER — Injected into page DOM
  // ---------------------------------------------------------------------------

  let bannerEl = null;
  let allowNextSend = false; // Bypass interception when user chose "Send Anyway"

  function hideBanner() {
    if (bannerEl) {
      bannerEl.remove();
      bannerEl = null;
    }
  }

  /**
   * Shows the PromptShield warning banner above the chat input.
   * @param {Object} matches - Category -> count
   * @param {Function} onSendAnyway - Called when user chooses Send Anyway
   * @param {Function} onEditFirst - Called when user chooses Edit First
   * @param {Function} onCancel - Called when user chooses Cancel
   */
  function escapeHtml(str) {
    const div = document.createElement('div');
    div.textContent = str;
    return div.innerHTML;
  }

  function getBannerLogoUrl() {
    const runtime = typeof chrome !== 'undefined' && chrome.runtime ? chrome.runtime : (typeof browser !== 'undefined' && browser.runtime ? browser.runtime : null);
    return runtime ? runtime.getURL('icons/banner_logo.png') : null;
  }

  function buildBannerStyles() {
    return `
      #promptshield-banner {
        position: fixed;
        bottom: ${BANNER_BOTTOM_PX}px;
        left: 50%;
        transform: translateX(-50%);
        z-index: ${BANNER_Z_INDEX};
        font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
        font-size: 14px;
        max-width: 480px;
        width: calc(100% - ${BANNER_WIDTH_OFFSET_PX}px);
      }
      .promptshield-banner-inner {
        background: #1a1a1a;
        border: 1px solid #333;
        border-radius: 12px;
        padding: 16px;
        box-shadow: 0 8px 32px rgba(0,0,0,0.5);
      }
      .promptshield-banner-header { margin-bottom: 8px; text-align: center; }
      .promptshield-banner-title-row {
        display: flex; align-items: center; justify-content: center; gap: 12px; width: 100%;
      }
      .promptshield-banner-icon {
        width: 40px; height: 40px; object-fit: contain; flex-shrink: 0;
      }
      span.promptshield-banner-icon { font-size: 40px; line-height: 1; display: inline-block; }
      .promptshield-banner-title {
        font-size: 36px; font-weight: 700; color: #00ff7f;
        text-shadow: 0 0 20px rgba(0, 255, 127, 0.3);
      }
      .promptshield-banner-message {
        color: #d4d4d4; margin: 0 0 12px 0; line-height: 1.4; text-align: center;
      }
      .promptshield-banner-actions {
        display: flex; gap: 8px; justify-content: center;
      }
      .promptshield-btn {
        padding: 8px 16px; border-radius: 8px; font-weight: 500; cursor: pointer; border: none; font-size: 13px;
      }
      .promptshield-btn-edit {
        background: #333; color: #00ff7f; border: 1px solid #00ff7f;
      }
      .promptshield-btn-edit:hover { background: rgba(0,255,127,0.1); }
      .promptshield-btn-send { background: #00ff7f; color: #000; }
      .promptshield-btn-send:hover { background: #00cc66; }
      @media (prefers-reduced-motion: reduce) {
        #promptshield-banner * { transition: none !important; }
      }
    `;
  }

  function showBanner(matches, onSendAnyway, onEditFirst, onCancel) {
    hideBanner();

    const summary = Object.entries(matches)
      .map(([cat, n]) => `${escapeHtml(String(n))} ${escapeHtml(cat)}`)
      .join(', ');

    const bannerLogoUrl = getBannerLogoUrl();
    const iconHtml = bannerLogoUrl
      ? `<img src="${escapeHtml(bannerLogoUrl)}" alt="PromptShield" class="promptshield-banner-icon" width="40" height="40" />`
      : '<span class="promptshield-banner-icon" aria-hidden="true">🛡</span>';

    bannerEl = document.createElement('div');
    bannerEl.id = 'promptshield-banner';
    bannerEl.innerHTML = `
      <div class="promptshield-banner-inner">
        <div class="promptshield-banner-header">
          <div class="promptshield-banner-title-row">
            ${iconHtml}
            <span class="promptshield-banner-title">PromptShield</span>
          </div>
        </div>
        <p class="promptshield-banner-message">
          Sensitive data detected: ${summary}<br>Please confirm before sending.
        </p>
        <div class="promptshield-banner-actions">
          <button type="button" class="promptshield-btn promptshield-btn-edit">Edit First</button>
          <button type="button" class="promptshield-btn promptshield-btn-send">Send Anyway</button>
        </div>
      </div>
    `;

    const style = document.createElement('style');
    style.id = 'promptshield-styles';
    style.textContent = buildBannerStyles();
    if (!document.getElementById('promptshield-styles')) {
      document.head.appendChild(style);
    }

    document.body.appendChild(bannerEl);

    const bannerImg = bannerEl.querySelector('.promptshield-banner-icon[src]');
    if (bannerImg) {
      bannerImg.addEventListener('error', () => {
        const span = document.createElement('span');
        span.className = 'promptshield-banner-icon';
        span.setAttribute('aria-hidden', 'true');
        span.textContent = '🛡';
        bannerImg.replaceWith(span);
      });
    }

    bannerEl.querySelector('.promptshield-btn-edit').addEventListener('click', () => {
      onEditFirst();
      hideBanner();
    });
    bannerEl.querySelector('.promptshield-btn-send').addEventListener('click', () => {
      onSendAnyway();
      hideBanner();
    });
  }

  // ---------------------------------------------------------------------------
  // SUBMIT INTERCEPTION — Capture send actions
  // ---------------------------------------------------------------------------

  let lastSendButton = null;
  let lastInput = null;

  async function handlePotentialSubmit(clickTarget) {
    const { enabled } = await getStorage();
    if (!enabled) return false;

    const input = findPromptInput();
    if (!input) return false;

    const text = getInputText(input);
    const matches = scanText(text);
    if (Object.keys(matches).length === 0) return false;

    // User clicked send and we found sensitive data — intercept
    lastSendButton = clickTarget;
    lastInput = input;

    return new Promise((resolve) => {
      showBanner(
        matches,
        () => {
          incrementSessionCounts(matches);
          allowNextSend = true;
          if (lastSendButton) {
            lastSendButton.click();
          }
          resolve(true);
        },
        () => {
          input.focus();
          resolve(true);
        },
        () => resolve(true)
      );
    });
  }

  // ---------------------------------------------------------------------------
  // PROACTIVE DETECTION — Scan on paste and input, warn before user hits Enter
  // ---------------------------------------------------------------------------

  let inputDebounceTimer = null;

  function attachProactiveListeners(input) {
    if (!input || input.dataset.promptshieldAttached === 'true') return;
    input.dataset.promptshieldAttached = 'true';

    // Paste: scan immediately when user pastes (before they hit Enter)
    input.addEventListener(
      'paste',
      () => {
        getStorage().then(({ enabled }) => {
          if (!enabled) return;
          setTimeout(() => {
            const text = getInputText(input);
            const matches = scanText(text);
            if (Object.keys(matches).length > 0) {
              showBanner(
                matches,
                () => { incrementSessionCounts(matches); allowNextSend = true; hideBanner(); },
                () => { input.focus(); hideBanner(); },
                () => hideBanner()
              );
            }
          }, PASTE_SCAN_DELAY_MS);
        });
      },
      true
    );

    // Input: debounced scan as user types (catches typed secrets)
    input.addEventListener(
      'input',
      () => {
        clearTimeout(inputDebounceTimer);
        inputDebounceTimer = setTimeout(() => {
          getStorage().then(({ enabled }) => {
            if (!enabled) return;
            const text = getInputText(input);
            const matches = scanText(text);
            if (Object.keys(matches).length > 0) {
              showBanner(
                matches,
                () => { incrementSessionCounts(matches); allowNextSend = true; hideBanner(); },
                () => { input.focus(); hideBanner(); },
                () => hideBanner()
              );
            }
          });
        }, INPUT_DEBOUNCE_MS);
      },
      true
    );
  }

  // Watch for prompt inputs appearing (SPA navigation, dynamic forms)
  const observer = new MutationObserver(() => {
    const input = findPromptInput();
    if (input) attachProactiveListeners(input);
  });
  observer.observe(document.body, { childList: true, subtree: true });
  const initialInput = findPromptInput();
  if (initialInput) attachProactiveListeners(initialInput);

  // ---------------------------------------------------------------------------
  // SUBMIT INTERCEPTION — Capture send actions (backup if proactive missed)
  // ---------------------------------------------------------------------------

  // Capture-phase click listener to intercept before the site handles it
  document.addEventListener(
    'click',
    async (e) => {
      if (allowNextSend) {
        allowNextSend = false;
        return;
      }
      // Don't intercept clicks on our own banner buttons
      if (e.target.closest?.('#promptshield-banner')) return;
      if (!isSendButton(e.target)) return;
      const input = findPromptInput();
      if (!input) return;
      const text = getInputText(input);
      if (!text.trim()) return;

      const matches = scanText(text);
      if (Object.keys(matches).length === 0) return;

      const handled = await handlePotentialSubmit(e.target);
      if (handled) {
        e.preventDefault();
        e.stopPropagation();
        e.stopImmediatePropagation();
      }
    },
    true
  );

  // Keyboard submit (Enter / Ctrl+Enter) — prevent default synchronously before any await
  document.addEventListener(
    'keydown',
    (e) => {
      if (e.key !== 'Enter') return;
      const isSubmit = e.ctrlKey || e.metaKey || !e.shiftKey;
      if (!isSubmit) return;

      const input = findPromptInput();
      if (!input || !input.contains(document.activeElement)) return;

      const text = getInputText(input);
      if (!text.trim()) return;

      // Block submit immediately so site doesn't process Enter before we finish
      e.preventDefault();
      e.stopPropagation();

      (async () => {
        const { enabled } = await getStorage();
        if (!enabled) {
          input.dispatchEvent(new KeyboardEvent('keydown', { key: 'Enter', bubbles: true, ctrlKey: e.ctrlKey, metaKey: e.metaKey }));
          return;
        }

        const matches = scanText(text);
        if (Object.keys(matches).length === 0) {
          input.dispatchEvent(new KeyboardEvent('keydown', { key: 'Enter', bubbles: true, ctrlKey: e.ctrlKey, metaKey: e.metaKey }));
          return;
        }

        lastInput = input;
        lastSendButton = null;

        return new Promise((resolve) => {
          showBanner(
            matches,
            () => {
              incrementSessionCounts(matches);
              allowNextSend = true;
              input.dispatchEvent(new KeyboardEvent('keydown', { key: 'Enter', bubbles: true, ctrlKey: e.ctrlKey, metaKey: e.metaKey }));
              setTimeout(() => {
                const btn = document.querySelector('button[data-testid*="send"], button[aria-label*="Send"]');
                if (btn && getInputText(input).trim()) btn.click();
              }, SEND_RETRY_DELAY_MS);
              resolve();
            },
            () => {
              input.focus();
              resolve();
            },
            () => resolve()
          );
        });
      })();
    },
    true
  );

  // Proactive: scan on paste and input (before Enter). Submit interception as backup.
})();
