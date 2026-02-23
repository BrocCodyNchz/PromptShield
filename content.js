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
      name: CATEGORIES.CREDIT_CARD,
      regex: /\b(?:\d[-\s]*){13,19}\b/g,
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

  /**
   * Scans text for sensitive data. Returns object of category -> count.
   */
  function scanText(text) {
    if (!text || typeof text !== 'string') return {};
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

  async function getStorage() {
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

  async function setSessionCounts(counts) {
    const { sessionCounts } = await getStorage();
    for (const [cat, n] of Object.entries(counts)) {
      sessionCounts[cat] = (sessionCounts[cat] || 0) + n;
    }
    await setStorage({ sessionCounts });
  }

  async function incrementSessionCounts(counts) {
    await setSessionCounts(counts);
    // Notify popup to refresh (it will read on open)
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
      if (el.offsetParent !== null && el.offsetWidth > 0 && el.innerText) {
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

  // Layout constants — avoid magic numbers (Read&Org: named constants over magic numbers)
  const BANNER_BOTTOM_PX = 120;
  const BANNER_Z_INDEX = 2147483647;
  const SEND_BUTTON_ANCESTOR_LIMIT = 8;

  /**
   * Shows the PromptShield warning banner above the chat input.
   * @param {Object} matches - Category -> count
   * @param {Function} onSendAnyway - Called when user chooses Send Anyway
   * @param {Function} onEditFirst - Called when user chooses Edit First
   * @param {Function} onCancel - Called when user chooses Cancel
   */
  function showBanner(matches, onSendAnyway, onEditFirst, onCancel) {
    hideBanner();

    const summary = Object.entries(matches)
      .map(([cat, n]) => `${n} ${cat}`)
      .join(', ');

    bannerEl = document.createElement('div');
    bannerEl.id = 'promptshield-banner';
    bannerEl.innerHTML = `
      <div class="promptshield-banner-inner">
        <div class="promptshield-banner-header">
          <span class="promptshield-banner-title">PromptShield</span>
          <button type="button" class="promptshield-banner-dismiss" aria-label="Dismiss">×</button>
        </div>
        <p class="promptshield-banner-message">
          Sensitive data detected: ${summary}. Please confirm before sending.
        </p>
        <div class="promptshield-banner-actions">
          <button type="button" class="promptshield-btn promptshield-btn-cancel">Cancel</button>
          <button type="button" class="promptshield-btn promptshield-btn-edit">Edit First</button>
          <button type="button" class="promptshield-btn promptshield-btn-send">Send Anyway</button>
        </div>
      </div>
    `;

    // Inject styles (scoped to our banner)
    const style = document.createElement('style');
    style.id = 'promptshield-styles';
    style.textContent = `
      #promptshield-banner {
        position: fixed;
        bottom: ${BANNER_BOTTOM_PX}px;
        left: 50%;
        transform: translateX(-50%);
        z-index: ${BANNER_Z_INDEX};
        font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
        font-size: 14px;
        max-width: 480px;
        width: calc(100% - 24px);
      }
      .promptshield-banner-inner {
        background: #1a1a1a;
        border: 1px solid #333;
        border-radius: 12px;
        padding: 16px;
        box-shadow: 0 8px 32px rgba(0,0,0,0.5);
      }
      .promptshield-banner-header {
        display: flex;
        justify-content: space-between;
        align-items: center;
        margin-bottom: 8px;
      }
      .promptshield-banner-title {
        font-weight: 600;
        color: #00ff7f;
      }
      .promptshield-banner-dismiss {
        background: none;
        border: none;
        color: #888;
        font-size: 20px;
        cursor: pointer;
        padding: 0 4px;
        line-height: 1;
      }
      .promptshield-banner-dismiss:hover { color: #FEFEFE; }
      .promptshield-banner-message {
        color: #d4d4d4;
        margin: 0 0 12px 0;
        line-height: 1.4;
      }
      .promptshield-banner-actions {
        display: flex;
        gap: 8px;
        justify-content: flex-end;
      }
      .promptshield-btn {
        padding: 8px 16px;
        border-radius: 8px;
        font-weight: 500;
        cursor: pointer;
        border: none;
        font-size: 13px;
      }
      .promptshield-btn-cancel {
        background: #333;
        color: #d4d4d4;
      }
      .promptshield-btn-cancel:hover { background: #444; }
      .promptshield-btn-edit {
        background: #333;
        color: #00ff7f;
        border: 1px solid #00ff7f;
      }
      .promptshield-btn-edit:hover { background: rgba(0,255,127,0.1); }
      .promptshield-btn-send {
        background: #00ff7f;
        color: #000;
      }
      .promptshield-btn-send:hover { background: #00cc66; }
      @media (prefers-reduced-motion: reduce) {
        #promptshield-banner * { transition: none !important; }
      }
    `;
    if (!document.getElementById('promptshield-styles')) {
      document.head.appendChild(style);
    }

    document.body.appendChild(bannerEl);

    bannerEl.querySelector('.promptshield-banner-dismiss').addEventListener('click', () => {
      onCancel();
      hideBanner();
    });
    bannerEl.querySelector('.promptshield-btn-cancel').addEventListener('click', () => {
      onCancel();
      hideBanner();
    });
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

  // Capture-phase click listener to intercept before the site handles it
  document.addEventListener(
    'click',
    async (e) => {
      if (allowNextSend) {
        allowNextSend = false;
        return;
      }
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

  // Keyboard submit (Enter / Ctrl+Enter)
  document.addEventListener(
    'keydown',
    async (e) => {
      if (e.key !== 'Enter') return;
      const isSubmit = e.ctrlKey || e.metaKey || !e.shiftKey;
      if (!isSubmit) return;

      const input = findPromptInput();
      if (!input || !input.contains(document.activeElement)) return;

      const text = getInputText(input);
      if (!text.trim()) return;

      const { enabled } = await getStorage();
      if (!enabled) return;

      const matches = scanText(text);
      if (Object.keys(matches).length === 0) return;

      e.preventDefault();
      e.stopPropagation();

      lastInput = input;
      lastSendButton = null; // Keyboard submit — we'll need to simulate click or let the site handle it after

      return new Promise((resolve) => {
        showBanner(
          matches,
          () => {
            incrementSessionCounts(matches);
            // Try to trigger send: dispatch Enter, or find and click send button
            const ev = new KeyboardEvent('keydown', {
              key: 'Enter',
              code: 'Enter',
              keyCode: 13,
              which: 13,
              bubbles: true,
              ctrlKey: e.ctrlKey,
              metaKey: e.metaKey,
            });
            input.dispatchEvent(ev);
            setTimeout(() => {
              const btn = document.querySelector('button[data-testid*="send"], button[aria-label*="Send"]');
              if (btn && getInputText(input).trim()) btn.click();
            }, 50);
            resolve();
          },
          () => {
            input.focus();
            resolve();
          },
          () => resolve()
        );
      });
    },
    true
  );

  // Paste is allowed; we intercept and scan at submit time (click or Enter)
})();
