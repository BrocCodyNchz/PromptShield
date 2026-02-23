# PromptShield

**PromptShield** is a browser extension that protects users from accidentally pasting sensitive data into AI chatbot interfaces like ChatGPT, Claude, Gemini, and Copilot. It works in **Chrome**, **Edge**, **Firefox**, and **Safari** (with additional packaging).

## How It Works

- **Monitors** text being pasted or typed into the main prompt input fields on AI chat websites
- **Scans** content for sensitive data patterns before submission
- **Displays** a non-blocking warning banner when matches are found
- **User choices**: "Send Anyway", "Edit First", or "Cancel"

All scanning happens **locally** in the content script — zero data leaves your browser.

## Sensitive Data Patterns Detected

| Category | Examples |
|----------|----------|
| API keys & tokens | AWS, GitHub, Stripe, OpenAI, Google |
| Private keys | `-----BEGIN ... PRIVATE KEY-----` |
| Passwords | `password=`, `pwd=`, `secret=` |
| Credit cards | Validated with Luhn algorithm |
| Social Security Numbers | US format (XXX-XX-XXXX) |
| Bulk emails | 3 or more in one paste |
| Internal IPs | 10.x, 192.168.x, 172.16–31.x |
| JWT tokens | `eyJ...` format |
| .env file contents | `KEY=value` patterns |
| Connection strings | `mongodb://`, `postgres://`, `mysql://` |

## Target Websites

- chatgpt.com
- claude.ai
- gemini.google.com
- copilot.microsoft.com
- Any URL containing `/chat` or `ai` in the path

## Browser Support

| Browser | Support | How to Install |
|---------|---------|----------------|
| **Chrome** | ✅ Full | Load unpacked (see below) |
| **Edge** | ✅ Full | Load unpacked from `edge://extensions/` |
| **Firefox** | ✅ Full | Load from `about:debugging` → "This Firefox" → "Load Temporary Add-on" |
| **Safari** | ✅ With packaging | Requires Safari Web Extension conversion (Xcode or [Safari Web Extension Packager](https://developer.apple.com/documentation/safariservices/safari_web_extensions)) |

## How to Load as an Unpacked Extension

### Chrome / Edge
1. Open `chrome://extensions/` (Chrome) or `edge://extensions/` (Edge)
2. Enable **Developer mode** (toggle in the top-right)
3. Click **Load unpacked**
4. Select the PromptShield folder (containing `manifest.json`)

### Firefox
1. Open `about:debugging` in Firefox
2. Click **This Firefox** → **Load Temporary Add-on**
3. Select the `manifest.json` file inside the PromptShield folder  
   *(Note: Temporary add-ons are removed when Firefox closes. For a permanent install, use [web-ext](https://extensionworkshop.com/documentation/develop/web-ext-command-reference/) to sign and package.)*

The extension icon will appear in the toolbar. Click it to view the popup with session warning counts and the enable/disable toggle.

## Files

| File | Purpose |
|------|---------|
| `manifest.json` | Chrome extension manifest (Manifest V3) |
| `content.js` | Content script: scanning, interception, warning banner |
| `popup.html` | Popup UI structure |
| `popup.js` | Popup logic: counts, toggle |
| `popup.css` | Popup styles (dark-mode) |
| `README.md` | This file |

## Technical Requirements

- **Manifest V3** Chrome extension
- **Vanilla JS, HTML, CSS** — no frameworks or external dependencies
- **Local scanning only** — no network requests from the content script

## Popup Features

- **Session warning count** — Running count of warnings triggered this session, broken down by category
- **Enable/disable toggle** — Temporarily disable the extension without uninstalling

## Warning Banner

- Injected into the page DOM above the chat input
- Dismissible (× button)
- Clean modern dark-mode aesthetic
- Actions: **Cancel**, **Edit First**, **Send Anyway**
