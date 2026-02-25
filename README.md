# PromptShield

A browser extension that prevents accidental exposure of sensitive data to AI chatbots. All scanning runs locally—no data leaves your browser.

---

## Overview

PromptShield monitors text input on AI chat interfaces (ChatGPT, Claude, Gemini, Copilot) and warns before submission when sensitive patterns are detected. Users can edit first or choose to send anyway.

**Supported browsers:** Chrome, Edge, Firefox, Safari (with additional packaging)

---

## Features

- **Proactive detection** — Scans on paste and as you type, before you press Enter
- **Submit interception** — Blocks send actions when sensitive data is detected
- **Local-only processing** — Zero network requests; all scanning occurs in-browser
- **Session tracking** — View warning counts by category in the extension popup
- **Enable/disable toggle** — Temporarily disable without uninstalling

---

## Sensitive Data Patterns

| Category | Examples |
|----------|----------|
| API keys & tokens | AWS, GitHub, Stripe, OpenAI, Google |
| Private keys | `-----BEGIN ... PRIVATE KEY-----` |
| Passwords | `password=`, `pwd=`, `secret=`, `password` + value |
| Credit cards | Plain, spaced, dashed, Amex 4-6-5 (Luhn-validated) |
| Social Security Numbers | US format (XXX-XX-XXXX) |
| Bulk emails | 3 or more in one paste |
| Internal IPs | 10.x, 192.168.x, 172.16–31.x |
| JWT tokens | `eyJ...` format |
| .env contents | `KEY=value` with sensitive variable names |
| Connection strings | `mongodb://`, `postgres://`, `mysql://`, `redis://` |

---

## Installation

### Chrome / Edge

1. Open `chrome://extensions/` or `edge://extensions/`
2. Enable **Developer mode** (top-right toggle)
3. Click **Load unpacked**
4. Select the PromptShield directory (the folder containing `manifest.json`)

### Firefox

1. Open `about:debugging`
2. Select **This Firefox** → **Load Temporary Add-on**
3. Choose `manifest.json` in the PromptShield folder

   *Temporary add-ons are removed when Firefox closes. For a permanent install, use [web-ext](https://extensionworkshop.com/documentation/develop/web-ext-command-reference/) to sign and package.*

### Safari

Requires conversion via Xcode or the [Safari Web Extension Packager](https://developer.apple.com/documentation/safariservices/safari_web_extensions).

---

## Supported Sites

- chatgpt.com
- claude.ai
- gemini.google.com
- copilot.microsoft.com
- URLs containing `/chat` or `ai` in the path

---

## Project Structure

| Path | Description |
|------|-------------|
| `manifest.json` | Extension manifest (Manifest V3) |
| `content.js` | Content script: scanning, interception, warning banner |
| `popup.html` / `popup.js` / `popup.css` | Extension popup UI |
| `icons/` | `logo.png` (toolbar, popup), `banner_logo.png` (warning banner) |
| `privacy-policy.html` | Privacy policy |

---

## Technical Details

- **Manifest V3** — No remote code; all scripts bundled
- **Vanilla JavaScript** — No frameworks or build step
- **Permissions** — `storage` only (enabled state, session counts)
- **Privacy** — No analytics, no data transmission

---

## License

MIT License. See [LICENSE](LICENSE) for details.
