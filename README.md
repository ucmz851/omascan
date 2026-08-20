# OmaScan (`ucmz851.omascan`)

**OmaScan** is a fast, native URL safety & threat intelligence scanner designed for the Omarchy Quattro desktop environment (`omarchy-shell` / Quickshell).

Powered by **[urlscan.io](https://urlscan.io/)** and **[VirusTotal](https://www.virustotal.com/)**, OmaScan lets you safely inspect suspicious links, phishing websites, and unknown domains directly from your top bar without having to visit them in your browser.

---

## Installation

Install directly with the Omarchy plugin manager:

```bash
omarchy plugin add https://github.com/ucmz851/omascan.git --enable
```

---

## Features

- **Dual-Engine Threat Analysis:**
  - **urlscan.io Sandbox:** Headless browser crawl, live page screenshot preview, server IP, country, ASN, web server technologies, and reputation score.
  - **VirusTotal Multi-Engine AV:** Multi-vendor antivirus detection ratios (Google Safe Browsing, Kaspersky, BitDefender, Cloudflare, etc.).
- **One-Click Clipboard Scan:** Click the paste icon or middle-click the bar icon to instantly paste and analyze any link copied from Discord, Telegram, Slack, or email (`wl-paste`).
- **Safe Sandboxed Screenshots:** View what a website looks like before opening it.
- **Zero-Friction Default Mode:** Works immediately out of the box using public search lookups without requiring API keys.
- **Optional API Key Mode:** Add free VirusTotal and urlscan.io API keys in the **API Keys** tab for real-time live submissions.
- **Scan History:** Keeps track of your last 10 scanned domains for instant review and rescanning.

---

## Bar Controls & Shortcuts

| Action | How to Trigger |
| :--- | :--- |
| **Open / Close Panel** | Left-click the globe/radar icon on your top bar |
| **Instant Clipboard Scan** | Middle-click the bar icon, or click the paste icon inside the panel |
| **Scan URL** | Type/paste URL and press `Enter`, or click the search icon |
| **Switch Tabs** | Click `Scan Results`, `History`, or `API Keys` |
| **Dismiss Panel** | `Escape` |

---

## File Structure

```
omascan/
├── BarWidget.qml       # Bar widget icon, dynamic color tinting, and tooltip
├── Panel.qml           # Anchored flyout panel with search bar, preview, and tabs
├── manifest.json       # Omarchy Quattro plugin manifest (namespaced id: ucmz851.omascan)
├── LICENSE             # MIT License
├── README.md           # Documentation & instructions
└── scripts/
    └── scanner.py      # Python threat intelligence scanner for urlscan.io & VirusTotal
```

---

## License

MIT © [ucmz851](https://github.com/ucmz851)
