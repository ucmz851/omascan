# OmaScan (`ucmz851.omascan`)

**OmaScan** is a fast, native threat intelligence scanner designed for the Omarchy Quattro desktop environment (`omarchy-shell` / Quickshell).

Powered by **[VirusTotal](https://www.virustotal.com/)** and **[urlscan.io](https://urlscan.io/)**, OmaScan lets you instantly inspect suspicious URLs, unknown domains, IP addresses, and file hashes directly from your top bar without having to visit dangerous websites or execute unverified files.

---

## Installation

Install directly with the Omarchy plugin manager:

```bash
omarchy plugin add https://github.com/ucmz851/omascan.git --enable
```

---

## Supported Target Types

| Target Type | Example | What OmaScan Analyzes |
| :--- | :--- | :--- |
| **Web URLs** | `https://suspicious-login.com/auth` | Live sandbox crawl, screenshot, 90+ antivirus engines, phishing verdicts |
| **Domains** | `malicious-domain.xyz` | Domain reputation, web server stack, IP address, country, SSL details |
| **IP Addresses** | `185.220.101.5` | Geolocation, ASN / ISP, network owner, abuse detection, open ports |
| **File Hashes (SHA-256)** | `275a021bbfb6489e54d471...` | Malware classification (Trojan, Ransomware), file name, size, vendor detections |
| **File Hashes (MD5 / SHA-1)**| `d41d8cd98f00b204e980...` | Antivirus engine signatures and file reputation |

---

## Features

- **Multi-Engine Antivirus (VirusTotal):** Multi-vendor detection breakdowns across 90+ industry security vendors (Google Safe Browsing, Kaspersky, Microsoft Defender, BitDefender, Sophos, CrowdStrike, Cloudflare).
- **Headless Sandbox Inspection (urlscan.io):** Visual screenshot preview of websites rendered inside a secure sandbox crawler—view pages safely without loading them on your PC.
- **Auto-Detect Target Type:** Automatically determines whether your input is a URL, Domain, IP, MD5, SHA-1, or SHA-256.
- **One-Click Clipboard Scan:** Middle-click the bar icon or click the paste icon to automatically analyze links or hashes from your clipboard (`wl-paste`).
- **Zero-Friction Default Mode:** Works instantly out of the box using public threat intelligence and urlscan.io search without requiring any registration or API keys.
- **Persistent Scan History:** Keeps track of your last 15 scanned targets for quick review and rescanning.

---

## How to Get Free API Keys (Optional)

OmaScan works out of the box with public intelligence lookups. To unlock live on-demand sandbox submissions and full 90+ antivirus engine breakdowns, you can add free personal API keys in the **API Keys** tab:

### 1. Free VirusTotal API Key (30 seconds)
1. Go to **[virustotal.com/gui/join-us](https://www.virustotal.com/gui/join-us)** and create a free account.
2. Click your profile avatar in the top-right corner and choose **API key**.
3. Copy your API key, paste it into OmaScan's **API Keys** tab, and click **Save API Keys**.

### 2. Free urlscan.io API Key (30 seconds)
1. Go to **[urlscan.io/user/signup](https://urlscan.io/user/signup)** and register a free account.
2. Navigate to **Settings** → **API Keys** and generate a new key.
3. Paste it into OmaScan's **API Keys** tab and click **Save API Keys**.

---

## Controls & Shortcuts

| Action | How to Trigger |
| :--- | :--- |
| **Open / Close Panel** | Left-click the globe icon (`󰖟`) on your top bar |
| **Instant Clipboard Scan** | Middle-click the bar icon, or click the paste icon inside the panel |
| **Scan Target** | Type or paste input and press `Enter`, or click the search icon |
| **Switch Tabs** | Click `Scan Results`, `History`, or `API Keys` |
| **Dismiss Panel** | `Escape` |

---

## File Structure

```
omascan/
├── BarWidget.qml       # Bar widget icon, dynamic color tinting, and tooltip
├── Panel.qml           # Anchored flyout panel with multi-target cards and tabs
├── manifest.json       # Omarchy Quattro plugin manifest (namespaced id: ucmz851.omascan)
├── LICENSE             # MIT License
├── README.md           # Documentation, usage guide, and API instructions
└── scripts/
    └── scanner.py      # Multi-target threat engine for VirusTotal & urlscan.io
```

---

## License

MIT © [ucmz851](https://github.com/ucmz851)
