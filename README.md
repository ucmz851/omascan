# OmaScan (`ucmz851.omascan`)

**OmaScan** is a lightning-fast, native threat intelligence scanner designed for the Omarchy Quattro desktop environment (`omarchy-shell` / Quickshell).

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

## Free Default Mode vs Enhanced API Key Mode

OmaScan is designed to be **100% useful out of the box with zero setup**, but also provides an optional **Enhanced Mode** if you add free personal API keys:

| Feature | **Default Mode (No Keys Needed)** | **Enhanced Mode (With Free API Keys)** |
| :--- | :--- | :--- |
| **Cost** | 100% Free | 100% Free |
| **Setup Required** | None (Works immediately) | 60 seconds (Paste free key once) |
| **Live Sandboxed Screenshots** | ✅ Yes (from urlscan.io cache/search) | ✅ Yes + on-demand live browser crawls |
| **TLS/SSL Health & Expiration** | ✅ Yes (Live probe with days remaining) | ✅ Yes (Live probe with days remaining) |
| **Server IP & Network ASN** | ✅ Yes (Live DNS & IP resolution) | ✅ Yes (Live DNS & IP resolution) |
| **Antivirus Vendor Breakdown** | Basic public threat reputation | **Full breakdown across 90+ Antivirus Engines** (Google SafeBrowsing, Kaspersky, Microsoft Defender, BitDefender, Sophos, CrowdStrike) |
| **Malware Family Names** | Basic detection | **Exact threat classifications** (e.g. *Trojan.Generic*, *Ransomware.LockBit*) |

---

## How to Get Free API Keys (Optional)

Both VirusTotal and urlscan.io provide **100% free personal API keys**:

### 1. Free VirusTotal API Key (500 free scans/day)
1. Open **[virustotal.com/gui/join-us](https://www.virustotal.com/gui/join-us)** and create a free account (or sign in with Google).
2. Click your profile avatar in the top right corner → click **API key**.
3. Copy your key, open OmaScan's **API Keys** tab, paste it, and click **Save API Keys**.

### 2. Free urlscan.io API Key (5,000 free scans/month)
1. Open **[urlscan.io/user/signup](https://urlscan.io/user/signup)** and register a free account.
2. In the top navigation menu, click **Settings** → **API Keys** → click **Create API Key**.
3. Copy your key, open OmaScan's **API Keys** tab, paste it, and click **Save API Keys**.

---

## Privacy & Security

- **100% Local Storage:** Your API keys and search history are stored exclusively on your local machine at `~/.config/omarchy/omascan.json`.
- **Locked File Permissions (`chmod 600`):** OmaScan strictly restricts configuration file permissions (`-rw-------`) so no other unprivileged process or user on your system can read your keys.
- **No Telemetry:** OmaScan does not track users, log searches externally, or include analytics.

---

## Controls & Shortcuts

| Action | How to Trigger |
| :--- | :--- |
| **Open / Close Panel** | Left-click the globe icon (`󰖟`) on your top bar |
| **Instant Clipboard Scan** | Middle-click the bar icon, or click the paste icon inside the panel |
| **Scan Target** | Type or paste input and press `Enter`, or click the search icon |
| **Clear Results** | Click the `` (Clear) button in the search bar |
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
