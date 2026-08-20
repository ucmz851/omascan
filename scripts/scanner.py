#!/usr/bin/env python3
"""
OmaScan Threat Intelligence Scanner
Queries urlscan.io and VirusTotal to evaluate URL/Domain safety, reputation, and metadata.
Outputs structured JSON for the Omarchy Quattro QML UI.
"""

import sys
import os
import re
import json
import time
import socket
import urllib.request
import urllib.parse
import urllib.error
from pathlib import Path

HOME = Path.home()
CONFIG_FILE = HOME / ".config" / "omarchy" / "omascan.json"

def load_config():
    if CONFIG_FILE.exists():
        try:
            return json.loads(CONFIG_FILE.read_text())
        except Exception:
            return {}
    return {}

def save_config(cfg):
    try:
        CONFIG_FILE.parent.mkdir(parents=True, exist_ok=True)
        CONFIG_FILE.write_text(json.dumps(cfg, indent=2))
    except Exception:
        pass

def normalize_url(raw_input):
    raw = raw_input.strip()
    if not raw.startswith("http://") and not raw.startswith("https://"):
        raw = "https://" + raw
    parsed = urllib.parse.urlparse(raw)
    domain = parsed.netloc.split(":")[0].lower()
    return raw, domain

def query_urlscan(domain, url, api_key=None):
    result = {
        "found": False,
        "screenshotUrl": None,
        "title": None,
        "ip": None,
        "country": None,
        "asn": None,
        "server": None,
        "verdict": None,
        "score": 0,
        "resultUrl": f"https://urlscan.io/search/#domain:{domain}"
    }

    try:
        search_url = f"https://urlscan.io/api/v1/search/?q=domain:{domain}&size=1"
        req = urllib.request.Request(search_url, headers={"User-Agent": "OmaScan-Omarchy/1.0"})
        with urllib.request.urlopen(req, timeout=4.0) as resp:
            data = json.loads(resp.read().decode("utf-8"))
            if data.get("results") and len(data["results"]) > 0:
                item = data["results"][0]
                page = item.get("page", {})
                result["found"] = True
                result["screenshotUrl"] = item.get("screenshot")
                result["title"] = page.get("title")
                result["ip"] = page.get("ip")
                result["country"] = page.get("country")
                result["asn"] = page.get("asnname") or page.get("asn")
                result["server"] = page.get("server")
                
                verdicts = item.get("verdicts", {})
                overall = verdicts.get("overall", {})
                result["score"] = overall.get("score", 0)
                result["verdict"] = overall.get("malicious")

                task_id = item.get("_id")
                if task_id:
                    result["resultUrl"] = f"https://urlscan.io/result/{task_id}/"
    except Exception as e:
        pass

    return result

def query_virustotal(domain, api_key=None):
    vt_result = {
        "hasKey": bool(api_key),
        "malicious": 0,
        "suspicious": 0,
        "harmless": 0,
        "undetected": 0,
        "totalEngines": 0,
        "flaggedVendors": [],
        "categories": {},
        "reputation": 0
    }

    if not api_key:
        return vt_result

    try:
        vt_url = f"https://www.virustotal.com/api/v3/domains/{domain}"
        req = urllib.request.Request(vt_url, headers={
            "User-Agent": "OmaScan-Omarchy/1.0",
            "x-apikey": api_key
        })
        with urllib.request.urlopen(req, timeout=4.5) as resp:
            data = json.loads(resp.read().decode("utf-8"))
            attrs = data.get("data", {}).get("attributes", {})
            stats = attrs.get("last_analysis_stats", {})
            
            vt_result["malicious"] = stats.get("malicious", 0)
            vt_result["suspicious"] = stats.get("suspicious", 0)
            vt_result["harmless"] = stats.get("harmless", 0)
            vt_result["undetected"] = stats.get("undetected", 0)
            vt_result["totalEngines"] = sum(stats.values())
            vt_result["reputation"] = attrs.get("reputation", 0)
            vt_result["categories"] = attrs.get("categories", {})

            # Extract specific flagged engines
            analysis_results = attrs.get("last_analysis_results", {})
            for vendor, val in analysis_results.items():
                cat = val.get("category")
                if cat in ["malicious", "suspicious"]:
                    vt_result["flaggedVendors"].append({
                        "engine": vendor,
                        "category": cat,
                        "result": val.get("result") or cat
                    })
    except Exception as e:
        pass

    return vt_result

def resolve_dns_details(domain):
    ip_list = []
    try:
        _, _, ips = socket.gethostbyname_ex(domain)
        ip_list = ips[:4]
    except Exception:
        pass
    return ip_list

def main():
    if len(sys.argv) < 2:
        print(json.dumps({"error": "No URL provided", "verdict": "UNKNOWN"}))
        sys.exit(1)

    # Handle command line or clipboard
    action = sys.argv[1]

    cfg = load_config()

    if action == "--set-keys":
        # Argument format: --set-keys VT_KEY URLSCAN_KEY
        cfg["vt_api_key"] = sys.argv[2] if len(sys.argv) > 2 else ""
        cfg["urlscan_api_key"] = sys.argv[3] if len(sys.argv) > 3 else ""
        save_config(cfg)
        print(json.dumps({"status": "keys_saved"}))
        return

    if action == "--get-config":
        print(json.dumps({
            "hasVtKey": bool(cfg.get("vt_api_key")),
            "hasUrlscanKey": bool(cfg.get("urlscan_api_key")),
            "history": cfg.get("history", [])
        }))
        return

    raw_input = action
    full_url, domain = normalize_url(raw_input)

    vt_key = cfg.get("vt_api_key")
    urlscan_key = cfg.get("urlscan_api_key")

    # Query in sequence / parallel
    urlscan_data = query_urlscan(domain, full_url, urlscan_key)
    vt_data = query_virustotal(domain, vt_key)
    dns_ips = resolve_dns_details(domain)

    # Determine overall verdict
    is_malicious = False
    is_suspicious = False
    verdict_text = "Safe / No Threats Detected"
    verdict_color = "good"
    verdict = "CLEAN"

    if vt_data["malicious"] > 0 or urlscan_data.get("verdict") is True or urlscan_data.get("score", 0) > 60:
        is_malicious = True
        verdict = "MALICIOUS"
        verdict_color = "urgent"
        verdict_text = f"Malicious Site Detected ({vt_data['malicious']} AV Engines Flagged)"
    elif vt_data["suspicious"] > 0 or (urlscan_data.get("score", 0) > 20 and urlscan_data.get("score", 0) <= 60):
        is_suspicious = True
        verdict = "SUSPICIOUS"
        verdict_color = "warning"
        verdict_text = "Suspicious Domain / Caution Advised"

    now_str = time.strftime("%H:%M:%S")

    # Update history in config
    history_entry = {
        "url": full_url,
        "domain": domain,
        "verdict": verdict,
        "verdictColor": verdict_color,
        "time": now_str
    }
    history = [h for h in cfg.get("history", []) if h.get("domain") != domain]
    history.insert(0, history_entry)
    cfg["history"] = history[:10]
    save_config(cfg)

    response = {
        "targetUrl": full_url,
        "domain": domain,
        "verdict": verdict,
        "verdictColor": verdict_color,
        "verdictText": verdict_text,
        "dnsIps": dns_ips,
        "vt": vt_data,
        "urlscan": urlscan_data,
        "timestamp": now_str,
        "history": cfg["history"]
    }

    print(json.dumps(response, indent=2))

if __name__ == "__main__":
    main()
