#!/usr/bin/env python3
"""
OmaScan Advanced Threat Intelligence Scanner
Unified multi-target scanner supporting:
- File Hashes (MD5, SHA-1, SHA-256)
- IP Addresses (IPv4, IPv6)
- Domains (FQDN)
- Full URLs

Integrates VirusTotal v3 API and urlscan.io v1 API with zero-friction public fallbacks.
"""

import sys
import os
import re
import json
import time
import socket
import base64
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

def detect_target_type(raw_target):
    t = raw_target.strip()
    # Check Hashes
    if re.match(r'^[a-fA-F0-9]{64}$', t):
        return "hash_sha256", t.lower(), t.lower()
    elif re.match(r'^[a-fA-F0-9]{40}$', t):
        return "hash_sha1", t.lower(), t.lower()
    elif re.match(r'^[a-fA-F0-9]{32}$', t):
        return "hash_md5", t.lower(), t.lower()

    # Check IPv4
    if re.match(r'^(\d{1,3}\.){3}\d{1,3}$', t):
        return "ip", t, t

    # Check IPv6
    if ":" in t and not t.startswith("http") and re.match(r'^[0-9a-fA-F:]+$', t):
        return "ip", t, t

    # Check Full URL
    if t.startswith("http://") or t.startswith("https://") or "/" in t:
        if not t.startswith("http://") and not t.startswith("https://"):
            t = "https://" + t
        parsed = urllib.parse.urlparse(t)
        domain = parsed.netloc.split(":")[0].lower()
        return "url", t, domain

    # Fallback to Domain
    domain = t.split("/")[0].split(":")[0].lower()
    return "domain", domain, domain

def query_urlscan(target_type, target, domain):
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
        "resultUrl": None
    }

    if target_type.startswith("hash"):
        return result

    try:
        if target_type == "ip":
            query_str = f"ip:{target}"
            result["resultUrl"] = f"https://urlscan.io/search/#ip:{target}"
        else:
            query_str = f"domain:{domain}"
            result["resultUrl"] = f"https://urlscan.io/search/#domain:{domain}"

        search_url = f"https://urlscan.io/api/v1/search/?q={urllib.parse.quote(query_str)}&size=1"
        req = urllib.request.Request(search_url, headers={"User-Agent": "OmaScan-Omarchy/2.0"})
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
    except Exception:
        pass

    return result

def query_virustotal(target_type, target, domain, api_key=None):
    vt_result = {
        "hasKey": bool(api_key),
        "malicious": 0,
        "suspicious": 0,
        "harmless": 0,
        "undetected": 0,
        "totalEngines": 0,
        "flaggedVendors": [],
        "threatLabel": None,
        "fileDetails": None,
        "reputation": 0,
        "resultUrl": None
    }

    # Set web link regardless of key
    if target_type.startswith("hash"):
        vt_result["resultUrl"] = f"https://www.virustotal.com/gui/file/{target}"
    elif target_type == "ip":
        vt_result["resultUrl"] = f"https://www.virustotal.com/gui/ip-address/{target}"
    elif target_type == "domain":
        vt_result["resultUrl"] = f"https://www.virustotal.com/gui/domain/{domain}"
    else:
        vt_result["resultUrl"] = f"https://www.virustotal.com/gui/domain/{domain}"

    if not api_key:
        return vt_result

    try:
        if target_type.startswith("hash"):
            endpoint = f"https://www.virustotal.com/api/v3/files/{target}"
        elif target_type == "ip":
            endpoint = f"https://www.virustotal.com/api/v3/ip_addresses/{target}"
        elif target_type == "domain":
            endpoint = f"https://www.virustotal.com/api/v3/domains/{domain}"
        else: # url
            url_id = base64.urlsafe_b64encode(target.encode()).decode().strip("=")
            endpoint = f"https://www.virustotal.com/api/v3/urls/{url_id}"

        req = urllib.request.Request(endpoint, headers={
            "User-Agent": "OmaScan-Omarchy/2.0",
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

            # Threat classification
            threat_class = attrs.get("popular_threat_classification", {})
            if threat_class.get("suggested_threat_label"):
                vt_result["threatLabel"] = threat_class["suggested_threat_label"]

            # File specifics if hash
            if target_type.startswith("hash"):
                vt_result["fileDetails"] = {
                    "name": attrs.get("meaningful_name") or (attrs.get("names", ["Unknown"])[0] if attrs.get("names") else "Unknown"),
                    "size": attrs.get("size", 0),
                    "type": attrs.get("type_description", "Binary / File")
                }

            # Flagged security vendor list
            analysis_results = attrs.get("last_analysis_results", {})
            for vendor, val in sorted(analysis_results.items()):
                cat = val.get("category")
                if cat in ["malicious", "suspicious"]:
                    vt_result["flaggedVendors"].append({
                        "engine": vendor,
                        "category": cat,
                        "result": val.get("result") or cat
                    })
    except Exception:
        pass

    return vt_result

def resolve_dns(domain):
    ips = []
    try:
        _, _, ip_list = socket.gethostbyname_ex(domain)
        ips = ip_list[:4]
    except Exception:
        pass
    return ips

def format_file_size(bytes_num):
    if not bytes_num:
        return "0 B"
    for unit in ['B', 'KB', 'MB', 'GB']:
        if bytes_num < 1024.0:
            return f"{bytes_num:.1f} {unit}"
        bytes_num /= 1024.0
    return f"{bytes_num:.1f} TB"

def main():
    if len(sys.argv) < 2:
        print(json.dumps({"error": "No target provided", "verdict": "UNKNOWN"}))
        sys.exit(1)

    action = sys.argv[1]
    cfg = load_config()

    if action == "--set-keys":
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

    raw_input = action.strip()
    target_type, target, domain = detect_target_type(raw_input)

    vt_key = cfg.get("vt_api_key")
    urlscan_key = cfg.get("urlscan_api_key")

    # Run lookups
    urlscan_data = query_urlscan(target_type, target, domain)
    vt_data = query_virustotal(target_type, target, domain, vt_key)
    dns_ips = resolve_dns(domain) if target_type in ["domain", "url"] else ([target] if target_type == "ip" else [])

    # Compute verdict
    is_malicious = False
    is_suspicious = False
    verdict = "CLEAN"
    verdict_color = "good"
    verdict_text = "Safe / No Known Threats Detected"

    if vt_data["malicious"] > 0 or urlscan_data.get("verdict") is True or urlscan_data.get("score", 0) > 60:
        is_malicious = True
        verdict = "MALICIOUS"
        verdict_color = "urgent"
        label = f" ({vt_data['threatLabel']})" if vt_data.get("threatLabel") else ""
        verdict_text = f"Malicious Threat Detected{label} — {vt_data['malicious']} Antivirus Engines Flagged"
    elif vt_data["suspicious"] > 0 or (urlscan_data.get("score", 0) > 20 and urlscan_data.get("score", 0) <= 60):
        is_suspicious = True
        verdict = "SUSPICIOUS"
        verdict_color = "warning"
        verdict_text = "Suspicious Target / Caution Advised"

    now_str = time.strftime("%H:%M:%S")

    # Friendly type name
    type_labels = {
        "hash_sha256": "File Hash (SHA-256)",
        "hash_sha1": "File Hash (SHA-1)",
        "hash_md5": "File Hash (MD5)",
        "ip": "IP Address",
        "domain": "Domain Name",
        "url": "Web URL"
    }

    # Save to history
    history_entry = {
        "target": target,
        "targetType": type_labels.get(target_type, "Target"),
        "verdict": verdict,
        "verdictColor": verdict_color,
        "time": now_str
    }
    history = [h for h in cfg.get("history", []) if h.get("target") != target]
    history.insert(0, history_entry)
    cfg["history"] = history[:15]
    save_config(cfg)

    response = {
        "rawInput": raw_input,
        "target": target,
        "targetType": target_type,
        "targetTypeLabel": type_labels.get(target_type, "Target"),
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
