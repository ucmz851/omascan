#!/usr/bin/env python3
"""
OmaScan Threat Intelligence Engine
Provides safe, cloud-sandboxed threat intelligence for:
- File Hashes (MD5, SHA-1, SHA-256)
- Public IP Addresses (IPv4, IPv6)
- Domain Names & FQDNs
- Web URLs

Integrates:
1. VirusTotal v3 API (90+ security engines)
2. urlscan.io v1 API (cloud browser sandbox & visual previews)
3. Strict public destination validation (disallows private/local network scanning)
4. Accurate verdict reporting (marks unavailable/unverified targets as UNVERIFIED instead of CLEAN)
"""

import sys
import os
import re
import json
import time
import socket
import ssl
import base64
import ipaddress
import urllib.request
import urllib.parse
import urllib.error
from datetime import datetime, timezone
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
        try:
            CONFIG_FILE.chmod(0o600)
        except Exception:
            pass
    except Exception:
        pass

def is_private_or_local(host_or_ip):
    # Check if raw string is an IP address
    try:
        ip = ipaddress.ip_address(host_or_ip)
        return ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_multicast or ip.is_reserved or ip.is_unspecified
    except ValueError:
        pass

    if host_or_ip.lower() in ["localhost", "broadcasthost", "local", "ip6-localhost", "ip6-loopback"]:
        return True

    # Check DNS resolution
    try:
        addr = socket.gethostbyname(host_or_ip)
        ip = ipaddress.ip_address(addr)
        return ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_multicast or ip.is_reserved or ip.is_unspecified
    except Exception:
        return False

def detect_target_type(raw_target):
    t = raw_target.strip()
    if re.match(r'^[a-fA-F0-9]{64}$', t):
        return "hash_sha256", t.lower(), t.lower()
    elif re.match(r'^[a-fA-F0-9]{40}$', t):
        return "hash_sha1", t.lower(), t.lower()
    elif re.match(r'^[a-fA-F0-9]{32}$', t):
        return "hash_md5", t.lower(), t.lower()
    elif re.match(r'^(\d{1,3}\.){3}\d{1,3}$', t):
        return "ip", t, t
    elif ":" in t and not t.startswith("http") and re.match(r'^[0-9a-fA-F:]+$', t):
        return "ip", t, t
    elif t.startswith("http://") or t.startswith("https://") or "/" in t:
        if not t.startswith("http://") and not t.startswith("https://"):
            t = "https://" + t
        parsed = urllib.parse.urlparse(t)
        domain = parsed.netloc.split(":")[0].lower()
        return "url", t, domain
    else:
        domain = t.split("/")[0].split(":")[0].lower()
        return "domain", domain, domain

def probe_ssl(domain):
    ssl_info = {
        "hasSsl": False,
        "issuer": None,
        "expires": None,
        "daysRemaining": None
    }
    if is_private_or_local(domain):
        return ssl_info

    try:
        # Strict default TLS verification using system trust store
        ctx = ssl.create_default_context()
        with ctx.wrap_socket(socket.socket(), server_hostname=domain) as s:
            s.settimeout(3.0)
            s.connect((domain, 443))
            cert = s.getpeercert()
            if cert:
                ssl_info["hasSsl"] = True
                issuer_dict = dict(x[0] for x in cert.get('issuer', []))
                ssl_info["issuer"] = issuer_dict.get('organizationName') or issuer_dict.get('commonName') or "Valid TLS Certificate"
                not_after = cert.get('notAfter')
                if not_after:
                    ssl_info["expires"] = not_after
                    try:
                        clean_str = re.sub(r'\s+', ' ', not_after.strip())
                        expire_dt = datetime.strptime(clean_str, "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
                        days_left = (expire_dt - datetime.now(timezone.utc)).days
                        ssl_info["daysRemaining"] = days_left
                    except Exception:
                        pass
    except Exception:
        pass
    return ssl_info

def query_urlscan(target_type, target, domain):
    result = {
        "found": False,
        "screenshotUrl": None,
        "title": None,
        "ip": None,
        "country": None,
        "asn": None,
        "server": None,
        "status": None,
        "verdict": None,
        "score": 0,
        "resultUrl": None
    }

    if target_type.startswith("hash") or is_private_or_local(domain):
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
                result["status"] = page.get("status")
                
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

    if target_type.startswith("hash"):
        vt_result["resultUrl"] = f"https://www.virustotal.com/gui/file/{target}"
    elif target_type == "ip":
        vt_result["resultUrl"] = f"https://www.virustotal.com/gui/ip-address/{target}"
    elif target_type == "domain":
        vt_result["resultUrl"] = f"https://www.virustotal.com/gui/domain/{domain}"
    else:
        vt_result["resultUrl"] = f"https://www.virustotal.com/gui/domain/{domain}"

    if not api_key or is_private_or_local(domain if not target_type.startswith("hash") else "8.8.8.8"):
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

            threat_class = attrs.get("popular_threat_classification", {})
            if threat_class.get("suggested_threat_label"):
                vt_result["threatLabel"] = threat_class["suggested_threat_label"]

            if target_type.startswith("hash"):
                vt_result["fileDetails"] = {
                    "name": attrs.get("meaningful_name") or (attrs.get("names", ["Unknown"])[0] if attrs.get("names") else "Unknown"),
                    "size": attrs.get("size", 0),
                    "type": attrs.get("type_description", "Binary / File")
                }

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

def resolve_dns_ips(domain):
    if is_private_or_local(domain):
        return []
    ips = []
    try:
        _, _, ip_list = socket.gethostbyname_ex(domain)
        ips = ip_list[:4]
    except Exception:
        pass
    return ips

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

    type_labels = {
        "hash_sha256": "File Hash (SHA-256)",
        "hash_sha1": "File Hash (SHA-1)",
        "hash_md5": "File Hash (MD5)",
        "ip": "IP Address",
        "domain": "Domain Name",
        "url": "Web URL"
    }

    # Check for private / local destinations
    if target_type not in ["hash_sha256", "hash_sha1", "hash_md5"] and is_private_or_local(domain):
        now_str = time.strftime("%H:%M:%S")
        response = {
            "rawInput": raw_input,
            "target": target,
            "targetType": target_type,
            "targetTypeLabel": type_labels.get(target_type, "Target"),
            "domain": domain,
            "verdict": "LOCAL",
            "verdictColor": "normal",
            "verdictText": "Private / Local Destination — Cloud reputation lookup skipped for safety.",
            "dnsIps": ["127.0.0.1" if domain == "localhost" else target],
            "ssl": {"hasSsl": False, "issuer": None, "expires": None, "daysRemaining": None},
            "http": {"status": "Local Network", "server": "Localhost", "hsts": False, "redirectTarget": None},
            "vt": {"hasKey": bool(vt_key), "malicious": 0, "suspicious": 0, "harmless": 0, "undetected": 0, "totalEngines": 0, "flaggedVendors": [], "threatLabel": None, "fileDetails": None, "reputation": 0, "resultUrl": None},
            "urlscan": {"found": False, "screenshotUrl": None, "title": "Private Network Destination", "ip": target, "country": "Local", "asn": "Local Area Network", "server": "Local", "status": None, "verdict": None, "score": 0, "resultUrl": None},
            "timestamp": now_str,
            "history": cfg.get("history", [])
        }
        print(json.dumps(response, indent=2))
        return

    # Multi-engine lookups
    urlscan_data = query_urlscan(target_type, target, domain)
    vt_data = query_virustotal(target_type, target, domain, vt_key)
    dns_ips = resolve_dns_ips(domain) if target_type in ["domain", "url"] else ([target] if target_type == "ip" else [])
    ssl_data = probe_ssl(domain) if target_type in ["domain", "url"] else None
    http_data = {
        "status": f"{urlscan_data['status']} (via urlscan.io sandbox)" if urlscan_data.get("status") else None,
        "server": urlscan_data.get("server"),
        "hsts": ssl_data.get("hasSsl") if ssl_data else False,
        "redirectTarget": None
    } if target_type in ["domain", "url"] else None

    # Compute verdict with strict accuracy
    is_malicious = False
    is_suspicious = False
    verdict = "UNVERIFIED"
    verdict_color = "normal"
    verdict_text = "No Threat Intelligence Found (Inconclusive)"

    if vt_data["malicious"] > 0 or urlscan_data.get("verdict") is True or urlscan_data.get("score", 0) > 60:
        is_malicious = True
        verdict = "MALICIOUS"
        verdict_color = "urgent"
        label = f" ({vt_data['threatLabel']})" if vt_data.get("threatLabel") else ""
        count = vt_data['malicious'] if vt_data['malicious'] > 0 else "urlscan.io sandbox"
        verdict_text = f"Malicious Threat Detected{label} — {count} Flags"
    elif vt_data["suspicious"] > 0 or (urlscan_data.get("score", 0) > 20 and urlscan_data.get("score", 0) <= 60):
        is_suspicious = True
        verdict = "SUSPICIOUS"
        verdict_color = "warning"
        verdict_text = "Suspicious Target / Caution Advised"
    elif vt_data["totalEngines"] > 0:
        verdict = "CLEAN"
        verdict_color = "good"
        verdict_text = f"Safe / Clean ({vt_data['harmless'] + vt_data['undetected']} Security Engines Verified)"
    elif urlscan_data["found"] is True:
        verdict = "CLEAN"
        verdict_color = "good"
        verdict_text = "Safe / Clean (Verified by urlscan.io sandbox crawl)"
    else:
        # When no threat lookup succeeded or no scan record exists
        verdict = "UNVERIFIED"
        verdict_color = "normal"
        verdict_text = "No Public Intelligence Found (Inconclusive — Add free VirusTotal key for on-demand 90+ engine analysis)"

    now_str = time.strftime("%H:%M:%S")

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
        "ssl": ssl_data,
        "http": http_data,
        "vt": vt_data,
        "urlscan": urlscan_data,
        "timestamp": now_str,
        "history": cfg["history"]
    }

    print(json.dumps(response, indent=2))

if __name__ == "__main__":
    main()
