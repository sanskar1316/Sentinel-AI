"""Threat-intelligence helpers for Sentinel AI (AbuseIPDB + VirusTotal).

API keys are NEVER hardcoded. They are read from Streamlit Secrets
(.streamlit/secrets.toml locally, or the app's Secrets box on Streamlit
Community Cloud) with an environment-variable fallback.
Every lookup returns a dict: {"ok": bool, "error": str|None, ...data}
and never raises, so the dashboard keeps working if an API fails.
"""
import base64
import ipaddress
import os
import re

import requests

TIMEOUT = 10
ABUSEIPDB_URL = "https://api.abuseipdb.com/api/v2/check"
VT_BASE = "https://www.virustotal.com/api/v3"


def get_secret(name):
    """Return a secret from st.secrets or env vars, or '' if missing."""
    try:
        import streamlit as st
        val = st.secrets.get(name, "")
        if val:
            return str(val).strip()
    except Exception:  # no secrets file / not running in Streamlit
        pass
    return os.environ.get(name, "").strip()


def key_status():
    return {
        "AbuseIPDB": bool(get_secret("ABUSEIPDB_API_KEY")),
        "VirusTotal": bool(get_secret("VIRUSTOTAL_API_KEY")),
    }


def is_valid_ip(value):
    try:
        ipaddress.ip_address(value.strip())
        return True
    except ValueError:
        return False


def _fail(msg):
    return {"ok": False, "error": msg}


def _http_error(service, status):
    msgs = {
        401: f"{service}: API key was rejected (401). Check the key in Secrets.",
        403: f"{service}: access denied (403). The key may be invalid or lack permission.",
        404: f"{service}: no record found for this item (404).",
        422: f"{service}: the request was not valid (422). Check the input.",
        429: f"{service}: rate limit or daily quota reached (429). Try again later.",
    }
    return msgs.get(status, f"{service}: unexpected response (HTTP {status}).")


def _get(service, url, headers, params=None):
    try:
        r = requests.get(url, headers=headers, params=params, timeout=TIMEOUT)
    except requests.exceptions.Timeout:
        return None, _fail(f"{service}: request timed out. Try again.")
    except requests.exceptions.ConnectionError:
        return None, _fail(f"{service}: network connection failed.")
    except requests.exceptions.RequestException as e:
        return None, _fail(f"{service}: request failed ({type(e).__name__}).")
    if r.status_code != 200:
        return None, _fail(_http_error(service, r.status_code))
    try:
        return r.json(), None
    except ValueError:
        return None, _fail(f"{service}: returned an unreadable response.")


def check_abuseipdb(ip, max_age_days=90):
    key = get_secret("ABUSEIPDB_API_KEY")
    if not key:
        return _fail("AbuseIPDB API key not configured (add ABUSEIPDB_API_KEY to Secrets).")
    ip = (ip or "").strip()
    if not is_valid_ip(ip):
        return _fail("Please enter a valid IPv4 or IPv6 address.")
    payload, err = _get("AbuseIPDB", ABUSEIPDB_URL,
                        {"Key": key, "Accept": "application/json"},
                        {"ipAddress": ip, "maxAgeInDays": max_age_days})
    if err:
        return err
    d = (payload or {}).get("data")
    if not isinstance(d, dict):
        return _fail("AbuseIPDB: response had no data.")
    return {
        "ok": True, "error": None, "ip": ip,
        "score": int(d.get("abuseConfidenceScore") or 0),
        "reports": int(d.get("totalReports") or 0),
        "country": d.get("countryCode") or "—",
        "isp": d.get("isp") or "—",
        "domain": d.get("domain") or "—",
        "usage": d.get("usageType") or "—",
        "last_reported": d.get("lastReportedAt") or "Never",
        "whitelisted": bool(d.get("isWhitelisted")),
    }


def classify_indicator(value):
    """Return (kind, vt_path_id) for an IP, URL, file hash or domain."""
    v = (value or "").strip()
    if not v:
        return None, None
    if is_valid_ip(v):
        return "IP address", f"ip_addresses/{v}"
    if re.fullmatch(r"[A-Fa-f0-9]{32}|[A-Fa-f0-9]{40}|[A-Fa-f0-9]{64}", v):
        return "File hash", f"files/{v.lower()}"
    if re.match(r"^https?://", v, re.I):
        uid = base64.urlsafe_b64encode(v.encode()).decode().rstrip("=")
        return "URL", f"urls/{uid}"
    if re.fullmatch(r"(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+[A-Za-z]{2,63}", v):
        return "Domain", f"domains/{v.lower()}"
    return None, None


def check_virustotal(indicator):
    key = get_secret("VIRUSTOTAL_API_KEY")
    if not key:
        return _fail("VirusTotal API key not configured (add VIRUSTOTAL_API_KEY to Secrets).")
    kind, path = classify_indicator(indicator)
    if not kind:
        return _fail("Enter an IP address, domain, full URL (http/https) or file hash (MD5/SHA-1/SHA-256).")
    payload, err = _get("VirusTotal", f"{VT_BASE}/{path}", {"x-apikey": key})
    if err:
        return err
    attrs = ((payload or {}).get("data") or {}).get("attributes")
    if not isinstance(attrs, dict):
        return _fail("VirusTotal: response had no data.")
    s = attrs.get("last_analysis_stats") or {}
    return {
        "ok": True, "error": None, "indicator": indicator.strip(), "kind": kind,
        "malicious": int(s.get("malicious", 0)),
        "suspicious": int(s.get("suspicious", 0)),
        "harmless": int(s.get("harmless", 0)),
        "undetected": int(s.get("undetected", 0)),
        "reputation": attrs.get("reputation", "—"),
        "owner": attrs.get("as_owner") or attrs.get("registrar") or attrs.get("meaningful_name") or "—",
        "country": attrs.get("country") or "—",
    }


def intel_floor(abuse=None, vt=None):
    """Minimum risk level implied by threat intel: 'HIGH', 'MEDIUM' or None."""
    score = abuse["score"] if abuse and abuse.get("ok") else 0
    mal = vt["malicious"] if vt and vt.get("ok") else 0
    sus = vt["suspicious"] if vt and vt.get("ok") else 0
    if score >= 75 or mal >= 5:
        return "HIGH"
    if score >= 25 or mal >= 1 or sus >= 3:
        return "MEDIUM"
    return None
