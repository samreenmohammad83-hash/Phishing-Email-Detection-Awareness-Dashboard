import ipaddress
import re
from urllib.parse import urlparse
from typing import Dict, List

SHORTENERS = {"bit.ly", "tinyurl.com", "t.co", "is.gd", "ow.ly", "buff.ly"}
SUSPICIOUS_WORDS = {"verify", "login", "signin", "password", "credential", "secure", "account", "payment", "invoice", "update", "confirm"}
URL_RE = re.compile(r"https?://[^\s<>\"]+", re.I)

def extract_urls(text: str) -> List[str]:
    return [u.rstrip(".,);]") for u in URL_RE.findall(text or "")]

def _is_ip(host: str) -> bool:
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        return False

def analyze_url(url: str) -> Dict:
    raw = url.strip()
    findings = []
    score = 0
    try:
        parsed = urlparse(raw)
        host = parsed.hostname or ""
        scheme = (parsed.scheme or "").lower()
        path_query = f"{parsed.path}?{parsed.query}".lower() if parsed.query else parsed.path.lower()
        labels = [x for x in host.split(".") if x]

        if scheme != "https":
            score += 15
            findings.append("Non-HTTPS URL.")
        if _is_ip(host):
            score += 25
            findings.append("Hostname is a raw IP address.")
        if host.lower() in SHORTENERS:
            score += 15
            findings.append("Known URL-shortener pattern detected.")
        if len(raw) > 120:
            score += 5
            findings.append("Unusually long URL.")
        if len(host) > 50:
            score += 5
            findings.append("Unusually long hostname.")
        if len(labels) >= 4:
            score += 10
            findings.append("Excessive subdomain depth.")
        if any(word in path_query for word in SUSPICIOUS_WORDS):
            score += 10
            findings.append("Security-sensitive keyword appears in URL.")
        if re.search(r"[@%]", raw):
            score += 5
            findings.append("Unusual URL character detected.")

        score = min(score, 100)
        return {
            "url": raw,
            "scheme": scheme,
            "hostname": host,
            "path": parsed.path,
            "query": parsed.query,
            "url_length": len(raw),
            "hostname_length": len(host),
            "subdomain_count": max(0, len(labels) - 2),
            "has_ip": _is_ip(host),
            "has_shortener": host.lower() in SHORTENERS,
            "https": scheme == "https",
            "risk_score": score,
            "findings": findings,
        }
    except Exception as exc:
        return {"url": raw, "risk_score": 30, "findings": [f"URL could not be parsed safely: {type(exc).__name__}"]}

def analyze_urls(urls: List[str]) -> List[Dict]:
    return [analyze_url(u) for u in urls]
