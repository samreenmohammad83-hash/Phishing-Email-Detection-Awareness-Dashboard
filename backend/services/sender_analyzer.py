import re
from typing import Dict

EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")
SYNTHETIC_SUSPICIOUS_TERMS = {"verify", "secure", "account", "support", "alert", "billing", "login"}

def analyze_sender(sender: str, display_name: str = "") -> Dict:
    sender = (sender or "").strip()
    score = 0
    findings = []
    if not EMAIL_RE.match(sender):
        return {"sender_risk_score": 35, "sender_findings": ["Sender email format is invalid or incomplete."], "domain": ""}

    local, domain = sender.rsplit("@", 1)
    domain_lower = domain.lower()
    if len(domain) > 40:
        score += 8
        findings.append("Sender domain is unusually long.")
    if domain.count(".") >= 4:
        score += 8
        findings.append("Sender domain contains many subdomains.")
    if re.search(r"[^a-zA-Z0-9.\-]", domain):
        score += 8
        findings.append("Sender domain contains unusual characters.")
    if "--" in domain or ".." in domain:
        score += 5
        findings.append("Sender domain contains an unusual punctuation pattern.")
    if any(term in local.lower() for term in SYNTHETIC_SUSPICIOUS_TERMS):
        score += 5
        findings.append("Sender local-part uses a security-themed keyword.")
    if display_name and domain.split(".")[0].lower() not in display_name.lower() and display_name.lower() not in {"training", "university", "hr"}:
        score += 5
        findings.append("Display name may not match the sender domain; verify contextually.")

    return {"sender_risk_score": min(score, 100), "sender_findings": findings, "domain": domain_lower}
