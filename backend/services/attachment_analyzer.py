import re
from typing import Dict

DANGEROUS = {".exe", ".scr", ".bat", ".cmd", ".js", ".vbs", ".ps1", ".jar", ".msi"}
ARCHIVES = {".zip", ".rar", ".7z", ".iso"}
DOUBLE_EXT_RE = re.compile(r"\.[A-Za-z0-9]{1,8}\.[A-Za-z0-9]{1,8}$")

def analyze_attachment(filename: str) -> Dict:
    name = (filename or "").strip()
    if not name:
        return {"risk_score": 0, "findings": [], "extension": ""}
    lower = name.lower()
    extension = "." + lower.rsplit(".", 1)[1] if "." in lower else ""
    score = 0
    findings = []
    if extension in DANGEROUS:
        score += 50
        findings.append(f"Potentially executable/script attachment extension: {extension}")
    elif extension in ARCHIVES:
        score += 10
        findings.append(f"Archive attachment requires contextual review: {extension}")
    if DOUBLE_EXT_RE.search(lower):
        score += 25
        findings.append("Double-extension filename detected.")
    return {"risk_score": min(score, 100), "findings": findings, "extension": extension}
