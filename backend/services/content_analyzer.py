import re
from typing import List, Dict

PATTERNS = {
    "urgency": (r"\b(urgent|immediately|act now|right away|within \d+ hours?|today only|as soon as possible)\b", 10,
                "Urgency/manipulation language was detected."),
    "fear": (r"\b(suspend|suspended|terminate|locked|blocked|security alert|legal action|penalty)\b", 10,
             "Fear or consequence language was detected."),
    "financial": (r"\b(payment|invoice|refund|wire|transfer|outstanding|billing|bank|payment due|gift card)\b", 10,
                  "Financial-pressure language was detected."),
    "credential_request": (r"\b(password|passcode|otp|one[- ]time password|login|sign in|verify your account|credentials)\b", 20,
                           "A credential or account-verification request was detected."),
    "personal_info": (r"\b(date of birth|social security|personal details|identity|address|phone number|tax id)\b", 15,
                      "A request for personal information was detected."),
    "reward": (r"\b(you have won|winner|prize|reward|bonus|lottery|claim your)\b", 10,
               "Reward/prize language was detected."),
}

GENERIC_GREETINGS = re.compile(r"^\s*(dear customer|dear user|hello customer|dear member|valued customer)\b", re.I)

def analyze_email_content(subject: str, body: str) -> Dict:
    text = f"{subject}\n{body}".strip()
    findings: List[Dict] = []
    counts = {}
    for category, (pattern, score, explanation) in PATTERNS.items():
        matches = re.findall(pattern, text, flags=re.I)
        counts[category] = len(matches)
        if matches:
            findings.append({"type": category, "severity": min(score, 25), "description": explanation})

    if GENERIC_GREETINGS.search(body or ""):
        findings.append({"type": "generic_greeting", "severity": 5,
                         "description": "A generic greeting is present; this is a weak signal by itself."})

    exclamations = (subject + " " + body).count("!")
    uppercase_chars = sum(c.isupper() for c in (subject + " " + body) if c.isalpha())
    alpha_chars = sum(c.isalpha() for c in (subject + " " + body))
    uppercase_ratio = uppercase_chars / alpha_chars if alpha_chars else 0.0

    if exclamations >= 3:
        findings.append({"type": "excessive_exclamation", "severity": 3,
                         "description": "Multiple exclamation marks may indicate emphasis or pressure."})
    if uppercase_ratio >= 0.45 and alpha_chars >= 20:
        findings.append({"type": "high_uppercase_ratio", "severity": 4,
                         "description": "Unusually high uppercase usage was detected."})

    return {
        "findings": findings,
        "keyword_counts": counts,
        "generic_greeting": bool(GENERIC_GREETINGS.search(body or "")),
        "exclamation_count": exclamations,
        "uppercase_ratio": round(uppercase_ratio, 4),
    }
