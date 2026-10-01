from typing import Dict, List

def calculate_phishing_score(sender_result: Dict, content_result: Dict, url_results: List[Dict], attachment_result: Dict) -> Dict:
    score = 0
    reasons = []
    # Project weights from the specification; scores are capped and are not probabilities.
    if sender_result.get("sender_risk_score", 0) >= 10:
        score += 15
        reasons.append(("sender", 15, "Suspicious sender pattern detected."))
    if content_result.get("keyword_counts", {}).get("urgency", 0):
        score += 10
        reasons.append(("urgency", 10, "Urgent language detected."))
    if content_result.get("keyword_counts", {}).get("credential_request", 0):
        score += 20
        reasons.append(("credential_request", 20, "Credential/account verification language detected."))
    if any(u.get("risk_score", 0) >= 15 for u in url_results):
        score += 20
        reasons.append(("url", 20, "Suspicious URL structure detected."))
    if attachment_result.get("risk_score", 0) >= 25:
        score += 25
        reasons.append(("attachment", 25, "Attachment filename requires caution."))
    if content_result.get("generic_greeting"):
        score += 5
        reasons.append(("generic_greeting", 5, "Generic greeting detected; weak signal only."))
    if content_result.get("keyword_counts", {}).get("fear", 0):
        score += 10
        reasons.append(("fear", 10, "Threat/fear language detected."))

    score = min(score, 100)
    if score <= 20:
        classification = "LOW RISK"
    elif score <= 40:
        classification = "MODERATE RISK"
    elif score <= 70:
        classification = "SUSPICIOUS"
    else:
        classification = "HIGH RISK / LIKELY PHISHING"

    recommendations = [
        "Do not click unexpected links.",
        "Do not open unexpected attachments.",
        "Verify the sender through a trusted channel.",
        "Report suspicious email to the security team.",
        "Use the organization's official website/app directly."
    ] if score >= 21 else [
        "Continue normal security hygiene.",
        "Verify unexpected requests before acting.",
        "Avoid sharing credentials through email."
    ]
    return {"risk_score": score, "classification": classification, "reasons": reasons, "recommendations": recommendations}
