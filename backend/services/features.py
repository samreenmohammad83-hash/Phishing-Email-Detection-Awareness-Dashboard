from typing import Dict
from .preprocessing import preprocess_email
from .content_analyzer import analyze_email_content
from .url_analyzer import analyze_urls
from .attachment_analyzer import analyze_attachment
from .sender_analyzer import analyze_sender

def extract_email_features(sender: str, subject: str, body: str, attachment_name: str = "") -> Dict:
    p = preprocess_email(sender, subject, body, attachment_name)
    content = analyze_email_content(subject, body)
    urls = analyze_urls(p["urls"])
    attachment = analyze_attachment(attachment_name)
    sender_result = analyze_sender(sender)

    suspicious_urls = [u for u in urls if u["risk_score"] > 0]
    return {
        "urgent_keyword_count": content["keyword_counts"].get("urgency", 0),
        "credential_keyword_count": content["keyword_counts"].get("credential_request", 0),
        "financial_keyword_count": content["keyword_counts"].get("financial", 0),
        "threat_keyword_count": content["keyword_counts"].get("fear", 0),
        "url_count": len(urls),
        "suspicious_url_count": len(suspicious_urls),
        "has_ip_url": any(u["has_ip"] for u in urls),
        "has_shortened_url_pattern": any(u["has_shortener"] for u in urls),
        "sender_domain_length": len(p["sender_domain"]),
        "subdomain_count": max(0, p["sender_domain"].count("." ) - 1) if p["sender_domain"] else 0,
        "suspicious_attachment": attachment["risk_score"] > 0,
        "generic_greeting": content["generic_greeting"],
        "contains_password_request": content["keyword_counts"].get("credential_request", 0) > 0,
        "contains_personal_info_request": content["keyword_counts"].get("personal_info", 0) > 0,
        "exclamation_count": content["exclamation_count"],
        "uppercase_ratio": content["uppercase_ratio"],
        "body_length": len(body or ""),
        "subject_length": len(subject or ""),
        "sender_risk_score": sender_result["sender_risk_score"],
        "url_risk_scores": [u["risk_score"] for u in urls],
        "attachment_risk_score": attachment["risk_score"],
    }
