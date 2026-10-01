import re
from typing import Dict
from .url_analyzer import extract_urls

def clean_text(text: str) -> str:
    # Preserve punctuation and URLs because they can be security indicators.
    return re.sub(r"\s+", " ", text or "").strip()

def preprocess_email(sender: str, subject: str, body: str, attachment_name: str = "") -> Dict:
    sender = clean_text(sender)
    subject = clean_text(subject)
    body = clean_text(body)
    domain = sender.rsplit("@", 1)[1].lower() if "@" in sender else ""
    urls = extract_urls(f"{subject}\n{body}")
    attachment_ext = "." + attachment_name.rsplit(".", 1)[1].lower() if "." in attachment_name else ""
    return {
        "sender": sender, "subject": subject, "body": body, "sender_domain": domain,
        "urls": urls, "attachment_extension": attachment_ext
    }
