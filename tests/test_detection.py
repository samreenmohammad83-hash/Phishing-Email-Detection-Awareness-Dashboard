import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import pytest
from backend.services.sender_analyzer import analyze_sender
from backend.services.content_analyzer import analyze_email_content
from backend.services.url_analyzer import analyze_url
from backend.services.attachment_analyzer import analyze_attachment
from backend.services.features import extract_email_features
from backend.services.risk_engine import calculate_phishing_score

def test_legitimate_email():
    c = analyze_email_content("Workshop Reminder", "Hello student, the workshop is Friday.")
    s = analyze_sender("training@example.org")
    u = []
    a = analyze_attachment("")
    r = calculate_phishing_score(s,c,u,a)
    assert r["risk_score"] <= 20

def test_urgent_email():
    c = analyze_email_content("URGENT", "Act now or your account will be suspended.")
    assert c["keyword_counts"]["urgency"] >= 1

def test_credential_request():
    c = analyze_email_content("Verify", "Please verify your password.")
    assert c["keyword_counts"]["credential_request"] >= 1

def test_financial_request():
    c = analyze_email_content("Invoice", "Payment due today.")
    assert c["keyword_counts"]["financial"] >= 1

def test_generic_greeting():
    assert analyze_email_content("", "Dear customer, hello.")["generic_greeting"]

def test_safe_https_url():
    r = analyze_url("https://example.org/training")
    assert r["risk_score"] == 0

def test_raw_ip_url():
    r = analyze_url("http://198.51.100.10/verify-account")
    assert r["has_ip"] and r["risk_score"] >= 25

def test_non_https():
    assert analyze_url("http://example.org/info")["risk_score"] >= 15

def test_excessive_subdomains():
    assert analyze_url("https://a.b.c.example.org/login")["subdomain_count"] >= 3

def test_suspicious_url_keyword():
    assert "Security-sensitive keyword" in " ".join(analyze_url("https://example.org/verify-account")["findings"])

def test_no_url_features():
    f = extract_email_features("training@example.org","Hi","No link here.")
    assert f["url_count"] == 0

def test_multiple_urls():
    f = extract_email_features("training@example.org","Info","https://example.org/a https://example.com/b")
    assert f["url_count"] == 2

def test_normal_attachment():
    assert analyze_attachment("agenda.pdf")["risk_score"] == 0

def test_executable_attachment():
    assert analyze_attachment("run.js")["risk_score"] >= 50

def test_double_extension():
    assert analyze_attachment("invoice.pdf.exe")["risk_score"] >= 75

def test_empty_subject():
    f = extract_email_features("training@example.org","","Hello")
    assert f["subject_length"] == 0

def test_empty_body():
    f = extract_email_features("training@example.org","Notice","")
    assert f["body_length"] == 0

def test_invalid_sender():
    assert analyze_sender("not-an-email")["sender_risk_score"] > 0

def test_high_uppercase_ratio():
    c = analyze_email_content("URGENT", "VERIFY YOUR ACCOUNT NOW")
    assert c["uppercase_ratio"] >= 0.45

def test_multiple_exclamation_marks():
    c = analyze_email_content("URGENT!!!", "ACT NOW!!!")
    assert c["exclamation_count"] >= 3

def test_score_cap():
    c = analyze_email_content("URGENT!!!", "Dear customer, act now immediately. Verify your password or account will be suspended. Payment due today!")
    s = analyze_sender("security-alert@account-check.invalid.test")
    u = [analyze_url("http://198.51.100.10/verify-account")]
    a = analyze_attachment("invoice.pdf.exe")
    r = calculate_phishing_score(s,c,u,a)
    assert 0 <= r["risk_score"] <= 100

def test_rule_boundary_low():
    r = calculate_phishing_score({"sender_risk_score":0},{"keyword_counts":{},"generic_greeting":False},[],{"risk_score":0})
    assert r["risk_score"] == 0

def test_feature_dict():
    f = extract_email_features("security@example.org","Verify account","Please verify your password at http://198.51.100.10/login","invoice.pdf.exe")
    for key in ["urgent_keyword_count","credential_keyword_count","url_count","has_ip_url","suspicious_attachment"]:
        assert key in f

def test_attachment_static_only():
    result = analyze_attachment("payload.ps1")
    assert "execute" not in str(result).lower() or result["risk_score"] > 0

def test_url_static_only():
    result = analyze_url("http://198.51.100.10/login")
    assert result["hostname"] == "198.51.100.10"

def test_fear_language():
    c = analyze_email_content("", "Your account will be suspended.")
    assert c["keyword_counts"]["fear"] >= 1
