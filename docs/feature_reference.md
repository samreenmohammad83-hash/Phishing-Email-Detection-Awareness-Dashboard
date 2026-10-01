# Feature Reference

- `urgent_keyword_count`: count of urgency phrases.
- `credential_keyword_count`: count of credential/account-verification phrases.
- `financial_keyword_count`: count of payment/billing pressure terms.
- `threat_keyword_count`: count of fear/consequence terms.
- `url_count`: URLs extracted from subject/body.
- `suspicious_url_count`: URLs with static risk indicators.
- `has_ip_url`: at least one URL uses an IP hostname.
- `has_shortened_url_pattern`: known shortener hostname pattern.
- `sender_domain_length`: character length of sender domain.
- `subdomain_count`: approximate subdomain depth.
- `suspicious_attachment`: risky extension/double-extension signal.
- `generic_greeting`: generic greeting pattern.
- `contains_password_request`: credential keyword detected.
- `contains_personal_info_request`: personal-information keyword detected.
- `exclamation_count`: number of `!`.
- `uppercase_ratio`: uppercase alphabetic characters / alphabetic characters.
- `body_length`: body character count.
- `subject_length`: subject character count.

No feature alone proves phishing. Context and multiple signals are required.
