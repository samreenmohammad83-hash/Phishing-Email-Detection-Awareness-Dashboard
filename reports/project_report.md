# Phishing Email Detection & Awareness Dashboard — Project Report

## Abstract

Phishing is a social-engineering technique in which deceptive messages attempt to influence recipients into unsafe actions. This project presents a defensive educational dashboard that analyzes synthetic email content, sender patterns, URLs, and attachment filenames. A transparent rule-based engine produces a bounded risk score and explains the indicators that contributed to it. An optional machine-learning module uses TF-IDF text representation and Logistic Regression. The application also provides analysis history, analytics, and a phishing-awareness checklist.

## Introduction

Email remains an important communication channel and therefore an important surface for social engineering. Automated analysis can help prioritize messages for human review, but detection must account for uncertainty, false positives, and false negatives.

## Problem Statement

Users and analysts need understandable signals that help them decide whether an email deserves further review. A black-box label alone does not explain why an email was flagged.

## Objectives

1. Analyze synthetic/authorized emails safely.
2. Extract sender, content, URL, and attachment indicators.
3. Produce explainable risk assessments.
4. Store non-sensitive analysis metadata.
5. Provide dashboard analytics.
6. Demonstrate optional ML evaluation.
7. Teach safe phishing-recognition habits.

## Phishing Background

Common social-engineering signals include urgency, fear, unexpected financial requests, credential requests, unusual sender patterns, suspicious links, and unexpected attachments. None is conclusive in isolation.

## Proposed System

The system accepts sender, subject, body, and an optional attachment filename. Preprocessing extracts URLs and sender-domain information. Specialized analyzers generate findings. The risk engine applies project-defined weights and caps the score at 100. Results are saved as metadata and displayed through Streamlit.

## Feature Engineering

Features include urgency counts, credential counts, financial counts, threat counts, URL counts, raw-IP usage, shortener patterns, domain length, subdomain count, suspicious attachment signals, generic greetings, password/personal-information requests, punctuation, uppercase ratio, and message lengths.

## Sender Analysis

The sender analyzer checks format, domain length, subdomain depth, unusual characters, punctuation patterns, and optional display-name context. It does not automatically treat an unfamiliar domain as malicious.

## URL Analysis

URLs are analyzed as strings using parsing. Scheme, hostname, length, subdomains, raw IP usage, shortener patterns, suspicious keywords, and unusual characters are considered. The application never opens the URL. HTTPS is useful for transport security but does not by itself establish that a site is trustworthy.

## Attachment Analysis

Only filenames are inspected. Potentially executable/script extensions and double extensions are flagged. No attachment is executed.

## Rule-Based Detection

The project uses a weighted rule engine. Example weights include suspicious sender +15, urgency +10, credential request +20, suspicious URL +20, suspicious attachment +25, generic greeting +5, and threat/fear language +10. The score is capped at 100. Thresholds are project assumptions and should be calibrated with validation data.

## Machine Learning

The optional model uses TF-IDF with Logistic Regression. Accuracy, precision, recall, and F1 are calculated from a held-out test set. Accuracy alone can be misleading because class imbalance and different operational costs matter. Precision relates to false-alarm reduction; recall relates to reducing missed phishing; F1 balances the two.

## Hybrid Detection

A future hybrid version can combine the interpretable rule score with an ML probability using a validated weighting scheme. An ML probability must not be presented as certainty.

## Dashboard

The dashboard displays totals, classifications, average risk, indicator counts, trends, analysis results, history, and awareness guidance.

## Security & Privacy

The application treats email content as untrusted. Uploads are restricted to `.txt`/`.eml` with a size limit. Raw bodies are not stored by default. Production deployments should add authentication, authorization, rate limiting, HTTPS, secure secret management, and stronger content isolation.

## False Positives and False Negatives

A legitimate HR request can contain urgent wording and trigger a rule. A carefully constructed phishing email can avoid obvious keywords. These cases demonstrate why automated detection should support analyst judgment.

## SOC Relevance

A SOC analyst can use the system for initial triage: inspect sender, URLs, attachment metadata, content signals, risk score, and explainable findings before deciding on the next response action.

## MITRE ATT&CK Context

The project relates conceptually to phishing/social-engineering behaviors including Spearphishing Attachment, Spearphishing Link, and Spearphishing via Service. Exact technique IDs should be verified against the current ATT&CK release when the report is submitted.

## Testing

The project includes more than 25 automated tests covering content, URLs, attachments, scoring boundaries, features, database behavior, API imports, and dataset generation.

## Results

The supplied synthetic dataset contains 600 records and the automated test suite currently passes 29/29 tests (with two framework deprecation warnings). On the fixed 80/20 stratified synthetic test split, the TF-IDF + Logistic Regression baseline produced:

- Accuracy: 1.0000
- Precision: 1.0000
- Recall: 1.0000
- F1: 1.0000

Confusion matrix: `[[60, 0], [0, 60]]`.

These results are **only measurements on the generated synthetic dataset**. The templates intentionally contain strong lexical differences between the two classes, so the perfect score should not be interpreted as real-world phishing-detection effectiveness. A production evaluation would require diverse, representative, authorized data and careful validation against distribution shift.

## Limitations

The dataset is synthetic, reputation services are not connected, email authentication headers are not analyzed, and rule thresholds are not production-calibrated.

## Future Scope

Header analysis, SPF/DKIM/DMARC ingestion, reputation enrichment, attachment hashes, better NLP, explainable AI, SOC ticketing/SIEM integration, threat-intelligence enrichment, awareness quizzes, and feedback-based retraining.

## Conclusion

The project demonstrates a safe, explainable approach to phishing-email triage using multiple static signals. It combines cybersecurity fundamentals, feature engineering, secure coding, analytics, and optional machine learning while keeping the demonstration data fictional and the analysis non-invasive.
