# Phishing Email Detection & Awareness Dashboard 🛡️

> Defensive cybersecurity education project for analyzing synthetic or authorized email data using explainable phishing indicators.

## Overview

This project analyzes email sender information, subject/body language, URLs, and attachment filenames without visiting URLs or executing attachments. It combines a transparent rule-based engine with an optional TF-IDF + Logistic Regression model.

## Problem Statement

Phishing messages use social engineering to create urgency, fear, financial pressure, or requests for credentials/personal information. A useful educational detector should show not only a classification but also the evidence that influenced the score.

## Objectives

- Analyze synthetic email samples safely.
- Detect multiple phishing indicators.
- Produce a 0–100 project risk score.
- Explain findings to users and analysts.
- Store safe metadata for history/analytics.
- Demonstrate optional ML classification.
- Teach phishing-awareness practices.

## Features

- Sender analysis
- Content/social-engineering analysis
- Static URL analysis
- Attachment filename analysis
- Rule-based scoring
- Explainable recommendations
- Optional ML
- SQLite history
- Streamlit dashboard
- 25+ automated tests
- Synthetic 600-record dataset

## Architecture

See [`docs/architecture.md`](docs/architecture.md).

## Technology Stack

Python, FastAPI, Streamlit, SQLite, pandas, scikit-learn, Plotly, pytest.

## Dataset

`data/generate_dataset.py` creates 600 synthetic records. Domains are restricted to `example.com`, `example.org`, `example.net`, and `invalid.test`. The demonstration IP `198.51.100.10` is from a documentation/reserved range.

Run:

```powershell
python data\generate_dataset.py
```

## Detection Indicators

The detector considers sender patterns, urgency, fear, financial pressure, credential requests, personal-information requests, generic greetings, URLs, attachment extensions, and formatting signals.

No single indicator proves phishing. The rule thresholds are project assumptions and should be calibrated with validation data for real deployments.

## Risk Scoring

- 0–20: LOW RISK
- 21–40: MODERATE RISK
- 41–70: SUSPICIOUS
- 71–100: HIGH RISK / LIKELY PHISHING

These labels are not probabilities.

## Optional Machine Learning

The ML module uses TF-IDF + Logistic Regression and reports accuracy, precision, recall, and F1. Accuracy alone is insufficient because phishing detection has asymmetric operational costs: false positives can create alert fatigue, while false negatives can leave phishing undetected.

On the current 600-record synthetic dataset, the fixed 80/20 stratified test split produced 1.0000 accuracy, precision, recall, and F1 with a 60/60 confusion matrix per class. This is a **synthetic benchmark only**; the dataset uses deliberately distinct templates and therefore does not establish production performance.

Run:

```powershell
python ml\train_model.py
```

The generated model is ignored by Git by default.

## Installation

### Windows PowerShell

```powershell
git clone <YOUR-REPOSITORY-URL>
cd Phishing-Email-Detection-Awareness-Dashboard

python -m venv .venv
.\.venv\Scripts\Activate.ps1

python -m pip install --upgrade pip
pip install -r requirements.txt

python data\generate_dataset.py
python ml\train_model.py
```

Start the backend in terminal 1:

```powershell
uvicorn backend.app:app --reload --port 8000
```

Start the dashboard in terminal 2:

```powershell
.\.venv\Scripts\Activate.ps1
streamlit run frontend\streamlit_app.py
```

Open the Streamlit URL shown in the terminal. FastAPI docs are at `http://127.0.0.1:8000/docs`.

## Safe Demonstration

### Synthetic phishing-style sample

Sender: `security-alert@account-check.invalid.test`

Subject: `URGENT: Verify Your Account Immediately`

URL: `http://198.51.100.10/verify-account`

Expected signals: urgency, credential/account verification language, suspicious sender pattern, raw IP URL, non-HTTPS URL.

### Synthetic legitimate sample

Sender: `training@example.org`

Subject: `Cybersecurity Workshop Reminder`

Body: normal informational workshop reminder with no credential request.

The expected result is low risk, but the actual score should be produced by the running system rather than assumed.

## Security & Privacy

- Never execute attachments.
- Never automatically visit suspicious URLs.
- Avoid storing raw email bodies by default.
- Escape/sanitize rendered content.
- Validate upload extensions and size.
- Keep secrets in environment variables.
- Add authentication/authorization and rate limiting for production.
- Use HTTPS in production.
- Treat all uploaded email content as untrusted input.

## False Positives / False Negatives

A legitimate HR message can contain urgency and still be genuine. Conversely, a sophisticated phishing message may contain few obvious indicators. Multiple signals and human review are therefore important.

## SOC Workflow

Reported email → initial triage → sender analysis → URL analysis → attachment metadata analysis → content analysis → risk score → analyst review → classification → response.

Automated scoring supports analyst judgment; it does not replace it.

## API

See [`docs/api.md`](docs/api.md).

## Testing

```powershell
pytest -q
```

The suite covers legitimate and phishing-style content, URLs, attachments, boundaries, feature extraction, database round trips, API imports, and dataset generation.

## Limitations

- No live reputation lookup.
- No SPF/DKIM/DMARC header validation.
- No real-world malicious data.
- Rule thresholds are not production-calibrated.
- ML performance depends on the synthetic dataset and does not establish production efficacy.
- URL analysis is static only.

## Future Improvements

Email-header analysis, SPF/DKIM/DMARC ingestion, domain reputation, URL reputation APIs, attachment hash reputation, better NLP, explainable AI, SIEM/ticket integration, threat-intelligence enrichment, awareness quizzes, and feedback-based retraining.

## Disclaimer

This project is designed for cybersecurity education and defensive analysis using synthetic or authorized data. It must not be used to send phishing emails, harvest credentials, attack systems, execute suspicious attachments, or automatically visit suspicious URLs.

## Author

Student cybersecurity portfolio project.
