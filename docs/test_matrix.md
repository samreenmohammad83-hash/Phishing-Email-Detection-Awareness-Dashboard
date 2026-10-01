# Test Matrix

| ID | Scenario | Expected |
|---|---|---|
| T01 | Legitimate email | Low score |
| T02 | Urgent email | Urgency finding |
| T03 | Credential request | Credential finding |
| T04 | Financial request | Financial finding |
| T05 | Generic greeting | Generic greeting finding |
| T06 | Safe URL | Low URL risk |
| T07 | Raw IP URL | IP finding |
| T08 | Non-HTTPS URL | Scheme finding |
| T09 | Excessive subdomains | Subdomain finding |
| T10 | Suspicious URL keyword | Keyword finding |
| T11 | No URL | URL count zero |
| T12 | Multiple URLs | Correct count |
| T13 | Normal attachment | Low attachment risk |
| T14 | Executable attachment | High attachment signal |
| T15 | Double extension | Double-extension signal |
| T16 | Empty subject | Valid feature extraction |
| T17 | Empty body | Valid feature extraction |
| T18 | Invalid sender | Sender finding |
| T19 | High uppercase ratio | Formatting finding |
| T20 | Multiple exclamation marks | Formatting finding |
| T21 | Score boundary/cap | 0–100 |
| T22 | Database save | Round trip works |
| T23 | API validation/import | API loads |
| T24 | ML prediction | Model loads after training |
| T25 | History retrieval | Stored analysis returned |

Run with `pytest -q`. Actual results should be taken from the test run; do not manually claim Pass/Fail without running it.
