# Architecture

```mermaid
flowchart TD
    U[User] --> UI[Streamlit Web Dashboard]
    UI --> API[FastAPI REST API]
    API --> PRE[Preprocessing]
    PRE --> SA[Sender Analyzer]
    PRE --> CA[Content Analyzer]
    PRE --> UA[Static URL Analyzer]
    PRE --> AA[Attachment Filename Analyzer]
    PRE --> FE[Feature Engineering]
    FE --> RE[Rule-Based Risk Engine]
    FE --> ML[Optional TF-IDF + Logistic Regression]
    RE --> EX[Explainable Findings]
    ML --> EX
    EX --> DB[(SQLite Analysis History)]
    DB --> UI
```

## Data flow

Email input → preprocessing → sender/content/URL/attachment analysis → feature extraction → rule engine and optional ML → risk score/classification → explanation/recommendations → history/dashboard.

Suspicious URLs are parsed as strings only. Attachments are never executed.
