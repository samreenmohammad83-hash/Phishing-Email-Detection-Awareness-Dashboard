# API Design

| Method | Endpoint | Purpose | Validation |
|---|---|---|---|
| POST | `/api/analyze` | Analyze email | Pydantic fields, bounded lengths |
| POST | `/api/analyze/url` | Static URL analysis | URL string length |
| POST | `/api/analyze/file` | Read safe `.txt/.eml` sample | Extension + 1 MB limit |
| GET | `/api/analyses` | History | None |
| GET | `/api/analyses/{id}` | One analysis | Integer ID |
| GET | `/api/dashboard/stats` | Dashboard metrics | None |
| GET | `/api/dashboard/indicators` | Indicator counts | None |
| DELETE | `/api/analyses/{id}` | Delete metadata | Integer ID |

Production deployments should add authentication, authorization, CSRF protections where applicable, rate limiting, HTTPS, structured audit logs, and stronger secret management.
