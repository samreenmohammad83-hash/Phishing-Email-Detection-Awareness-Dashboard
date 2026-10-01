import os, sqlite3, json
from datetime import datetime, timezone

DB_PATH = os.getenv("DATABASE_PATH", "phishing_dashboard.db")

def get_conn():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    conn = get_conn()
    conn.executescript("""
    CREATE TABLE IF NOT EXISTS analyses (
        analysis_id INTEGER PRIMARY KEY AUTOINCREMENT,
        sender_domain TEXT NOT NULL,
        subject TEXT NOT NULL,
        risk_score INTEGER NOT NULL,
        classification TEXT NOT NULL,
        created_at TEXT NOT NULL
    );
    CREATE TABLE IF NOT EXISTS indicators (
        indicator_id INTEGER PRIMARY KEY AUTOINCREMENT,
        analysis_id INTEGER NOT NULL,
        indicator_type TEXT NOT NULL,
        description TEXT NOT NULL,
        severity INTEGER NOT NULL,
        FOREIGN KEY(analysis_id) REFERENCES analyses(analysis_id) ON DELETE CASCADE
    );
    CREATE TABLE IF NOT EXISTS url_analyses (
        url_analysis_id INTEGER PRIMARY KEY AUTOINCREMENT,
        analysis_id INTEGER NOT NULL,
        url_safe_representation TEXT NOT NULL,
        risk_score INTEGER NOT NULL,
        findings TEXT NOT NULL,
        FOREIGN KEY(analysis_id) REFERENCES analyses(analysis_id) ON DELETE CASCADE
    );
    """)
    conn.commit()
    conn.close()

def save_analysis(sender_domain, subject, risk_score, classification, reasons, urls):
    conn = get_conn()
    now = datetime.now(timezone.utc).isoformat()
    cur = conn.execute(
        "INSERT INTO analyses(sender_domain,subject,risk_score,classification,created_at) VALUES(?,?,?,?,?)",
        (sender_domain, subject, risk_score, classification, now)
    )
    analysis_id = cur.lastrowid
    for kind, severity, desc in reasons:
        conn.execute(
            "INSERT INTO indicators(analysis_id,indicator_type,description,severity) VALUES(?,?,?,?)",
            (analysis_id, kind, desc, severity)
        )
    for u in urls:
        conn.execute(
            "INSERT INTO url_analyses(analysis_id,url_safe_representation,risk_score,findings) VALUES(?,?,?,?)",
            (analysis_id, u.get("url","")[:500], u.get("risk_score",0), json.dumps(u.get("findings",[])))
        )
    conn.commit()
    conn.close()
    return analysis_id

def list_analyses():
    conn = get_conn()
    rows = conn.execute("SELECT * FROM analyses ORDER BY created_at DESC").fetchall()
    conn.close()
    return [dict(r) for r in rows]

def get_analysis(analysis_id):
    conn = get_conn()
    row = conn.execute("SELECT * FROM analyses WHERE analysis_id=?", (analysis_id,)).fetchone()
    indicators = conn.execute("SELECT * FROM indicators WHERE analysis_id=?", (analysis_id,)).fetchall()
    urls = conn.execute("SELECT * FROM url_analyses WHERE analysis_id=?", (analysis_id,)).fetchall()
    conn.close()
    if not row:
        return None
    result = dict(row)
    result["indicators"] = [dict(x) for x in indicators]
    result["urls"] = [dict(x) for x in urls]
    return result

def delete_analysis(analysis_id):
    conn = get_conn()
    conn.execute("DELETE FROM url_analyses WHERE analysis_id=?", (analysis_id,))
    conn.execute("DELETE FROM indicators WHERE analysis_id=?", (analysis_id,))
    cur = conn.execute("DELETE FROM analyses WHERE analysis_id=?", (analysis_id,))
    conn.commit()
    conn.close()
    return cur.rowcount > 0

def dashboard_stats():
    conn = get_conn()
    total = conn.execute("SELECT COUNT(*) c FROM analyses").fetchone()["c"]
    avg = conn.execute("SELECT COALESCE(AVG(risk_score),0) a FROM analyses").fetchone()["a"]
    by_class = conn.execute("SELECT classification, COUNT(*) c FROM analyses GROUP BY classification").fetchall()
    indicators = conn.execute("SELECT indicator_type, COUNT(*) c FROM indicators GROUP BY indicator_type ORDER BY c DESC LIMIT 10").fetchall()
    trend = conn.execute("""
        SELECT substr(created_at,1,10) day, COUNT(*) total, AVG(risk_score) avg_score
        FROM analyses GROUP BY day ORDER BY day
    """).fetchall()
    conn.close()
    classes = {r["classification"]: r["c"] for r in by_class}
    return {
        "total_emails_analyzed": total,
        "likely_phishing": classes.get("HIGH RISK / LIKELY PHISHING", 0),
        "suspicious": classes.get("SUSPICIOUS", 0),
        "low_risk": classes.get("LOW RISK", 0) + classes.get("MODERATE RISK", 0),
        "average_risk_score": round(avg, 2),
        "classification_distribution": classes,
        "top_indicators": [dict(r) for r in indicators],
        "trend": [dict(r) for r in trend],
    }
