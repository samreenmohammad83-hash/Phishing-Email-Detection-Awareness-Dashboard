import sys, os, tempfile
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

def test_api_import():
    from backend.app import app
    assert app.title.startswith("Phishing Email")

def test_database_roundtrip():
    from backend import database
    old = database.DB_PATH
    fd, path = tempfile.mkstemp(suffix=".db")
    os.close(fd)
    database.DB_PATH = path
    try:
        database.init_db()
        aid = database.save_analysis("example.org","Test",50,"SUSPICIOUS",[("test",5,"demo")],[])
        item = database.get_analysis(aid)
        assert item["risk_score"] == 50
        assert database.delete_analysis(aid)
        assert database.get_analysis(aid) is None
    finally:
        database.DB_PATH = old
        try: os.remove(path)
        except OSError: pass
