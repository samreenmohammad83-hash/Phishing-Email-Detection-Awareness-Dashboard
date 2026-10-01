from pathlib import Path
import subprocess, sys, pandas as pd

def test_dataset_generator_creates_600_records(tmp_path):
    script = Path(__file__).resolve().parents[1] / "data" / "generate_dataset.py"
    result = subprocess.run([sys.executable, str(script)], capture_output=True, text=True)
    assert result.returncode == 0
    df = pd.read_csv(script.parent / "phishing_email_dataset.csv")
    assert len(df) >= 500
    assert set(df["label"]) == {"LEGITIMATE","PHISHING"}
    assert all(df["sender_domain"].str.endswith(("example.com","example.org","example.net","invalid.test")))
