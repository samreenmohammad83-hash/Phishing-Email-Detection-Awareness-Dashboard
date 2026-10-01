# Quick Start — Windows PowerShell

```powershell
cd Phishing-Email-Detection-Awareness-Dashboard
python -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
pip install -r requirements.txt

python data\generate_dataset.py
python ml\train_model.py

# Terminal 1
uvicorn backend.app:app --reload --port 8000

# Terminal 2
.\.venv\Scripts\Activate.ps1
streamlit run frontend\streamlit_app.py
```

If PowerShell blocks activation, use:
```powershell
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
```

Then activate the environment again.
