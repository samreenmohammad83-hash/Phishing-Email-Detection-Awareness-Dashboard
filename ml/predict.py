from pathlib import Path
import joblib

MODEL = Path(__file__).resolve().parents[1] / "models" / "phishing_tfidf_logreg.joblib"

def predict(text: str):
    if not MODEL.exists():
        raise FileNotFoundError("Train the model first with: python ml/train_model.py")
    pipe = joblib.load(MODEL)
    probability = float(pipe.predict_proba([text])[0][1])
    return {"phishing_probability": round(probability, 4), "label": "PHISHING" if probability >= 0.5 else "LEGITIMATE"}
