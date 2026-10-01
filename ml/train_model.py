from pathlib import Path
import joblib, pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.pipeline import Pipeline
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score

ROOT = Path(__file__).resolve().parents[1]
DATA = ROOT / "data" / "phishing_email_dataset.csv"
MODEL = ROOT / "models" / "phishing_tfidf_logreg.joblib"

def train():
    df = pd.read_csv(DATA)
    text = (df["subject"].fillna("") + " " + df["body"].fillna("")).values
    y = (df["label"] == "PHISHING").astype(int).values
    x_train, x_test, y_train, y_test = train_test_split(text, y, test_size=0.2, random_state=42, stratify=y)
    pipe = Pipeline([
        ("tfidf", TfidfVectorizer(ngram_range=(1,2), min_df=1, max_features=10000)),
        ("model", LogisticRegression(max_iter=1000))
    ])
    pipe.fit(x_train, y_train)
    pred = pipe.predict(x_test)
    metrics = {
        "accuracy": accuracy_score(y_test, pred),
        "precision": precision_score(y_test, pred, zero_division=0),
        "recall": recall_score(y_test, pred, zero_division=0),
        "f1": f1_score(y_test, pred, zero_division=0)
    }
    joblib.dump(pipe, MODEL)
    print("Model:", MODEL)
    print("Metrics:", {k: round(v, 4) for k, v in metrics.items()})
    return metrics

if __name__ == "__main__":
    train()
