from fastapi import FastAPI
from backend.database import init_db
from backend.routes.api import router

app = FastAPI(
    title="Phishing Email Detection & Awareness API",
    version="1.0.0",
    description="Defensive static analysis API using synthetic/authorized email data."
)
app.include_router(router)

@app.on_event("startup")
def startup():
    init_db()

@app.get("/health")
def health():
    return {"status": "ok", "mode": "defensive-static-analysis"}
