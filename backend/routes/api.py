from fastapi import APIRouter, HTTPException, UploadFile, File
from pydantic import BaseModel, Field
from backend.services.preprocessing import preprocess_email
from backend.services.sender_analyzer import analyze_sender
from backend.services.content_analyzer import analyze_email_content
from backend.services.url_analyzer import analyze_urls, analyze_url
from backend.services.attachment_analyzer import analyze_attachment
from backend.services.risk_engine import calculate_phishing_score
from backend.services.features import extract_email_features
from backend.database import save_analysis, list_analyses, get_analysis, delete_analysis, dashboard_stats

router = APIRouter(prefix="/api")

class EmailRequest(BaseModel):
    sender: str = Field(..., min_length=3, max_length=320)
    subject: str = Field("", max_length=500)
    body: str = Field("", max_length=100000)
    attachment_name: str = Field("", max_length=255)
    display_name: str = Field("", max_length=200)

class URLRequest(BaseModel):
    url: str = Field(..., min_length=4, max_length=2048)

@router.post("/analyze")
def analyze_email(req: EmailRequest):
    p = preprocess_email(req.sender, req.subject, req.body, req.attachment_name)
    sender = analyze_sender(req.sender, req.display_name)
    content = analyze_email_content(req.subject, req.body)
    urls = analyze_urls(p["urls"])
    attachment = analyze_attachment(req.attachment_name)
    risk = calculate_phishing_score(sender, content, urls, attachment)
    features = extract_email_features(req.sender, req.subject, req.body, req.attachment_name)
    analysis_id = save_analysis(p["sender_domain"], req.subject, risk["risk_score"], risk["classification"], risk["reasons"], urls)
    return {
        "analysis_id": analysis_id,
        "risk": risk,
        "sender_analysis": sender,
        "content_analysis": content,
        "url_analysis": urls,
        "attachment_analysis": attachment,
        "features": features
    }

@router.post("/analyze/url")
def analyze_single_url(req: URLRequest):
    # Static parsing only; the service never requests the URL.
    return analyze_url(req.url)

@router.post("/analyze/file")
async def analyze_text_file(file: UploadFile = File(...)):
    if not file.filename.lower().endswith((".txt", ".eml")):
        raise HTTPException(400, "Only .txt and .eml files are allowed.")
    data = await file.read()
    if len(data) > 1_048_576:
        raise HTTPException(413, "File exceeds the 1 MB upload limit.")
    text = data.decode("utf-8", errors="replace")
    return {"filename": file.filename, "content_preview": text[:10000]}

@router.get("/analyses")
def analyses():
    return list_analyses()

@router.get("/analyses/{analysis_id}")
def analysis(analysis_id: int):
    result = get_analysis(analysis_id)
    if not result:
        raise HTTPException(404, "Analysis not found.")
    return result

@router.delete("/analyses/{analysis_id}")
def remove_analysis(analysis_id: int):
    if not delete_analysis(analysis_id):
        raise HTTPException(404, "Analysis not found.")
    return {"deleted": True}

@router.get("/dashboard/stats")
def stats():
    return dashboard_stats()

@router.get("/dashboard/indicators")
def indicators():
    return dashboard_stats()["top_indicators"]
