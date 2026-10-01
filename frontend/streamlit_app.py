import os, requests, pandas as pd, streamlit as st
import plotly.express as px

API = os.getenv("API_BASE_URL", "http://127.0.0.1:8000/api")
st.set_page_config(page_title="Phishing Email Detection Dashboard", page_icon="🛡️", layout="wide")

st.title("🛡️ Phishing Email Detection & Awareness Dashboard")
st.caption("Defensive educational tool using static analysis. Suspicious URLs are never visited.")

tabs = st.tabs(["Email Analyzer", "Dashboard", "History", "Awareness", "API Help"])

with tabs[0]:
    st.subheader("Analyze a safe sample email")
    c1, c2 = st.columns(2)
    sender = c1.text_input("Sender", "training@example.org")
    display = c1.text_input("Display name", "Training")
    subject = c2.text_input("Subject", "Cybersecurity Workshop Reminder")
    attachment = c2.text_input("Attachment filename (optional)", "")
    body = st.text_area("Email body", height=220,
        value="Hello student,\nThis is a reminder that the cybersecurity workshop is scheduled for Friday at 10:00 AM. No action is required.")
    uploaded = st.file_uploader("Optional safe .txt/.eml sample", type=["txt","eml"])
    if uploaded:
        st.info("Uploaded text is treated as untrusted content and is not executed.")
        body = uploaded.read().decode("utf-8", errors="replace")[:100000]
    if st.button("🔎 ANALYZE EMAIL", type="primary"):
        try:
            r = requests.post(f"{API}/analyze", json={
                "sender": sender, "display_name": display, "subject": subject,
                "body": body, "attachment_name": attachment
            }, timeout=10)
            r.raise_for_status()
            result = r.json()
            risk = result["risk"]
            st.metric("Risk Score", f'{risk["risk_score"]}/100')
            st.subheader(f'Classification: {risk["classification"]}')
            if risk["reasons"]:
                st.markdown("### Why?")
                for _, sev, desc in risk["reasons"]:
                    st.write(f"• {desc} (+{sev})")
            st.markdown("### Sender Analysis")
            st.json(result["sender_analysis"])
            st.markdown("### URL Analysis")
            if result["url_analysis"]:
                st.dataframe(pd.DataFrame(result["url_analysis"]), use_container_width=True)
            else:
                st.write("No URLs detected.")
            st.markdown("### Attachment Analysis")
            st.json(result["attachment_analysis"])
            st.markdown("### Recommended Actions")
            for x in risk["recommendations"]:
                st.write(f"• {x}")
        except Exception as e:
            st.error(f"Backend unavailable or request failed: {e}")

with tabs[1]:
    st.subheader("Security Analytics")
    try:
        stats = requests.get(f"{API}/dashboard/stats", timeout=5).json()
        a,b,c,d,e = st.columns(5)
        a.metric("Total", stats["total_emails_analyzed"])
        b.metric("Likely Phishing", stats["likely_phishing"])
        c.metric("Suspicious", stats["suspicious"])
        d.metric("Low/Moderate", stats["low_risk"])
        e.metric("Average Risk", stats["average_risk_score"])
        dist = pd.DataFrame(list(stats["classification_distribution"].items()), columns=["Classification","Count"])
        if not dist.empty:
            st.plotly_chart(px.bar(dist, x="Classification", y="Count", title="Classification Distribution"), use_container_width=True)
        inds = pd.DataFrame(stats["top_indicators"])
        if not inds.empty:
            st.plotly_chart(px.bar(inds, x="indicator_type", y="c", title="Top Detected Indicators"), use_container_width=True)
        trend = pd.DataFrame(stats["trend"])
        if not trend.empty:
            st.plotly_chart(px.line(trend, x="day", y="avg_score", title="Average Risk Trend"), use_container_width=True)
    except Exception as e:
        st.warning(f"No dashboard data yet: {e}")

with tabs[2]:
    st.subheader("Analysis History")
    try:
        rows = requests.get(f"{API}/analyses", timeout=5).json()
        df = pd.DataFrame(rows)
        if not df.empty:
            choice = st.multiselect("Filter classification", sorted(df["classification"].unique()))
            if choice:
                df = df[df["classification"].isin(choice)]
            df = df.sort_values("risk_score", ascending=False)
            st.dataframe(df, use_container_width=True)
        else:
            st.info("No analyses stored yet.")
    except Exception as e:
        st.error(str(e))

with tabs[3]:
    st.subheader("How to Spot a Phishing Email")
    for item in [
        "Check the sender address and domain spelling.",
        "Be cautious with unexpected urgency.",
        "Inspect links without opening them.",
        "Never provide passwords or OTPs by email.",
        "Treat unexpected attachments carefully.",
        "Be cautious with generic greetings.",
        "Verify unusual payment requests through a trusted channel.",
        "Watch for threatening or manipulative language.",
        "Consider the context and whether the request is expected.",
        "When unsure, report the message to your security team."
    ]:
        st.write("☐ " + item)
    st.info("Before You Click: pause → inspect sender → inspect destination → verify context → use the official app/site → report if suspicious.")

with tabs[4]:
    st.subheader("REST API")
    st.code("""
POST /api/analyze
POST /api/analyze/url
GET  /api/analyses
GET  /api/analyses/{id}
GET  /api/dashboard/stats
GET  /api/dashboard/indicators
DELETE /api/analyses/{id}
""")
    st.write("Interactive API documentation is available at http://127.0.0.1:8000/docs when the backend is running.")
