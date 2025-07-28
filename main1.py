import streamlit as st
import os
import email
import requests
from email import policy
from email.parser import BytesParser
from bs4 import BeautifulSoup
from dotenv import load_dotenv
from io import BytesIO
from reportlab.lib.pagesizes import letter
from reportlab.pdfgen import canvas

# Load environment variables
load_dotenv()
VT_API_KEY = os.getenv("VT_API_KEY")

# ---------- Setup UI ----------
st.set_page_config(page_title="📧 Email Phishing Analyzer", layout="centered")
st.title("📧 Email Phishing Analyzer")

# uploaded_files = st.file_uploader("📤 Upload one or more `.eml` files", type=["eml"], accept_multiple_files=True)

uploaded_files = st.file_uploader(
    "📤 Upload one or more `.eml` files",
    type=["eml"],
    accept_multiple_files=True,
    label_visibility="visible"
)


# ---------- Utility: Verdict Color ----------
def verdict_color(verdict):
    if verdict.lower() == "legit":
        return "green"
    elif verdict.lower() == "suspicious":
        return "orange"
    elif verdict.lower() == "phishing":
        return "red"
    return "gray"

# ---------- Header Check ----------
def check_headers(email_bytes):
    msg = BytesParser(policy=policy.default).parsebytes(email_bytes)
    headers = dict(msg.items())
    spf = headers.get('Received-SPF', '')
    dkim = headers.get('Authentication-Results', '')
    from_addr = headers.get("From", "")
    return_path = headers.get("Return-Path", "")

    verdict = "Legit"
    score = 100
    reasons = []

    if "fail" in spf.lower():
        score -= 30
        reasons.append("❌ SPF check failed")
    elif "softfail" in spf.lower():
        score -= 20
        reasons.append("⚠️ SPF softfail")

    if "dkim=fail" in dkim.lower():
        score -= 30
        reasons.append("❌ DKIM check failed")
    elif "dkim=none" in dkim.lower():
        score -= 10
        reasons.append("⚠️ DKIM not found")

    if return_path and from_addr and return_path not in from_addr:
        score -= 20
        reasons.append("⚠️ Mismatch between From and Return-Path")

    if score < 50:
        verdict = "Phishing"
    elif score < 80:
        verdict = "Suspicious"

    return {"method": "Header SPF/DKIM Check", "verdict": verdict, "score": score, "reasons": reasons}

# ---------- VirusTotal Link Reputation ----------
def check_links(email_bytes, api_key):
    msg = email.message_from_bytes(email_bytes)
    html_body = ""
    for part in msg.walk():
        if part.get_content_type() == "text/html":
            html_body = part.get_payload(decode=True).decode(errors="ignore")

    links = [a.get("href") for a in BeautifulSoup(html_body, "html.parser").find_all("a", href=True)]
    if not links:
        return {
            "method": "Link Reputation (VirusTotal)",
            "verdict": "Legit",
            "score": 90,
            "details": []
        }

    results = []
    headers = {"x-apikey": api_key}

    for url in links:
        try:
            submit_resp = requests.post("https://www.virustotal.com/api/v3/urls", headers=headers, data={"url": url})
            if submit_resp.status_code != 200:
                results.append((url, 0))
                continue

            url_id = submit_resp.json()["data"]["id"]
            analysis_resp = requests.get(f"https://www.virustotal.com/api/v3/analyses/{url_id}", headers=headers)
            if analysis_resp.status_code != 200:
                results.append((url, 0))
                continue

            stats = analysis_resp.json()["data"]["attributes"]["stats"]
            malicious = stats.get("malicious", 0)
            suspicious = stats.get("suspicious", 0)
            hits = malicious + suspicious
            results.append((url, hits))
        except Exception:
            results.append((url, 0))

    total_hits = sum(score for url, score in results)
    verdict = "Legit" if total_hits == 0 else "Suspicious" if total_hits <= 2 else "Phishing"
    final_score = 100 if total_hits == 0 else 60 if total_hits <= 2 else 30

    return {
        "method": "Link Reputation (VirusTotal)",
        "verdict": verdict,
        "score": final_score,
        "details": results
    }

# ---------- Keyword + Heuristic Check ----------
def check_keywords(email_bytes):
    msg = BytesParser(policy=policy.default).parsebytes(email_bytes)
    subject = msg.get("Subject", "") or ""
    from_addr = msg.get("From", "") or ""
    body = ""
    for part in msg.walk():
        if part.get_content_type() == "text/plain":
            body += part.get_payload(decode=True).decode(errors="ignore")

    text = subject + " " + body

    keywords = [
    # Account & Security
    "account", "login", "verify", "confirmation", "update", "password",
    "credentials", "security", "suspend", "unlock", "reactivate", "identity",
    "access", "reset", "secure", "authentication", "deactivate", "breach",

    # Urgency & Pressure
    "urgent", "immediately", "asap", "action required", "important", "final notice",
    "act now", "last warning", "attention", "limited time", "emergency",

    # Money & Billing
    "invoice", "payment", "bank", "billing", "refund", "transaction",
    "overdue", "charge", "credit card", "wire transfer", "balance", "funds",

    # Click & Links
    "click here", "login here", "visit link", "open attachment", "download",
    "see document", "follow this link", "verify here", "submit form",

    # Rewards & Temptation
    "free", "win", "gift", "reward", "voucher", "bonus", "offer",
    "congratulations", "selected", "claim", "prize", "exclusive", "promo",

    # Popular Brands (for impersonation detection)
    "amazon", "paypal", "google", "apple", "microsoft", "facebook",
    "instagram", "netflix", "bank", "atm", "support", "helpdesk",

    # Miscellaneous
    "compliance", "violation", "terms", "alert", "notification", "unusual activity"
    ]

    matches = [kw for kw in keywords if kw in text.lower()]
    score = 100
    verdict = "Legit"
    reasons = []

    if len(matches) >= 5:
        verdict = "Phishing"
        score = 30
        reasons.append("❌ Too many phishing keywords")
    elif 2 <= len(matches) < 5:
        verdict = "Suspicious"
        score = 60
        reasons.append("⚠️ Moderate number of phishing keywords")

    suspicious_tlds = [".ru", ".cn", ".xyz", ".top", ".tk"]
    if any(tld in from_addr.lower() for tld in suspicious_tlds):
        verdict = "Phishing"
        score = min(score, 40)
        reasons.append(f"❌ Suspicious TLD in sender: {from_addr}")

    return {
        "method": "Keyword & Heuristic Check",
        "verdict": verdict,
        "score": score,
        "matches": matches,
        "reasons": reasons
    }

# ---------- Combine Scores ----------
def combine_scores(results):
    final_score = sum([r["score"] for r in results]) // len(results)
    if final_score >= 80:
        return "Legit", final_score
    elif final_score >= 50:
        return "Suspicious", final_score
    else:
        return "Phishing", final_score

# ---------- Generate PDF Report ----------
def generate_pdf_report(filename, results, final_verdict, final_score):
    buffer = BytesIO()
    c = canvas.Canvas(buffer, pagesize=letter)
    c.setFont("Helvetica", 12)

    c.drawString(30, 750, f"Email Report for: {filename}")
    y = 720
    for r in results:
        c.drawString(40, y, f"{r['method']}: {r['verdict']} (Score: {r['score']})")
        y -= 20
        for reason in r.get("reasons", []):
            c.drawString(60, y, f"- {reason}")
            y -= 15
        if r.get("matches"):
            c.drawString(60, y, f"Keywords: {', '.join(r['matches'])}")
            y -= 20
        if r.get("details"):
            for url, hits in r["details"]:
                c.drawString(60, y, f"{url} → Hits: {hits}")
                y -= 15
    c.drawString(30, y-20, f"Final Verdict: {final_verdict} | Score: {final_score}/100")
    c.save()
    buffer.seek(0)
    return buffer

# ---------- MAIN UI ----------
if uploaded_files:

    # st.markdown("### 📨 Uploaded Files:")
    # for file in uploaded_files:
    #     st.markdown(f"- 📄 `{file.name}`")

    if st.button("🔍 Scan Emails"):
        tabs = st.tabs([f"📧 {f.name}" for f in uploaded_files])

        for i, uploaded in enumerate(uploaded_files):
            with tabs[i]:
                st.subheader(f"📊 Scan Results for `{uploaded.name}`")

                email_bytes = uploaded.read()
                header_result = check_headers(email_bytes)
                uploaded.seek(0)
                keyword_result = check_keywords(uploaded.read())
                uploaded.seek(0)
                vt_result = check_links(uploaded.read(), VT_API_KEY) if VT_API_KEY else {"method": "VirusTotal", "verdict": "Unknown", "score": 60, "details": []}

                all_results = [header_result, keyword_result, vt_result]
                final_verdict, final_score = combine_scores(all_results)
                verdict_col = verdict_color(final_verdict)

                for r in all_results:
                    st.markdown(f"""<div style="background-color:{verdict_color(r['verdict'])};padding:10px;border-radius:10px">
                    <strong>{r['method']} → {r['verdict']}</strong> (Score: {r['score']})</div>""", unsafe_allow_html=True)
                    for reason in r.get("reasons", []):
                        st.markdown(f"- {reason}")
                    if r.get("matches"):
                        st.caption("🔑 Matched Keywords: " + ", ".join(r["matches"]))
                    for url, hits in r.get("details", []):
                        if hits > 0:
                            st.markdown(f"🔍 **{url}** → ⚠️ {hits} detections")
                        else:
                            st.caption(f"✅ {url}")

                st.markdown("---")
                st.markdown(f"""<div style="background-color:{verdict_col};color:white;padding:20px;border-radius:15px;text-align:center">
                    <h2>🏁 Final Verdict: {final_verdict}</h2><p>Overall Score: {final_score}/100</p></div>""", unsafe_allow_html=True)

                # PDF Download
                pdf_buf = generate_pdf_report(uploaded.name, all_results, final_verdict, final_score)
                st.download_button("📥 Download PDF Report", data=pdf_buf, file_name=f"{uploaded.name}_report.pdf", mime="application/pdf")
else:
    st.info("Please upload one or more `.eml` files to begin analysis.")
