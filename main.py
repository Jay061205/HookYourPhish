import streamlit as st
import re
import time
import requests
import random
from fpdf import FPDF
from io import BytesIO
from datetime import datetime
import os
import email
from email import policy
from email.parser import BytesParser
from bs4 import BeautifulSoup
from dotenv import load_dotenv
from reportlab.lib.pagesizes import letter
from reportlab.pdfgen import canvas
import streamlit.components.v1 as components

st.set_page_config(page_title="HookYourPhish",page_icon="🦈", layout="centered")
st.title("🦈 HookYourPhish")

# Create main tabs
tab1, tab2, tab3 = st.tabs(["🔗 Check URL", "📧 Check Email", "🌐 Check Domain"],)

class StyledPDF(FPDF):
    def __init__(self):
        super().__init__()
        self.set_auto_page_break(auto=True, margin=15)
    
    def header(self):
        # Add a header with company/app branding
        self.set_fill_color(41, 128, 185)  # Blue header
        self.rect(0, 0, 210, 25, 'F')
        
        self.set_font('Arial', 'B', 20)
        self.set_text_color(255, 255, 255)  # White text
        self.cell(0, 20, 'PHISHING DETECTION REPORT', 0, 1, 'C')
        self.ln(5)
        
    def footer(self):
        # Add footer with page number and timestamp
        self.set_y(-15)
        self.set_font('Arial', 'I', 8)
        self.set_text_color(128, 128, 128)  # Gray text
        self.cell(0, 10, f'Generated on {datetime.now().strftime("%Y-%m-%d %H:%M:%S")} - Page {self.page_no()}', 0, 0, 'C')
    
    def add_section_header(self, title, icon=""):
        # Add colored section headers
        self.ln(10)
        self.set_fill_color(52, 73, 94)  # Dark blue-gray
        self.set_text_color(255, 255, 255)
        self.set_font('Arial', 'B', 14)
        self.cell(0, 12, f"{title}", 0, 1, 'L', True)
        self.ln(5)
        self.set_text_color(0, 0, 0)  # Reset to black
    
    def add_status_box(self, status, is_threat=False):
        # Add colored status boxes
        if is_threat:
            self.set_fill_color(231, 76, 60)  # Red for threats
            self.set_text_color(255, 255, 255)
        else:
            self.set_fill_color(46, 204, 113)  # Green for safe
            self.set_text_color(255, 255, 255)
        
        self.set_font('Arial', 'B', 12)
        self.cell(0, 10, f"STATUS: {status}", 0, 1, 'C', True)
        self.ln(5)
        self.set_text_color(0, 0, 0)  # Reset to black
    
    def add_info_row(self, label, value, is_important=False):
        # Add formatted information rows
        if is_important:
            self.set_font('Arial', 'B', 11)
            self.set_fill_color(241, 196, 15)  # Yellow highlight
        else:
            self.set_font('Arial', '', 10)
            self.set_fill_color(236, 240, 241)  # Light gray
        
        # Label cell
        self.cell(60, 8, f"{label}:", 1, 0, 'L', True)
        
        # Value cell
        self.set_fill_color(255, 255, 255)  # White background for value
        if is_important:
            self.set_font('Arial', 'B', 11)
        else:
            self.set_font('Arial', '', 10)
        
        # Handle long text
        if len(str(value)) > 50:
            self.cell(130, 8, str(value)[:47] + "...", 1, 1, 'L', True)
        else:
            self.cell(130, 8, str(value), 1, 1, 'L', True)
    
    def add_risk_meter(self, risk_score):
        # Add a visual risk meter
        self.ln(5)
        self.set_font('Arial', 'B', 12)
        self.cell(0, 8, f"Risk Score: {risk_score}/10", 0, 1, 'C')
        
        # Draw risk meter bar
        bar_width = 100
        bar_height = 8
        x_start = (210 - bar_width) / 2
        
        # Background bar (gray)
        self.set_fill_color(200, 200, 200)
        self.rect(x_start, self.get_y(), bar_width, bar_height, 'F')
        
        # Risk level bar (colored based on risk)
        fill_width = (risk_score / 10) * bar_width
        if risk_score <= 3:
            self.set_fill_color(46, 204, 113)  # Green
        elif risk_score <= 6:
            self.set_fill_color(241, 196, 15)  # Yellow
        else:
            self.set_fill_color(231, 76, 60)  # Red
        
        self.rect(x_start, self.get_y(), fill_width, bar_height, 'F')
        
        # Border
        self.set_draw_color(0, 0, 0)
        self.rect(x_start, self.get_y(), bar_width, bar_height, 'D')
        self.ln(15)

def generate_pdf(google_data, heuristic_result):
    pdf = StyledPDF()
    pdf.add_page()
    
    # Executive Summary Box
    pdf.set_fill_color(245, 245, 245)
    pdf.rect(10, pdf.get_y(), 190, 25, 'F')
    pdf.set_font('Arial', 'B', 12)
    pdf.set_text_color(0, 0, 0)
    pdf.cell(0, 8, "EXECUTIVE SUMMARY", 0, 1, 'C')
    
    # Determine overall threat status
    google_threat = bool(google_data and any(key.lower() in ['threat', 'malware', 'phishing'] for key in google_data.keys()))
    heuristic_threat = heuristic_result and heuristic_result.get('Risk Score', 0) > 5
    
    if google_threat or heuristic_threat:
        pdf.add_status_box("THREAT DETECTED", True)
    else:
        pdf.add_status_box("NO THREATS FOUND", False)
    
    # Google Safe Browsing Section
    pdf.add_section_header("Google Safe Browsing Analysis")
    
    if google_data:
        for key, value in google_data.items():
            is_important = key.lower() in ['threat type', 'platform affected']
            pdf.add_info_row(key, value, is_important)
    else:
        pdf.set_fill_color(46, 204, 113)  # Green
        pdf.set_text_color(255, 255, 255)
        pdf.set_font('Arial', 'B', 11)
        pdf.cell(0, 10, "No threats detected by Google Safe Browsing", 0, 1, 'C', True)
        pdf.set_text_color(0, 0, 0)
    
    # Heuristic Analysis Section
    pdf.add_section_header("Heuristic Analysis")
    
    if heuristic_result:
        # Add risk meter if risk score exists
        if 'Risk Score' in heuristic_result:
            pdf.add_risk_meter(heuristic_result['Risk Score'])
        
        for key, value in heuristic_result.items():
            if key == 'Risk Score':
                continue  # Already displayed in risk meter
            
            if isinstance(value, list):
                pdf.add_info_row(key, f"{len(value)} items detected")
                # Add list items with bullets
                pdf.set_font('Arial', '', 9)
                for i, item in enumerate(value, 1):
                    pdf.cell(10, 6, "", 0, 0)  # Indent
                    pdf.cell(0, 6, f"- {item}", 0, 1)
                pdf.ln(2)
            else:
                is_important = key.lower() in ['verdict', 'status']
                pdf.add_info_row(key, value, is_important)
    else:
        pdf.set_fill_color(46, 204, 113)  # Green
        pdf.set_text_color(255, 255, 255)
        pdf.set_font('Arial', 'B', 11)
        pdf.cell(0, 10, "No anomalies detected by heuristic analysis", 0, 1, 'C', True)
        pdf.set_text_color(0, 0, 0)
    
    # Recommendations Section
    pdf.add_section_header("Recommendations")
    pdf.set_font('Arial', '', 10)
    
    if google_threat or heuristic_threat:
        recommendations = [
            "WARNING: Do not enter personal information on this website",
            "WARNING: Avoid downloading files from this source",
            "WARNING: Consider blocking this URL in your security systems",
            "WARNING: Report this URL to your IT security team"
        ]
        pdf.set_text_color(231, 76, 60)  # Red text for warnings
    else:
        recommendations = [
            "SAFE: This URL appears to be safe based on current analysis",
            "SAFE: Continue with normal browsing precautions",
            "SAFE: Keep security software updated",
            "SAFE: Remain vigilant for any suspicious behavior"
        ]
        pdf.set_text_color(46, 204, 113)  # Green text for safe
    
    for rec in recommendations:
        pdf.cell(0, 8, rec, 0, 1)
    
    # Save PDF to buffer
    buffer = BytesIO()
    buffer.write(pdf.output(dest='S').encode('latin-1'))
    buffer.seek(0)
    return buffer

# Example input data
google_result = {
    "Threat Type": "SOCIAL_ENGINEERING",
    "Platform Affected": "ALL PLATFORM",
    "Threat Entry Type": "URL",
    "Google's Cache Validity": "300s"
}

heuristic_result = {
    "Risk Score": 7,
    "Verdict": "High Risk",
    "Anomaly Labels": ["Suspicious Characters", "Too Many Digits"],
    "Anomaly Details": ["URL contains unusual symbols", "Domain has a numeric pattern"]
}

# === Tab 1: Check URL ===
with tab1:
    st.subheader("🔗 Detect Suspicious URLs")
    url = st.text_input("Enter that fishy URL:", placeholder="http://badwebsite.com").strip()

    apiBrowsing, heuristic = st.tabs(["Google Safe Browsing Method", "Heuristic Method"])

    # --- Heuristic Method ---
    with heuristic:
        def check_ip_in_url(url):
            risk_score = 0
            suspicious_keywords = [
                'login', 'secure', 'bank', 'update', 'free', 'bonus', 'account', 'verify', 'verification', 'paypal',
                'signin', 'webscr', 'submit', 'claim', 'win', 'offer', 'gift', 'password', 'credentials', 'invoice',
                'payment', 'admin', 'support', 'confirm', 'ebay', 'apple', 'amazon', 'wallet', 'unlock', 'reset',
                'security', 'alert', 'suspend', 'limit', 'urgent', 'recover', 'authentication', 'insurance',
                'MALWARE', 'SOCIAL_ENGINEERING', 'UNWANTED_SOFTWARE', 'POTENTIALLY_HARMFUL_APPLICATION',
            ]
            anomaly_label = []
            anomaly = []

            if re.search(r'(http[s]?://)?(\d{1,3}\.){3}', url):
                risk_score += 2
                anomaly_label.append("Checking if the URL contains IP Address")
                anomaly.append("IP Address is found in the URL")

            found_keywords = [word for word in suspicious_keywords if word in url.lower()]
            if found_keywords:
                anomaly_label.append("Checking for Suspicious Keywords")
                anomaly.append(f"Suspicious Keywords found: {', '.join(found_keywords)}")
                risk_score += 2 if len(found_keywords) > 2 else 1

            if len(url) >= 75:
                anomaly_label.append("Checking if the URL length is too long")
                anomaly.append("URL is too long")
                risk_score += 1

            if '@' in url:
                anomaly_label.append("Checking if the URL contains '@'")
                anomaly.append("URL contains '@' symbol")
                risk_score += 2

            if risk_score == 0:
                verdict = "✅ No Risk detected, Safe to surf"
                st.success(verdict)
            elif risk_score >= 5:
                verdict = '🚨 High Risk'
                st.error(verdict)
            elif 3 <= risk_score < 5:
                verdict = '⚠️ Medium Risk'
                st.warning(verdict)
            else:
                verdict = '✅ Low Risk'
                st.success(verdict)

            return {
                "risk_score": risk_score,
                "verdict": verdict,
                "anomaly": anomaly,
                "anomaly_label": anomaly_label
            }

        if st.button("Run Heuristic Scan"):
            if not url:
                st.error("🔴 No URL provided")
            elif not (url.startswith("http://") or url.startswith("https://") or url.startswith("www")):
                st.error("❌ Invalid URL")  
            else:
                status = st.empty()
                status.info("🔎 Scanning in progress...")
                time.sleep(2)
                status.empty()

                st.markdown("## 📜 Scan Report")
                results = check_ip_in_url(url)
                st.info(f"**Risk Score:** {results['risk_score']}")

                if results['risk_score'] > 0:
                    st.subheader("🕵 What is detected as suspicious?")
                    for label in results['anomaly_label']:
                        ph = st.empty()
                        ph.markdown(f"⏳ {label}")
                        time.sleep(0.4)
                        ph.empty()

                    for item in results['anomaly']:
                        st.error(f"➡️ {item}")

        

                    if results['risk_score'] > 5:
                        st.markdown("""
                            <h3 style='text-align: center; color: crimson;'>⚠️ Site seems to be suspicious.</h3>
                            <h3 style='text-align: center; color: crimson;'>🚫 We advise you NOT to surf the site.</h3>
                        """, unsafe_allow_html=True)
                    elif 2 <= results['risk_score'] <= 4:
                        st.markdown("""
                            <h3 style='text-align: center; color: orange;'>⚠️ Site seems to be suspicious.</h3>
                            <h3 style='text-align: center; color: orange;'>🚧 Medium risk. Proceed with caution.</h3>
                        """, unsafe_allow_html=True)

            st.info("ℹ️ If phishing is detected using the Google Safe Browsing method and not through the heuristic method, prioritize and rely on the Safe Browsing results.")

    # --- Google Safe Browsing API ---
    with apiBrowsing:
        def check_url_with_google_safe_browsing(api_key, url):
            endpoint = "https://safebrowsing.googleapis.com/v4/threatMatches:find"
            payload = {
                "client": {
                    "clientId": "phishing-detection-site",
                    "clientVersion": "1.0",
                },
                "threatInfo": {
                    "threatTypes": [
                        "MALWARE",
                        "SOCIAL_ENGINEERING",
                        "UNWANTED_SOFTWARE",
                        "POTENTIALLY_HARMFUL_APPLICATION"
                    ],
                    "platformTypes": ["ANY_PLATFORM"],
                    "threatEntryTypes": ["URL"],
                    "threatEntries": [{"url": url}]
                }
            }

            try:
                response = requests.post(f"{endpoint}?key={api_key}", json=payload)
                response.raise_for_status()
                data = response.json()
                return data.get("matches", None)
            except requests.RequestException as e:
                st.error(f"Error: {e}")
                return None

        if st.button("Scan with Google Safe Browsing"):
            if not url:
                st.error("🔴 No URL provided")
            elif not (url.startswith("http://") or url.startswith("https://") or url.startswith("www")):
                st.error("❌ Invalid URL")
            else:
                status = st.empty()
                status.info("🔎 Checking with Google Safe Browsing...")
                time.sleep(2)
                status.empty()

                st.markdown("## 📜 Scan Report")
                matches = check_url_with_google_safe_browsing("AIzaSyDXWxfhC7ZUlwZ8Qhq6UfhIqp6BeiLumyk", url)
                

                if matches:
                    st.error("🚨 The URL is listed as malicious in Google's database.")

                    st.markdown("### 🧾 Threat Report")

                    for threat_info in matches:
                        st.write(f"**Threat Type:** {threat_info['threatType']}")
                        st.write(f"**Platform Affected:** {'ALL PLATFORMS' if threat_info['platformType'] == 'ANY_PLATFORM' else threat_info['platformType']}")
                        st.write(f"**Threat Entry Type:** {threat_info['threatEntryType']}")
                    st.warning("🚧 Consider running a Heuristic Scan (Manual Check method) using the tab above.")
                else:
                    st.info("⚠️ The URL was not found in Google's threat database.")
                    st.warning("🚧 This does NOT guarantee safety. Try Heuristic Scan from the other tab.")
        # Divider
        st.markdown("---")

        # Generate PDF and show download button
        pdf_buffer = generate_pdf(google_result, heuristic_result)
        st.download_button(
            label="📄 Download Report as PDF",
            data=pdf_buffer,
            file_name="phishing_report.pdf",
            mime="application/pdf"
        )

with tab2:      
    eml, paste_text = st.tabs(["Upload .eml file", "Paste the text from mail"], width="stretch")
    with eml:
        load_dotenv()
        VT_API_KEY = os.getenv("VT_API_KEY")

        # ---------- Setup UI ----------
        

        # uploaded_files = st.file_uploader("📤 Upload one or more `.eml` files", type=["eml"], accept_multiple_files=True)

        @st.dialog("📖 How to download .eml files?")
        def show_info_dialog():
            st.video("./static/eml_file_download.mp4", muted=True, width="stretch",autoplay=True,loop=True)

        # Show ℹ️ button
        
        col1, col2 = st.columns([9, 1])
        
        with col1:
            st.subheader("📧 Email Phishing Analyzer")
        
        with col2:
            if st.button("ⓘ", help="How to download .eml file"):
                show_info_dialog()

        uploaded_files = st.file_uploader(
            "📤 Upload one or more `.eml` files",
            type=["eml"],
            accept_multiple_files=True,
            label_visibility="visible",
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
                        st.markdown('---')
                        st.download_button("📥 Download PDF Report", data=pdf_buf, file_name=f"{uploaded.name}_report.pdf", mime="application/pdf")
        else:
            st.info("Please upload one or more `.eml` files to begin analysis.")

    with paste_text:
        st.markdown("### Manually Input Email Data")
        header_input = st.text_area("📋 Paste Email Headers here", height=150)
        content_input = st.text_area("✉ Paste full raw email content here (including headers and body)", height=300)
        use_manual_input = st.button("🔍 Scan Manual Input")

        def verdict_color(verdict):
            if verdict.lower() == "legit":
                return "green"
            elif verdict.lower() == "suspicious":
                return "orange"
            elif verdict.lower() == "phishing":
                return "red"
            return "gray"

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
                reasons.append("⚠ SPF softfail")

            if "dkim=fail" in dkim.lower():
                score -= 30
                reasons.append("❌ DKIM check failed")
            elif "dkim=none" in dkim.lower():
                score -= 10
                reasons.append("⚠ DKIM not found")

            if return_path and from_addr and return_path not in from_addr:
                score -= 20
                reasons.append("⚠ Mismatch between From and Return-Path")

            if score < 50:
                verdict = "Phishing"
            elif score < 80:
                verdict = "Suspicious"

            return {"method": "Header SPF/DKIM Check", "verdict": verdict, "score": score, "reasons": reasons}

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
                reasons.append("⚠ Moderate number of phishing keywords")

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

        def combine_scores(results):
            final_score = sum([r["score"] for r in results]) // len(results)
            if final_score >= 80:
                return "Legit", final_score
            elif final_score >= 50:
                return "Suspicious", final_score
            else:
                return "Phishing", final_score

        def prepare_email_from_manual(header_text, content_text):
            # If full raw email content pasted, we use that directly
            if content_text.strip():
                return content_text.encode("utf-8")

            # If only headers pasted, we create a minimal email bytes object
            if header_text.strip():
                # Combine headers with a basic minimal body to form an email message
                raw_email = header_text.strip() + "\n\nThis is a minimal body."
                return raw_email.encode("utf-8")

            return None

        def run_analysis(email_bytes):
            """Function to run all analysis checks and display results"""
            st.subheader("📊 Scan Results")
            
            # Header Check
            with st.spinner("Checking headers..."):
                header_result = check_headers(email_bytes)
            st.markdown(
                f"""<div style="background-color:{verdict_color(header_result['verdict'])};padding:10px;border-radius:10px">
                <strong>📋 {header_result['method']} → {header_result['verdict']}</strong> (Score: {header_result['score']})
                </div>""", unsafe_allow_html=True)
            for reason in header_result["reasons"]:
                st.markdown(f"- {reason}")

            # Keyword Heuristics
            with st.spinner("Analyzing keywords..."):
                keyword_result = check_keywords(email_bytes)
            st.markdown(
                f"""<div style="background-color:{verdict_color(keyword_result['verdict'])};padding:10px;border-radius:10px">
                <strong>🧠 {keyword_result['method']} → {keyword_result['verdict']}</strong> (Score: {keyword_result['score']})
                </div>""", unsafe_allow_html=True)
            if keyword_result["matches"]:
                st.caption("🔑 Matched Keywords: " + ", ".join(keyword_result["matches"]))
            for reason in keyword_result["reasons"]:
                st.markdown(f"- {reason}")

            # VirusTotal Scan
            if VT_API_KEY:
                with st.spinner("Checking URLs with VirusTotal..."):
                    vt_result = check_links(email_bytes, VT_API_KEY)
                st.markdown(
                    f"""<div style="background-color:{verdict_color(vt_result['verdict'])};padding:10px;border-radius:10px">
                    <strong>🔗 {vt_result['method']} → {vt_result['verdict']}</strong> (Score: {vt_result['score']})
                    </div>""", unsafe_allow_html=True)
                for url, hits in vt_result.get("details", []):
                    if hits > 0:
                        st.markdown(f"🔍 *{url}* → ⚠ {hits} detections")
                    else:
                        st.caption(f"✅ {url}")
            else:
                vt_result = {"method": "VirusTotal", "verdict": "Unknown", "score": 60}
                st.warning("⚠ VirusTotal API key not found!")

            # Final Verdict
            all_results = [header_result, keyword_result, vt_result]
            final_verdict, final_score = combine_scores(all_results)
            verdict_col = verdict_color(final_verdict)

            st.markdown("---")
            st.markdown(
                f"""<div style="background-color:{verdict_col};color:white;padding:20px;border-radius:15px;text-align:center">
                <h2>🏁 Final Verdict: {final_verdict}</h2>
                <p>Overall Score: {final_score}/100</p>
                </div>""", unsafe_allow_html=True)

        # ---------- MAIN UI ----------


            st.success("📬 Manual email data received. Running scan...")
            run_analysis(email_bytes)
            st.info("Please either upload a .eml file or enter headers/email content to begin analysis.")


with tab3:
    st.markdown("<h3 style='text-align: center;'>ℹ️ This side of the page is under construction</h3>", unsafe_allow_html=True)
    st.markdown("<h3 style='text-align: center;'>Consider enjoying this comic image</h3>", unsafe_allow_html=True)

    st.markdown("Random xkcd Comic Viewer")

    # Get latest comic number
    latest_comic_url = "https://xkcd.com/info.0.json"
    try:
        res = requests.get(latest_comic_url)
        res.raise_for_status()
        latest_num = res.json()["num"]

        # Pick a random comic
        random_num = random.randint(1, latest_num)
        comic_url = f"https://xkcd.com/{random_num}/info.0.json"

        comic_res = requests.get(comic_url)
        comic_res.raise_for_status()
        comic_data = comic_res.json()

        # Display comic
        st.subheader(f"#{comic_data['num']}: {comic_data['title']}")
        st.image(comic_data['img'], caption=comic_data['alt'])

        # Credits
        st.markdown(
            """
            ---
            **Image Source**: [xkcd.com](https://xkcd.com)  
            **License**: [Creative Commons Attribution-NonCommercial 2.5](https://xkcd.com/license.html)
            """
        )

    except Exception as e:
        st.error(f"Failed to load comic: {e}")