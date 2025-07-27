import streamlit as st
import re
import time
import requests

st.title("Phising Detection Site")
tab1, tab2, tab3 = st.tabs(["🔗 Check URL", "📧 Check Email", "🌐 Check Domain"])
with tab1:
    st.subheader("🔗 Detect the suspective URLs")
    apiBrowsing, heuristic = st.tabs(['Google Safe Browsing Method','Heuristic Method'])

    # Heuristic Method (Manual Checks)
    with heuristic:
        def check_ip_in_url(url):
            risk_score = 0
            suspicious_keywords = [
            'login', 'secure', 'bank', 'update', 'free', 'bonus', 'account', 'verify', 'verification', 'paypal',
            'signin', 'webscr', 'submit', 'claim', 'win', 'offer', 'gift', 'password', 'credentials', 'invoice',
            'payment', 'admin', 'support', 'confirm', 'ebay', 'apple', 'amazon', 'wallet', 'unlock', 'reset',
            'security', 'alert', 'suspend', 'limit', 'urgent', 'recover', 'authentication', 'insurance'
            ]
            anomaly_label = []
            anomaly = []
            
            ip_pattern = re.compile(r'(http[s]?://)?(\d{1,3}\.){3}')       # it sees if the url contains ip address like 192.234.0
            ip_in_url  = bool(ip_pattern.search(url))
            if ip_in_url :
                risk_score+=2
                anomaly_label.append("Checking if the URL contains IP Address")
                anomaly.append('IP Address is found in the URL')
                

            found_keywords = [word for word in suspicious_keywords if word in url.lower()]      # To see if it contains any suspicious words in url
            if found_keywords:
                anomaly_label.append("Checking for Suspicious Keywords")
                anomaly.append(f"Suspicious Keywords found in the URL: " + ", ".join(found_keywords))
                keywords_len = len(found_keywords)
                if keywords_len>2:
                    risk_score+=2
                else:
                    risk_score+=1

            url_length = len(url)       # Long urls could confuse the search engines, so it can be a lil sussy
            if url_length >= 75:
                anomaly_label.append("Checking if the URL length is too long")
                anomaly.append("URL is too long")
                risk_score+=1

            has_at_symbol = '@' in url
            if has_at_symbol:
                anomaly_label.append("Checking if the URL contains '@'")
                anomaly.append("URL contains '@' symbol")
                risk_score+=2

            if risk_score == 0:
                verdict = "✅ No Risk detected, Safe to surf"
                st.success(verdict)
            elif risk_score >= 5:
                verdict = '🚨 High Risk'
                st.error(verdict)
            elif 3 >= risk_score < 5:
                verdict = '⚠️ Medium Risk'
                st.warning(verdict)
            else:
                verdict = '✅ Low Risk'
                st.success(verdict)
            

            return{
                "ip_in_url": ip_in_url,
                "found_keywords": found_keywords,
                "url_length": url_length,
                "has_at_symbol": has_at_symbol,
                "risk_score": risk_score,
                "verdict": verdict,
                "anomaly": anomaly,
                "anomaly_label": anomaly_label,
            }
            

        with st.form(key="url_form"):
            st.subheader("👤 Heuristic Method in use")
            url = st.text_input("Enter that fishy url: ", placeholder="http://badwebsite.com").strip()
            submit = st.form_submit_button("Scan URL")
            if url.strip() == "" and submit:
                st.error("🟥 No URL found, enter the URL in the textbox")
            elif submit and not (url.startswith("http://") or url.startswith("https://") or url.startswith("www")):
                st.error("❌ Invalid URL")
            else:
                if submit:
                    status = st.empty()
                    status.info("🔎 Scanning in progress...")
                    time.sleep(2)
                    status.empty()
                    st.markdown("## 📝 Scan Report")
                    
                    results = check_ip_in_url(url)
                    if results['risk_score'] == 0:
                        st.info(f'**Risk Score:** {results['risk_score']}')
                    else:
                        st.info(f'**Risk Score:** {results['risk_score']}')
                        st.subheader('🕵️ What is detected as suspicious?')
                        # st.markdown("➡️" + "\n\n➡️ ".join(results['anomaly']))

                        for item in results["anomaly"]:
                            placeholder_list = [] 

                        for label in results['anomaly_label']:
                                ph = st.empty()
                                ph.markdown(f"⏳ {label}")
                                placeholder_list.append(ph)
                                time.sleep(0.5)

                        time.sleep(1)   
                        for ph in placeholder_list:
                            ph.empty()
                        for item in results["anomaly"]:
                                st.error(f"\n\n➡️ {item}")
                                time.sleep(0.5)
                        time.sleep(1)
                        if results['risk_score'] > 5:
                            st.markdown(
                                "<h3 style='text-align: center; color: crimson;'>⚠️ Site seems to be suspicious.</h3>",
                                unsafe_allow_html=True
                            )
                            st.markdown(
                                "<h3 style='text-align: center; color: crimson;'>🚫 We advise you NOT to surf the site.</h3>",
                                unsafe_allow_html=True
                            )

                        elif 2 <= results['risk_score'] <= 4:
                            st.markdown(
                                "<h3 style='text-align: center; color: orange;'>⚠️ Site seems to be suspicious.</h3>",
                                unsafe_allow_html=True
                            )
                            st.markdown(
                                "<h3 style='text-align: center; color: orange;'>🚧 It appears to be at MEDIUM risk. You may surf the site at your own risk.</h3>",
                                unsafe_allow_html=True
                            )


    # Google Safe Browsing API to check in Google's bad website database 
    with apiBrowsing:
        api_key = "AIzaSyDXWxfhC7ZUlwZ8Qhq6UfhIqp6BeiLumyk"
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
                        "POTENTIALLY_HARMFUL_APPLICATION",
                        ],

                "platformTypes": ["ANY_PLATFORM"],
                "threatEntryTypes": ["URL"],
                "threatEntries": [
                    {"url": url}
                    ]
                }
            }

            try:
                response = requests.post(f"{endpoint}?key={api_key}", json=payload)
                response.raise_for_status()
                data = response.json()
                return bool(data.get("matches"))
            except requests.RequestException as e:
                print("Error contacting Google Safe Browsing API:",e)
                return False

        with st.form(key="url_form_google"):
            st.subheader("🦾 Google Safe Browsing Method in use")
            
            url = st.text_input("Enter that fishy URL:", placeholder="https://example.com").strip()
            submit = st.form_submit_button("Scan URL")

            if submit:
                if not url:
                    st.error("🟥 No URL found. Please enter a URL.")
                elif not (url.startswith("http://") or url.startswith("https://")):
                    st.error("❌ Invalid URL. It must start with http:// or https://")
                else:
                    status = st.empty()
                    status.info("🔎 Scanning in progress...")
                    time.sleep(2)
                    status.empty()

                    st.markdown("## 📝 Scan Report")
                    result = check_url_with_google_safe_browsing(api_key, url)
                    if result:
                        st.error("🚨 The URL is potentially harmful or malicious!")
                    else:
                        st.success("✅ The URL is safe.")



