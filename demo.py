import streamlit as st

st.title("🔍 Intelligent Checker")

tab1, tab2, tab3 = st.tabs(["🔗 Check URL", "📧 Check Email", "🌐 Check Domain"])

with tab1:
    url = st.text_input("Enter a URL:")
    if url:
        st.write(f"Processing URL: `{url}`")
        # Your URL analysis logic here

with tab2:
    email = st.text_input("Enter an Email address:")
    if email:
        st.write(f"Processing Email: `{email}`")
        # Your Email analysis logic here

with tab3:
    domain = st.text_input("Enter a Domain:")
    if domain:
        st.write(f"Processing Domain: `{domain}`")
        # Your Domain analysis logic here
