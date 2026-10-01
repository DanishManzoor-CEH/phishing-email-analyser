import streamlit as st
from analyzer import analyze_email


st.set_page_config(
    page_title="Phishing Email Analyser",
    page_icon="🛡️",
    layout="wide",
)

st.title("🛡️ Phishing Email Analyser")

st.caption(
    "Educational phishing-email triage tool — not a definitive malware detector."
)

email = st.text_area(
    "Paste an email",
    height=350,
    placeholder="Paste suspicious email content here...",
)

if st.button("🔍 Analyse Email", type="primary"):

    if not email.strip():
        st.warning("Please paste an email first.")

    else:
        result = analyze_email(email)

        st.subheader("Risk Assessment")

        col1, col2 = st.columns(2)

        with col1:
            st.metric("Risk Score", f"{result['score']}/100")

        with col2:
            st.metric("Classification", result["classification"])

        st.subheader("Detected Warning Signs")

        if result["findings"]:

            for finding in result["findings"]:
                st.write(
                    f"**{finding['indicator']}** "
                    f"(+{finding['score']} points)"
                )

                st.write(finding["description"])
                st.caption(f"Source: {finding['source']}")

        else:
            st.success("No predefined warning signs were detected.")

        if result["urls"]:
            st.subheader("URLs Detected")

            for url in result["urls"]:
                st.code(url)

        st.info(
            "A low score does not prove that an email is legitimate. "
            "Always independently verify important requests."
        )
