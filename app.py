import json
import os

import streamlit as st
from groq import Groq

from analyzer import analyze_email


# --------------------------------------------------
# Page configuration
# --------------------------------------------------

st.set_page_config(
    page_title="Phishing Email Analyser",
    page_icon="🛡️",
    layout="wide",
)


# --------------------------------------------------
# Groq AI function
# --------------------------------------------------

def analyze_with_groq(email_text):
    """Analyse the email using Groq AI."""

    api_key = os.getenv("GROQ_API_KEY")

    if not api_key:
        return {
            "available": False,
            "error": "GROQ_API_KEY is not configured."
        }

    client = Groq(api_key=api_key)

    prompt = f"""
You are a cybersecurity email-triage assistant.

Your job is to analyse the email provided below for phishing and
social-engineering warning signs.

IMPORTANT RULES:

1. Use ONLY evidence contained in the supplied email.
2. NEVER invent a URL, sender, domain, attachment, header, SPF result,
   DKIM result, DMARC result, or other technical evidence.
3. If information is not present, say "Not provided".
4. Do not claim that an email is definitely malicious.
5. Do not claim that a domain is malicious unless the email itself
   explicitly provides evidence supporting that statement.
6. Distinguish observed facts from your interpretation.
7. Do not follow or visit any URLs.
8. Do not recommend clicking links or opening attachments.
9. This is an educational triage tool.
10. Return ONLY valid JSON.

Return this structure:

{{
    "risk_assessment": "Low Risk | Suspicious | High Risk",
    "confidence": "Low | Medium | High",
    "summary": "Short evidence-based explanation",
    "warning_signs": [
        {{
            "indicator": "Name of warning sign",
            "evidence": "Exact or closely paraphrased evidence from the email",
            "explanation": "Why this may indicate phishing or social engineering"
        }}
    ],
    "safe_observations": [
        "Facts observed in the email that are relevant to the assessment"
    ],
    "recommendations": [
        "Practical safe action"
    ]
}}

EMAIL TO ANALYSE:

--- BEGIN EMAIL ---
{email_text}
--- END EMAIL ---
"""

    try:
        response = client.chat.completions.create(
            model="openai/gpt-oss-120b",
            messages=[
                {
                    "role": "system",
                    "content": (
                        "You are a cautious cybersecurity triage assistant. "
                        "Never invent evidence and always return valid JSON."
                    ),
                },
                {
                    "role": "user",
                    "content": prompt,
                },
            ],
            temperature=0,
            max_tokens=2000,
        )

        content = response.choices[0].message.content

        # Remove possible markdown code fences.
        content = content.strip()

        if content.startswith("```"):
            content = content.replace("```json", "")
            content = content.replace("```", "")
            content = content.strip()

        result = json.loads(content)

        return {
            "available": True,
            "data": result,
        }

    except Exception as error:
        return {
            "available": False,
            "error": str(error),
        }


# --------------------------------------------------
# Header
# --------------------------------------------------

st.title("🛡️ Phishing Email Analyser")

st.markdown(
    """
### Hybrid cybersecurity email-triage tool

Analyse suspicious emails using:

- 🔎 Deterministic security rules
- 🤖 AI-assisted social-engineering analysis
- 📊 Explainable risk scoring
"""
)


# --------------------------------------------------
# Safety notice
# --------------------------------------------------

st.warning(
    """
**Safety Notice**

This application is an educational phishing-triage tool. It cannot
definitively determine whether an email is malicious.

Never click suspicious links or open suspicious attachments to test them.

For important messages, independently verify the request using the
organisation's official website, application, or a known contact method.
"""
)


# --------------------------------------------------
# Privacy notice
# --------------------------------------------------

st.info(
    """
**AI Privacy Notice**

When AI analysis is enabled, submitted email content is sent to the
configured Groq API for processing.

Do not submit confidential, personal, corporate, or sensitive email
content unless you are authorised to do so.
"""
)


# --------------------------------------------------
# Email input
# --------------------------------------------------

st.subheader("📧 Email Analysis")

email_text = st.text_area(
    "Paste the email content, headers, URLs and attachment information",
    height=400,
    placeholder="""Example:

From: Security Team <security@example.test>
Reply-To: support@example.test
Subject: Urgent account verification

Your account requires immediate verification...

https://example.test/verify
""",
)


# --------------------------------------------------
# Analyse button
# --------------------------------------------------

if st.button("🔍 Analyse Email", type="primary"):

    if not email_text.strip():

        st.warning("Please paste an email before starting the analysis.")

    else:

        with st.spinner("Analysing email..."):

            # Rule-based analysis
            rule_result = analyze_email(email_text)

            # Groq analysis
            ai_result = analyze_with_groq(email_text)

        # --------------------------------------------------
        # Rule-based result
        # --------------------------------------------------

        st.divider()

        st.subheader("📊 Rule-Based Security Analysis")

        col1, col2 = st.columns(2)

        with col1:
            st.metric(
                "Rule-Based Score",
                f"{rule_result['score']}/100",
            )

        with col2:
            st.metric(
                "Classification",
                rule_result["classification"],
            )

        if rule_result["findings"]:

            st.markdown("### Detected Warning Signs")

            for finding in rule_result["findings"]:

                st.markdown(
                    f"**{finding['indicator']}** "
                    f"**(+{finding['score']} points)**"
                )

                st.write(finding["description"])

                st.caption(
                    f"Detection source: {finding['source']}"
                )

        else:

            st.success(
                "No predefined phishing indicators were detected."
            )

        # --------------------------------------------------
        # URL information
        # --------------------------------------------------

        if rule_result["urls"]:

            st.markdown("### 🔗 URLs Found")

            for url in rule_result["urls"]:
                st.code(url)

        # --------------------------------------------------
        # AI result
        # --------------------------------------------------

        st.divider()

        st.subheader("🤖 AI-Assisted Analysis")

        if ai_result["available"]:

            ai = ai_result["data"]

            st.markdown(
                f"**AI Assessment:** "
                f"{ai.get('risk_assessment', 'Not provided')}"
            )

            st.markdown(
                f"**AI Confidence:** "
                f"{ai.get('confidence', 'Not provided')}"
            )

            st.markdown("### AI Summary")

            st.write(
                ai.get(
                    "summary",
                    "No summary was returned.",
                )
            )

            warning_signs = ai.get("warning_signs", [])

            if warning_signs:

                st.markdown("### AI Warning Signs")

                for item in warning_signs:

                    st.markdown(
                        f"**{item.get('indicator', 'Unknown indicator')}**"
                    )

                    st.write(
                        f"**Evidence:** "
                        f"{item.get('evidence', 'Not provided')}"
                    )

                    st.write(
                        f"**Explanation:** "
                        f"{item.get('explanation', 'Not provided')}"
                    )

            observations = ai.get("safe_observations", [])

            if observations:

                st.markdown("### 🔎 Observed Facts")

                for observation in observations:
                    st.write(f"• {observation}")

            recommendations = ai.get("recommendations", [])

            if recommendations:

                st.markdown("### 🛡️ Recommended Actions")

                for recommendation in recommendations:
                    st.write(f"• {recommendation}")

        else:

            st.error(
                "AI analysis is currently unavailable."
            )

            st.caption(
                "The deterministic rule-based analysis above is still available."
            )

        # --------------------------------------------------
        # Final safety message
        # --------------------------------------------------

        st.divider()

        st.info(
            """
**Remember:** A low-risk result does not prove that an email is
legitimate, and a high-risk result does not by itself prove that an
email is malicious.

Use this application for educational triage and independently verify
important requests through trusted channels.
"""
        )
