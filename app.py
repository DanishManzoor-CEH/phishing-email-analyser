import io
import json
import os
from datetime import datetime

import streamlit as st
from groq import Groq
from reportlab.lib import colors
from reportlab.lib.enums import TA_CENTER
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import mm
from reportlab.platypus import (
    SimpleDocTemplate,
    Paragraph,
    Spacer,
    Table,
    TableStyle,
    PageBreak,
)

from analyzer import analyze_email


# ============================================================
# PAGE CONFIG
# ============================================================

st.set_page_config(
    page_title="Phishing Email Analyser",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="collapsed",
)


# ============================================================
# CUSTOM UI
# ============================================================

st.markdown(
    """
    <style>
        .main {
            padding-top: 1.5rem;
        }

        .app-header {
            text-align: center;
            padding: 10px 0 20px 0;
        }

        .app-title {
            font-size: 2.2rem;
            font-weight: 700;
            margin-bottom: 5px;
        }

        .app-subtitle {
            color: #6b7280;
            font-size: 1rem;
        }

        .result-card {
            padding: 18px;
            border-radius: 12px;
            border: 1px solid #e5e7eb;
            background: #ffffff;
            margin-bottom: 12px;
        }

        .metric-label {
            font-size: 0.82rem;
            color: #6b7280;
            margin-bottom: 4px;
        }

        .metric-value {
            font-size: 1.55rem;
            font-weight: 700;
        }

        .warning-item {
            padding: 10px 12px;
            border-left: 3px solid #ef4444;
            background: #f9fafb;
            border-radius: 5px;
            margin-bottom: 7px;
        }

        .safe-item {
            padding: 9px 12px;
            border-left: 3px solid #10b981;
            background: #f9fafb;
            border-radius: 5px;
            margin-bottom: 7px;
        }

        .footer-note {
            text-align: center;
            color: #6b7280;
            font-size: 0.8rem;
            margin-top: 30px;
        }

        div.stButton > button {
            font-weight: 600;
        }
    </style>
    """,
    unsafe_allow_html=True,
)


# ============================================================
# HEADER
# ============================================================

st.markdown(
    """
    <div class="app-header">
        <div class="app-title">🛡️ Phishing Email Analyser</div>
        <div class="app-subtitle">
            Rule-based detection + AI-assisted phishing analysis
        </div>
    </div>
    """,
    unsafe_allow_html=True,
)

st.info(
    "Educational security-triage tool. Do not click suspicious links or open "
    "unexpected attachments. Always verify requests through a trusted channel."
)


# ============================================================
# GROQ ANALYSIS
# ============================================================

def analyze_with_groq(email_text):
    """Analyze email with Groq while restricting the model to supplied evidence."""

    try:
        api_key = st.secrets.get("GROQ_API_KEY")
    except Exception:
        api_key = None

    if not api_key:
        api_key = os.getenv("GROQ_API_KEY")

    if not api_key:
        return {
            "available": False,
            "error": "GROQ_API_KEY is not configured."
        }

    client = Groq(api_key=api_key)

    system_prompt = """
You are a cybersecurity email-triage assistant.

Analyze ONLY the email content provided by the user.

Strict rules:
1. Use only evidence present in the supplied email.
2. Never invent URLs, domains, senders, attachments, headers,
   SPF, DKIM, or DMARC results.
3. If information is missing, say "Not provided".
4. Never state that an email is definitely malicious.
5. Do not claim a domain is malicious unless that fact is explicitly
   present in the submitted text.
6. Clearly distinguish observed facts from interpretation.
7. Do not visit, follow, or investigate URLs.
8. Do not recommend clicking links or opening attachments.
9. Provide concise security-triage guidance.
10. Return ONLY valid JSON.

Return exactly this structure:

{
  "risk_assessment": "Low Risk | Suspicious | High Risk",
  "confidence": "Low | Medium | High",
  "summary": "Short evidence-based summary",
  "warning_signs": [
    {
      "indicator": "Short warning sign",
      "evidence": "Evidence from the email",
      "explanation": "Short explanation"
    }
  ],
  "safe_observations": [
    "Observed fact"
  ],
  "recommendations": [
    "Safe recommended action"
  ]
}
"""

    user_prompt = f"""
Analyze this email:

--- BEGIN EMAIL ---
{email_text}
--- END EMAIL ---
"""

    try:
        response = client.chat.completions.create(
            model="openai/gpt-oss-120b",
            messages=[
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_prompt},
            ],
            temperature=0,
            max_tokens=2000,
        )

        content = response.choices[0].message.content.strip()

        if content.startswith("```"):
            content = content.replace("```json", "")
            content = content.replace("```", "")
            content = content.strip()

        result = json.loads(content)

        return {
            "available": True,
            "data": result
        }

    except Exception as exc:
        return {
            "available": False,
            "error": str(exc)
        }


# ============================================================
# PDF REPORT
# ============================================================

def create_pdf_report(email_text, rule_result, ai_result):
    """Create a professional PDF analysis report in memory."""

    buffer = io.BytesIO()

    document = SimpleDocTemplate(
        buffer,
        pagesize=A4,
        rightMargin=18 * mm,
        leftMargin=18 * mm,
        topMargin=18 * mm,
        bottomMargin=18 * mm,
    )

    styles = getSampleStyleSheet()

    title_style = ParagraphStyle(
        "ReportTitle",
        parent=styles["Title"],
        alignment=TA_CENTER,
        fontSize=20,
        spaceAfter=8,
    )

    subtitle_style = ParagraphStyle(
        "Subtitle",
        parent=styles["Normal"],
        alignment=TA_CENTER,
        fontSize=9,
        textColor=colors.grey,
        spaceAfter=18,
    )

    heading_style = ParagraphStyle(
        "Heading",
        parent=styles["Heading2"],
        fontSize=13,
        spaceBefore=12,
        spaceAfter=7,
    )

    body_style = ParagraphStyle(
        "Body",
        parent=styles["BodyText"],
        fontSize=9.5,
        leading=14,
        spaceAfter=5,
    )

    small_style = ParagraphStyle(
        "Small",
        parent=styles["BodyText"],
        fontSize=8,
        leading=11,
        textColor=colors.grey,
    )

    story = []

    # Header
    story.append(Paragraph("Phishing Email Analysis Report", title_style))
    story.append(
        Paragraph(
            "Generated by Phishing Email Analyser",
            subtitle_style,
        )
    )

    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    # Summary table
    score = rule_result.get("score", 0)
    classification = rule_result.get("classification", "Unknown")

    summary_data = [
        ["Risk Score", f"{score}/100"],
        ["Classification", classification],
        ["Analysis Time", timestamp],
    ]

    summary_table = Table(
        summary_data,
        colWidths=[55 * mm, 115 * mm],
    )

    summary_table.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (0, -1), colors.HexColor("#f3f4f6")),
                ("BOX", (0, 0), (-1, -1), 0.5, colors.HexColor("#d1d5db")),
                ("INNERGRID", (0, 0), (-1, -1), 0.25, colors.HexColor("#e5e7eb")),
                ("FONTNAME", (0, 0), (-1, -1), "Helvetica"),
                ("FONTNAME", (0, 0), (0, -1), "Helvetica-Bold"),
                ("FONTSIZE", (0, 0), (-1, -1), 9),
                ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
                ("TOPPADDING", (0, 0), (-1, -1), 7),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 7),
            ]
        )
    )

    story.append(summary_table)

    # AI summary
    if ai_result.get("available"):
        ai_data = ai_result["data"]

        story.append(Paragraph("AI-Assisted Assessment", heading_style))

        story.append(
            Paragraph(
                f"<b>Assessment:</b> {ai_data.get('risk_assessment', 'Not provided')}",
                body_style,
            )
        )

        story.append(
            Paragraph(
                f"<b>Confidence:</b> {ai_data.get('confidence', 'Not provided')}",
                body_style,
            )
        )

        story.append(
            Paragraph(
                f"<b>Summary:</b> {ai_data.get('summary', 'Not provided')}",
                body_style,
            )
        )

    # Rule findings
    story.append(Paragraph("Detected Warning Signs", heading_style))

    findings = rule_result.get("findings", [])

    if findings:
        for finding in findings:
            indicator = finding.get("indicator", "Unknown")
            explanation = finding.get("explanation", "")

            story.append(
                Paragraph(
                    f"<b>{indicator}</b> — {explanation}",
                    body_style,
                )
            )
    else:
        story.append(
            Paragraph(
                "No rule-based warning signs were detected.",
                body_style,
            )
        )

    # AI warning signs
    if ai_result.get("available"):
        ai_warning_signs = ai_result["data"].get("warning_signs", [])

        if ai_warning_signs:
            story.append(
                Paragraph(
                    "AI-Identified Warning Signs",
                    heading_style,
                )
            )

            for item in ai_warning_signs:
                indicator = item.get("indicator", "Unknown")
                evidence = item.get("evidence", "Not provided")

                story.append(
                    Paragraph(
                        f"<b>{indicator}</b><br/>Evidence: {evidence}",
                        body_style,
                    )
                )

    # Recommendations
    story.append(Paragraph("Recommended Actions", heading_style))

    recommendations = []

    if ai_result.get("available"):
        recommendations = ai_result["data"].get(
            "recommendations",
            []
        )

    if not recommendations:
        recommendations = [
            "Do not click suspicious links.",
            "Do not provide passwords or MFA codes by email.",
            "Verify unexpected requests using a trusted channel.",
        ]

    for recommendation in recommendations:
        story.append(
            Paragraph(
                f"• {recommendation}",
                body_style,
            )
        )

    # Email
    story.append(
        Paragraph(
            "Submitted Email",
            heading_style,
        )
    )

    safe_email = (
        email_text
        .replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
        .replace("\n", "<br/>")
    )

    story.append(
        Paragraph(
            safe_email,
            small_style,
        )
    )

    story.append(Spacer(1, 12))

    story.append(
        Paragraph(
            "Disclaimer: This report is for educational security triage. "
            "A risk score does not prove that an email is malicious or legitimate. "
            "Verify important requests independently.",
            small_style,
        )
    )

    document.build(story)

    buffer.seek(0)

    return buffer.getvalue()


# ============================================================
# EMAIL INPUT
# ============================================================

st.markdown("### 📩 Analyse an Email")

email_text = st.text_area(
    "Paste the email content below",
    height=240,
    placeholder=(
        "Paste the suspicious email, including headers if available...\n\n"
        "Example:\n"
        "From: security@example.invalid\n"
        "Subject: Urgent account verification\n"
        "..."
    ),
    label_visibility="collapsed",
)

analyse_clicked = st.button(
    "🔍 Analyse Email",
    type="primary",
    width="stretch",
)


# ============================================================
# ANALYSIS
# ============================================================

if analyse_clicked:

    if not email_text.strip():
        st.warning("Please paste an email before starting the analysis.")
        st.stop()

    with st.spinner("Analysing email..."):
        rule_result = analyze_email(email_text)
        ai_result = analyze_with_groq(email_text)

    # Save results in session state
    st.session_state["rule_result"] = rule_result
    st.session_state["ai_result"] = ai_result
    st.session_state["email_text"] = email_text


# ============================================================
# DISPLAY SAVED RESULTS
# ============================================================

if "rule_result" in st.session_state:

    rule_result = st.session_state["rule_result"]
    ai_result = st.session_state["ai_result"]
    email_text = st.session_state["email_text"]

    st.markdown("---")
    st.markdown("### 📊 Analysis Result")

    score = rule_result.get("score", 0)
    classification = rule_result.get(
        "classification",
        "Unknown"
    )

    # Compact metrics
    col1, col2, col3 = st.columns(3)

    with col1:
        st.metric(
            "Risk Score",
            f"{score}/100"
        )

    with col2:
        st.metric(
            "Classification",
            classification
        )

    with col3:
        if ai_result.get("available"):
            confidence = ai_result["data"].get(
                "confidence",
                "Not provided"
            )
        else:
            confidence = "Unavailable"

        st.metric(
            "AI Confidence",
            confidence
        )

    # Main summary
    st.markdown("#### 🧠 Quick Assessment")

    if ai_result.get("available"):

        ai_data = ai_result["data"]

        summary = ai_data.get(
            "summary",
            "No AI summary available."
        )

        st.info(summary)

    else:
        st.info(
            "AI analysis is unavailable. "
            "The rule-based analysis is still available."
        )

    # Warning signs
    findings = rule_result.get("findings", [])

    if findings:

        st.markdown("#### ⚠️ Key Warning Signs")

        # Show only short indicator names on dashboard
        for finding in findings[:6]:

            indicator = finding.get(
                "indicator",
                "Unknown warning"
            )

            st.markdown(
                f"""
                <div class="warning-item">
                    ⚠️ <b>{indicator}</b>
                </div>
                """,
                unsafe_allow_html=True,
            )

    # AI warning signs
    if ai_result.get("available"):

        ai_warning_signs = ai_result["data"].get(
            "warning_signs",
            []
        )

        if ai_warning_signs:

            with st.expander(
                "View AI Warning Sign Details"
            ):

                for item in ai_warning_signs[:6]:

                    indicator = item.get(
                        "indicator",
                        "Warning sign"
                    )

                    evidence = item.get(
                        "evidence",
                        "Not provided"
                    )

                    explanation = item.get(
                        "explanation",
                        "Not provided"
                    )

                    st.markdown(
                        f"**{indicator}**"
                    )

                    st.caption(
                        f"Evidence: {evidence}"
                    )

                    st.write(explanation)

    # Recommendations
    if ai_result.get("available"):

        recommendations = ai_result["data"].get(
            "recommendations",
            []
        )

        if recommendations:

            st.markdown("#### ✅ Recommended Action")

            # Keep dashboard concise
            st.success(
                recommendations[0]
            )

            if len(recommendations) > 1:

                with st.expander("More recommendations"):

                    for recommendation in recommendations[1:]:
                        st.write(f"• {recommendation}")

    # Technical details
    with st.expander("Technical Details"):

        st.write(
            f"**Rule-based score:** {score}/100"
        )

        st.write(
            f"**Rule classification:** {classification}"
        )

        urls = rule_result.get("urls", [])

        if urls:
            st.write("**Detected URLs:**")

            for url in urls:
                st.code(url)

        else:
            st.write("**Detected URLs:** None")

        if findings:

            st.write("**Rule findings:**")

            for finding in findings:

                indicator = finding.get(
                    "indicator",
                    "Unknown"
                )

                explanation = finding.get(
                    "explanation",
                    ""
                )

                st.write(
                    f"• {indicator}: {explanation}"
                )

    # ========================================================
    # PDF REPORT
    # ========================================================

    st.markdown("---")

    st.markdown("### 📄 Analysis Report")

    st.caption(
        "Generate a concise PDF report containing the analysis results."
    )

    pdf_data = create_pdf_report(
        email_text,
        rule_result,
        ai_result,
    )

    st.download_button(
        label="📥 Generate & Download PDF Report",
        data=pdf_data,
        file_name="phishing_email_analysis_report.pdf",
        mime="application/pdf",
        width="stretch",
    )


# ============================================================
# FOOTER
# ============================================================

st.markdown(
    """
    <div class="footer-note">
        Phishing Email Analyser • Rule-Based Detection + AI-Assisted Analysis
        <br>
        For educational and defensive security analysis only.
    </div>
    """,
    unsafe_allow_html=True,
)
