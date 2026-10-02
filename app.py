import json
import os
from datetime import datetime
from html import escape

import streamlit as st
from groq import Groq

from analyzer import analyze_email


# ============================================================
# PAGE CONFIGURATION
# ============================================================

st.set_page_config(
    page_title="Phishing Email Analyser",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="collapsed",
)


# ============================================================
# CUSTOM CSS
# ============================================================

st.markdown(
    """
    <style>

    /* --------------------------------------------------------
       GLOBAL
    -------------------------------------------------------- */

    .stApp {
        background: #0b0f14;
        color: #f5f7fa;
    }

    .main .block-container {
        max-width: 1200px;
        padding-top: 2rem;
        padding-bottom: 3rem;
    }

    h1, h2, h3, h4, h5, h6 {
        color: #f5f7fa !important;
    }

    p, li {
        color: #d1d5db;
    }


    /* --------------------------------------------------------
       HEADER
    -------------------------------------------------------- */

    .app-header {
        background: linear-gradient(
            135deg,
            #111827 0%,
            #172033 100%
        );
        border: 1px solid #263244;
        border-radius: 14px;
        padding: 24px 28px;
        margin-bottom: 22px;
    }

    .app-title {
        font-size: 32px;
        font-weight: 800;
        color: #ffffff !important;
        margin-bottom: 6px;
    }

    .app-subtitle {
        font-size: 15px;
        color: #aeb7c4 !important;
        margin-bottom: 0;
    }


    /* --------------------------------------------------------
       EMAIL INPUT
       -------------------------------------------------------- */

    .input-label {
        font-size: 18px;
        font-weight: 700;
        color: #ffffff !important;
        margin-bottom: 8px;
    }

    textarea {
        background-color: #111827 !important;
        color: #f9fafb !important;
        border: 1px solid #374151 !important;
        border-radius: 10px !important;
    }

    textarea::placeholder {
        color: #9ca3af !important;
    }


    /* --------------------------------------------------------
       BUTTON
       -------------------------------------------------------- */

    .stButton > button {
        width: 100%;
        border-radius: 9px;
        border: 1px solid #2563eb;
        background: #2563eb;
        color: white;
        font-weight: 700;
        padding: 0.65rem 1rem;
    }

    .stButton > button:hover {
        background: #1d4ed8;
        border-color: #1d4ed8;
        color: white;
    }


    /* --------------------------------------------------------
       RESULT SECTION
       -------------------------------------------------------- */

    .section-title {
        font-size: 24px;
        font-weight: 800;
        color: #ffffff !important;
        margin-top: 25px;
        margin-bottom: 15px;
    }


    /* --------------------------------------------------------
       METRIC CARDS
       -------------------------------------------------------- */

    .metric-card {
        background: #111827;
        border: 1px solid #263244;
        border-radius: 12px;
        padding: 18px;
        text-align: center;
        min-height: 110px;
    }

    .metric-label {
        font-size: 13px;
        color: #9ca3af !important;
        margin-bottom: 8px;
    }

    .metric-value {
        font-size: 26px;
        font-weight: 800;
        color: #ffffff !important;
    }


    /* --------------------------------------------------------
       AI SUMMARY
       -------------------------------------------------------- */

    .summary-card {
        background: #142338;
        border: 1px solid #29415f;
        border-radius: 10px;
        padding: 16px 18px;
        margin-top: 14px;
        margin-bottom: 20px;
    }

    .summary-title {
        font-size: 15px;
        font-weight: 700;
        color: #93c5fd !important;
        margin-bottom: 7px;
    }

    .summary-text {
        font-size: 15px;
        line-height: 1.6;
        color: #e5e7eb !important;
    }


    /* --------------------------------------------------------
       KEY WARNING SIGNS
       IMPORTANT: WHITE CARD + DARK TEXT
       -------------------------------------------------------- */

    .warning-card {
        background: #ffffff !important;
        border: 1px solid #d1d5db !important;
        border-left: 5px solid #ff4b4b !important;
        border-radius: 9px;
        padding: 15px 18px;
        margin: 10px 0;
        box-shadow: 0 2px 6px rgba(0, 0, 0, 0.15);
    }

    .warning-card,
    .warning-card div,
    .warning-card span,
    .warning-card p,
    .warning-card strong {
        color: #1f2937 !important;
    }

    .warning-card-title {
        color: #111827 !important;
        font-size: 15px;
        font-weight: 700;
        line-height: 1.5;
    }


    /* --------------------------------------------------------
       AI WARNING DETAILS
       -------------------------------------------------------- */

    .detail-card {
        background: #111827;
        border: 1px solid #303846;
        border-radius: 9px;
        padding: 15px 18px;
        margin: 10px 0;
    }

    .detail-title {
        color: #ffffff !important;
        font-size: 16px;
        font-weight: 700;
        margin-bottom: 10px;
    }

    .detail-label {
        color: #9ca3af !important;
        font-size: 13px;
        font-weight: 700;
    }

    .detail-text {
        color: #d1d5db !important;
        font-size: 14px;
        line-height: 1.55;
        margin-bottom: 10px;
    }


    /* --------------------------------------------------------
       RECOMMENDATION CARDS
       -------------------------------------------------------- */

    .recommendation-card {
        background: #101a14;
        border: 1px solid #244832;
        border-left: 4px solid #22c55e;
        border-radius: 8px;
        padding: 12px 16px;
        margin: 8px 0;
    }

    .recommendation-card p {
        color: #d1fae5 !important;
        margin: 0;
        line-height: 1.5;
    }


    /* --------------------------------------------------------
       TECHNICAL DETAILS
       -------------------------------------------------------- */

    .technical-box {
        background: #0f141b;
        border: 1px solid #29313d;
        border-radius: 9px;
        padding: 15px;
        margin-top: 10px;
    }

    .technical-box p,
    .technical-box li {
        color: #cbd5e1 !important;
    }


    /* --------------------------------------------------------
       DISCLAIMER
       -------------------------------------------------------- */

    .disclaimer {
        background: #1c1710;
        border: 1px solid #4a3920;
        border-radius: 8px;
        padding: 13px 16px;
        margin-top: 25px;
    }

    .disclaimer p {
        color: #d6c5a5 !important;
        font-size: 13px;
        margin: 0;
        line-height: 1.5;
    }


    /* --------------------------------------------------------
       FOOTER
       -------------------------------------------------------- */

    .footer {
        text-align: center;
        color: #6b7280 !important;
        font-size: 12px;
        margin-top: 35px;
        padding-top: 15px;
        border-top: 1px solid #1f2937;
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
            Hybrid rule-based and AI-assisted phishing email triage
        </div>
    </div>
    """,
    unsafe_allow_html=True,
)


# ============================================================
# GROQ API KEY
# ============================================================

def get_groq_api_key():
    """
    Get the Groq API key from Streamlit Cloud secrets first,
    then fall back to an environment variable.
    """

    api_key = None

    try:
        api_key = st.secrets.get("GROQ_API_KEY")
    except Exception:
        api_key = None

    if not api_key:
        api_key = os.getenv("GROQ_API_KEY")

    return api_key


# ============================================================
# GROQ AI ANALYSIS
# ============================================================

def analyze_with_groq(email_text):
    """
    Send the supplied email to Groq for contextual analysis.

    The AI is instructed to use only evidence contained in the
    supplied email and never invent missing information.
    """

    api_key = get_groq_api_key()

    if not api_key:
        return {
            "error": (
                "GROQ_API_KEY is not configured. "
                "Please add it to Streamlit Cloud Secrets."
            )
        }

    client = Groq(api_key=api_key)

    system_prompt = """
You are an email security analysis assistant.

Your task is to analyze a suspicious email for phishing and
social-engineering indicators.

IMPORTANT RULES:

1. Use ONLY evidence contained in the supplied email.
2. Never invent a sender, domain, URL, attachment, header,
   SPF result, DKIM result, or DMARC result.
3. If information is missing, say "Not provided".
4. Never claim that an email is definitely malicious.
5. Do not claim that a domain is malicious unless the email
   itself provides evidence supporting that statement.
6. Do not visit, follow, or test URLs.
7. Do not recommend clicking links or opening attachments.
8. Distinguish observed facts from your interpretation.
9. The rule-based analyzer is the primary measurable scoring
   authority. Your role is contextual/social-engineering analysis.
10. Keep the result concise and useful for a cybersecurity analyst.
11. Return valid JSON only.
12. Do not include Markdown fences around the JSON.

Return exactly this structure:

{
  "risk_assessment": "Low Risk | Suspicious | High Risk",
  "confidence": "Low | Medium | High",
  "summary": "Short evidence-based explanation",
  "warning_signs": [
    {
      "indicator": "Name of warning sign",
      "evidence": "Exact or closely paraphrased evidence from the email",
      "explanation": "Why this may indicate phishing or social engineering"
    }
  ],
  "safe_observations": [
    "Facts directly observed in the email"
  ],
  "recommendations": [
    "Practical safe action"
  ]
}
"""

    user_prompt = f"""
Analyze the following email.

EMAIL:
--------------------
{email_text}
--------------------
"""

    try:
        response = client.chat.completions.create(
            model="openai/gpt-oss-120b",
            messages=[
                {
                    "role": "system",
                    "content": system_prompt,
                },
                {
                    "role": "user",
                    "content": user_prompt,
                },
            ],
            temperature=0,
            max_tokens=2000,
        )

        content = response.choices[0].message.content.strip()

        # Remove accidental Markdown JSON fences
        if content.startswith("```json"):
            content = content[7:]

        if content.startswith("```"):
            content = content[3:]

        if content.endswith("```"):
            content = content[:-3]

        content = content.strip()

        return json.loads(content)

    except json.JSONDecodeError:
        return {
            "error": "The AI returned an invalid JSON response."
        }

    except Exception as e:
        return {
            "error": f"AI analysis failed: {str(e)}"
        }


# ============================================================
# PDF REPORT GENERATOR
# ============================================================

def generate_pdf_report(
    email_text,
    rule_result,
    ai_result,
):
    """
    Generate a PDF report using ReportLab.
    """

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

    from io import BytesIO

    buffer = BytesIO()

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
        fontSize=20,
        leading=24,
        alignment=TA_CENTER,
        spaceAfter=12,
    )

    heading_style = ParagraphStyle(
        "Heading",
        parent=styles["Heading2"],
        fontSize=13,
        leading=17,
        spaceBefore=10,
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

    # --------------------------------------------------------
    # TITLE
    # --------------------------------------------------------

    story.append(
        Paragraph(
            "Phishing Email Analysis Report",
            title_style,
        )
    )

    story.append(
        Paragraph(
            f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
            small_style,
        )
    )

    story.append(Spacer(1, 10))

    # --------------------------------------------------------
    # SUMMARY TABLE
    # --------------------------------------------------------

    score = rule_result.get("score", 0)
    classification = rule_result.get(
        "classification",
        "Unknown",
    )

    ai_assessment = ai_result.get(
        "risk_assessment",
        "Not available",
    )

    ai_confidence = ai_result.get(
        "confidence",
        "Not available",
    )

    summary_data = [
        ["Rule-Based Risk Score", str(score) + "/100"],
        ["Rule-Based Classification", classification],
        ["AI Assessment", ai_assessment],
        ["AI Confidence", ai_confidence],
    ]

    summary_table = Table(
        summary_data,
        colWidths=[65 * mm, 95 * mm],
    )

    summary_table.setStyle(
        TableStyle(
            [
                (
                    "BACKGROUND",
                    (0, 0),
                    (0, -1),
                    colors.HexColor("#eeeeee"),
                ),
                (
                    "GRID",
                    (0, 0),
                    (-1, -1),
                    0.5,
                    colors.grey,
                ),
                (
                    "FONTNAME",
                    (0, 0),
                    (-1, -1),
                    "Helvetica",
                ),
                (
                    "FONTSIZE",
                    (0, 0),
                    (-1, -1),
                    9,
                ),
                (
                    "VALIGN",
                    (0, 0),
                    (-1, -1),
                    "MIDDLE",
                ),
                (
                    "PADDING",
                    (0, 0),
                    (-1, -1),
                    7,
                ),
            ]
        )
    )

    story.append(summary_table)

    # --------------------------------------------------------
    # AI SUMMARY
    # --------------------------------------------------------

    story.append(
        Paragraph(
            "AI-Assisted Summary",
            heading_style,
        )
    )

    ai_summary = ai_result.get(
        "summary",
        "No AI summary available.",
    )

    story.append(
        Paragraph(
            escape(str(ai_summary)),
            body_style,
        )
    )

    # --------------------------------------------------------
    # RULE-BASED FINDINGS
    # --------------------------------------------------------

    story.append(
        Paragraph(
            "Rule-Based Warning Signs",
            heading_style,
        )
    )

    findings = rule_result.get("findings", [])

    if findings:
        for finding in findings:
            if isinstance(finding, dict):
                indicator = finding.get(
                    "indicator",
                    "Warning sign",
                )

                evidence = finding.get(
                    "evidence",
                    "",
                )

                points = finding.get(
                    "score",
                    "",
                )

                text = (
                    f"<b>{escape(str(indicator))}</b>"
                    f" — {escape(str(evidence))}"
                )

                if points != "":
                    text += f" (+{escape(str(points))})"

                story.append(
                    Paragraph(
                        text,
                        body_style,
                    )
                )

            else:
                story.append(
                    Paragraph(
                        escape(str(finding)),
                        body_style,
                    )
                )
    else:
        story.append(
            Paragraph(
                "No rule-based warning signs detected.",
                body_style,
            )
        )

    # --------------------------------------------------------
    # AI WARNING SIGNS
    # --------------------------------------------------------

    story.append(
        Paragraph(
            "AI Warning Signs",
            heading_style,
        )
    )

    warning_signs = ai_result.get(
        "warning_signs",
        [],
    )

    if warning_signs:
        for warning in warning_signs:

            if not isinstance(warning, dict):
                story.append(
                    Paragraph(
                        escape(str(warning)),
                        body_style,
                    )
                )
                continue

            indicator = warning.get(
                "indicator",
                "Warning sign",
            )

            evidence = warning.get(
                "evidence",
                "Not provided",
            )

            explanation = warning.get(
                "explanation",
                "Not provided",
            )

            story.append(
                Paragraph(
                    f"<b>{escape(str(indicator))}</b>",
                    body_style,
                )
            )

            story.append(
                Paragraph(
                    f"<b>Evidence:</b> {escape(str(evidence))}",
                    body_style,
                )
            )

            story.append(
                Paragraph(
                    f"<b>Explanation:</b> "
                    f"{escape(str(explanation))}",
                    body_style,
                )
            )

            story.append(Spacer(1, 3))

    else:
        story.append(
            Paragraph(
                "No additional AI warning signs were identified.",
                body_style,
            )
        )

    # --------------------------------------------------------
    # RECOMMENDATIONS
    # --------------------------------------------------------

    story.append(
        Paragraph(
            "Recommendations",
            heading_style,
        )
    )

    recommendations = ai_result.get(
        "recommendations",
        [],
    )

    if recommendations:
        for recommendation in recommendations:
            story.append(
                Paragraph(
                    "• " + escape(str(recommendation)),
                    body_style,
                )
            )
    else:
        story.append(
            Paragraph(
                "Do not click suspicious links or open unexpected "
                "attachments. Independently verify requests through "
                "a trusted channel.",
                body_style,
            )
        )

    # --------------------------------------------------------
    # SUBMITTED EMAIL
    # --------------------------------------------------------

    story.append(PageBreak())

    story.append(
        Paragraph(
            "Submitted Email",
            heading_style,
        )
    )

    email_lines = escape(email_text).replace(
        "\n",
        "<br/>",
    )

    story.append(
        Paragraph(
            email_lines,
            body_style,
        )
    )

    # --------------------------------------------------------
    # DISCLAIMER
    # --------------------------------------------------------

    story.append(
        Spacer(1, 15)
    )

    story.append(
        Paragraph(
            "<b>Disclaimer:</b> This tool provides educational "
            "security triage and does not establish that an email "
            "is definitively malicious. Verify suspicious requests "
            "independently before taking action.",
            small_style,
        )
    )

    document.build(story)

    buffer.seek(0)

    return buffer.getvalue()


# ============================================================
# SESSION STATE
# ============================================================

if "analysis_result" not in st.session_state:
    st.session_state.analysis_result = None

if "ai_result" not in st.session_state:
    st.session_state.ai_result = None

if "submitted_email" not in st.session_state:
    st.session_state.submitted_email = ""


# ============================================================
# EMAIL INPUT
# ============================================================

st.markdown(
    '<div class="input-label">📧 Suspicious Email</div>',
    unsafe_allow_html=True,
)

email_text = st.text_area(
    label="Email content",
    label_visibility="collapsed",
    height=260,
    placeholder=(
        "Paste the suspicious email here...\n\n"
        "Example:\n"
        "Subject: Urgent Account Verification\n"
        "Your account will be suspended within 24 hours..."
    ),
)


# ============================================================
# ANALYSE BUTTON
# ============================================================

if st.button(
    "🔍 Analyse Email",
    use_container_width=True,
):

    if not email_text.strip():
        st.warning("Please paste an email before starting the analysis.")

    else:

        with st.spinner("Analysing email..."):

            # Rule-based analysis
            rule_result = analyze_email(
                email_text.strip()
            )

            # AI analysis
            ai_result = analyze_with_groq(
                email_text.strip()
            )

            # Store results
            st.session_state.analysis_result = rule_result
            st.session_state.ai_result = ai_result
            st.session_state.submitted_email = email_text.strip()

        st.success("Email analysis completed.")


# ============================================================
# DISPLAY RESULTS
# ============================================================

if (
    st.session_state.analysis_result is not None
    and st.session_state.ai_result is not None
):

    rule_result = st.session_state.analysis_result
    ai_result = st.session_state.ai_result

    st.markdown(
        '<div class="section-title">📊 Analysis Overview</div>',
        unsafe_allow_html=True,
    )

    # --------------------------------------------------------
    # METRICS
    # --------------------------------------------------------

    score = rule_result.get(
        "score",
        0,
    )

    classification = rule_result.get(
        "classification",
        "Unknown",
    )

    ai_confidence = ai_result.get(
        "confidence",
        "Unavailable",
    )

    col1, col2, col3 = st.columns(3)

    with col1:
        st.markdown(
            f"""
            <div class="metric-card">
                <div class="metric-label">Risk Score</div>
                <div class="metric-value">{score}/100</div>
            </div>
            """,
            unsafe_allow_html=True,
        )

    with col2:
        st.markdown(
            f"""
            <div class="metric-card">
                <div class="metric-label">Classification</div>
                <div class="metric-value">{escape(str(classification))}</div>
            </div>
            """,
            unsafe_allow_html=True,
        )

    with col3:
        st.markdown(
            f"""
            <div class="metric-card">
                <div class="metric-label">AI Confidence</div>
                <div class="metric-value">{escape(str(ai_confidence))}</div>
            </div>
            """,
            unsafe_allow_html=True,
        )

    # --------------------------------------------------------
    # AI ERROR
    # --------------------------------------------------------

    if "error" in ai_result:

        st.error(
            ai_result["error"]
        )

    else:

        # ----------------------------------------------------
        # AI SUMMARY
        # ----------------------------------------------------

        st.markdown(
            '<div class="section-title">🤖 AI-Assisted Assessment</div>',
            unsafe_allow_html=True,
        )

        ai_summary = ai_result.get(
            "summary",
            "No summary available.",
        )

        st.markdown(
            f"""
            <div class="summary-card">
                <div class="summary-title">
                    AI Assessment: {escape(str(ai_result.get("risk_assessment", "Unavailable")))}
                </div>
                <div class="summary-text">
                    {escape(str(ai_summary))}
                </div>
            </div>
            """,
            unsafe_allow_html=True,
        )

        # ----------------------------------------------------
        # KEY WARNING SIGNS
        # ----------------------------------------------------

        st.markdown(
            '<div class="section-title">⚠️ Key Warning Signs</div>',
            unsafe_allow_html=True,
        )

        warning_signs = ai_result.get(
            "warning_signs",
            [],
        )

        if warning_signs:

            # Display only the first few warning signs
            # in the compact dashboard.
            for warning in warning_signs[:5]:

                if isinstance(warning, dict):
                    indicator = warning.get(
                        "indicator",
                        "Warning sign detected",
                    )
                else:
                    indicator = str(warning)

                # IMPORTANT:
                # This card explicitly uses DARK text on WHITE background.
                st.markdown(
                    f"""
                    <div class="warning-card">
                        <div class="warning-card-title">
                            ⚠️&nbsp;&nbsp;{escape(str(indicator))}
                        </div>
                    </div>
                    """,
                    unsafe_allow_html=True,
                )

        else:

            st.markdown(
                """
                <div class="warning-card"
                     style="border-left-color:#22c55e !important;">
                    <div class="warning-card-title">
                        ✓ No major AI warning signs identified.
                    </div>
                </div>
                """,
                unsafe_allow_html=True,
            )

        # ----------------------------------------------------
        # AI WARNING DETAILS
        # ----------------------------------------------------

        with st.expander(
            "🔎 View AI Warning Sign Details",
            expanded=False,
        ):

            if warning_signs:

                for warning in warning_signs:

                    if not isinstance(warning, dict):
                        continue

                    indicator = warning.get(
                        "indicator",
                        "Warning sign",
                    )

                    evidence = warning.get(
                        "evidence",
                        "Not provided",
                    )

                    explanation = warning.get(
                        "explanation",
                        "Not provided",
                    )

                    st.markdown(
                        f"""
                        <div class="detail-card">

                            <div class="detail-title">
                                {escape(str(indicator))}
                            </div>

                            <div class="detail-label">
                                Evidence
                            </div>

                            <div class="detail-text">
                                {escape(str(evidence))}
                            </div>

                            <div class="detail-label">
                                Why It Matters
                            </div>

                            <div class="detail-text">
                                {escape(str(explanation))}
                            </div>

                        </div>
                        """,
                        unsafe_allow_html=True,
                    )

            else:

                st.info(
                    "No additional AI warning details were identified."
                )

        # ----------------------------------------------------
        # RECOMMENDATIONS
        # ----------------------------------------------------

        st.markdown(
            '<div class="section-title">🛡️ Recommended Actions</div>',
            unsafe_allow_html=True,
        )

        recommendations = ai_result.get(
            "recommendations",
            [],
        )

        if recommendations:

            for recommendation in recommendations:

                st.markdown(
                    f"""
                    <div class="recommendation-card">
                        <p>✓ {escape(str(recommendation))}</p>
                    </div>
                    """,
                    unsafe_allow_html=True,
                )

        else:

            st.markdown(
                """
                <div class="recommendation-card">
                    <p>
                        ✓ Do not click suspicious links or open
                        unexpected attachments. Verify requests
                        through an independent trusted channel.
                    </p>
                </div>
                """,
                unsafe_allow_html=True,
            )

    # ========================================================
    # TECHNICAL DETAILS
    # ========================================================

    with st.expander(
        "⚙️ Technical Analysis Details",
        expanded=False,
    ):

        st.markdown(
            '<div class="technical-box">',
            unsafe_allow_html=True,
        )

        st.markdown(
            f"""
            <p>
                <strong>Rule-Based Score:</strong>
                {score}/100
            </p>

            <p>
                <strong>Rule-Based Classification:</strong>
                {escape(str(classification))}
            </p>
            """,
            unsafe_allow_html=True,
        )

        findings = rule_result.get(
            "findings",
            [],
        )

        st.markdown(
            "<p><strong>Detected Rule Indicators:</strong></p>",
            unsafe_allow_html=True,
        )

        if findings:

            for finding in findings:

                if isinstance(finding, dict):

                    indicator = finding.get(
                        "indicator",
                        "Indicator",
                    )

                    evidence = finding.get(
                        "evidence",
                        "",
                    )

                    points = finding.get(
                        "score",
                        "",
                    )

                    st.markdown(
                        f"""
                        <p>
                            • <strong>{escape(str(indicator))}</strong>
                            — {escape(str(evidence))}
                            {f" (+{escape(str(points))})" if points != "" else ""}
                        </p>
                        """,
                        unsafe_allow_html=True,
                    )

                else:

                    st.markdown(
                        f"<p>• {escape(str(finding))}</p>",
                        unsafe_allow_html=True,
                    )

        else:

            st.markdown(
                "<p>• No rule-based indicators detected.</p>",
                unsafe_allow_html=True,
            )

        urls = rule_result.get(
            "urls",
            [],
        )

        st.markdown(
            "<p><strong>URLs Detected:</strong></p>",
            unsafe_allow_html=True,
        )

        if urls:

            for url in urls:
                st.code(
                    str(url),
                    language=None,
                )

        else:

            st.markdown(
                "<p>• No URLs detected.</p>",
                unsafe_allow_html=True,
            )

        st.markdown(
            "</div>",
            unsafe_allow_html=True,
        )

    # ========================================================
    # PDF REPORT
    # ========================================================

    st.markdown(
        '<div class="section-title">📄 Analysis Report</div>',
        unsafe_allow_html=True,
    )

    try:

        pdf_data = generate_pdf_report(
            st.session_state.submitted_email,
            rule_result,
            ai_result,
        )

        timestamp = datetime.now().strftime(
            "%Y%m%d_%H%M%S"
        )

        st.download_button(
            label="⬇️ Download PDF Report",
            data=pdf_data,
            file_name=f"phishing_analysis_{timestamp}.pdf",
            mime="application/pdf",
            use_container_width=True,
        )

    except Exception as e:

        st.error(
            f"Could not generate PDF report: {str(e)}"
        )

    # ========================================================
    # DISCLAIMER
    # ========================================================

    st.markdown(
        """
        <div class="disclaimer">
            <p>
                <strong>⚠️ Security Notice:</strong>
                This tool provides educational security triage.
                A high-risk result does not by itself prove that
                an email is malicious. Do not click suspicious
                links or open unexpected attachments. Verify
                important requests through an independent,
                trusted communication channel.
            </p>
        </div>
        """,
        unsafe_allow_html=True,
    )


# ============================================================
# FOOTER
# ============================================================

st.markdown(
    """
    <div class="footer">
        Phishing Email Analyser • Hybrid Rule-Based + AI Security Analysis
    </div>
    """,
    unsafe_allow_html=True,
)
