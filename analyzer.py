import re
from urllib.parse import urlparse


# -----------------------------
# Risk scoring configuration
# -----------------------------

RULES = [
    {
        "name": "Urgency or pressure",
        "patterns": [
            r"\burgent\b",
            r"\bimmediately\b",
            r"\bas soon as possible\b",
            r"\baction required\b",
            r"\bact now\b",
            r"\bwithin \d+ hours?\b",
            r"\bdeadline\b",
        ],
        "score": 10,
        "description": "The email uses pressure or urgency to encourage immediate action.",
    },
    {
        "name": "Account suspension or closure threat",
        "patterns": [
            r"account.{0,40}(suspend|disable|close|terminate)",
            r"(suspend|disable|close|terminate).{0,40}account",
        ],
        "score": 15,
        "description": "The email threatens account suspension, closure, or loss of access.",
    },
    {
        "name": "Password request",
        "patterns": [
            r"enter.{0,30}password",
            r"provide.{0,30}password",
            r"confirm.{0,30}password",
            r"send.{0,30}password",
        ],
        "score": 20,
        "description": "The email appears to request a password or other credentials.",
    },
    {
        "name": "MFA or verification-code request",
        "patterns": [
            r"\bmfa\b",
            r"\botp\b",
            r"verification code",
            r"security code",
            r"authentication code",
            r"one[- ]time code",
        ],
        "score": 20,
        "description": "The email requests or references an MFA, OTP, or verification code.",
    },
    {
        "name": "Payment or gift-card request",
        "patterns": [
            r"gift card",
            r"gift cards",
            r"make a payment",
            r"send payment",
            r"wire transfer",
            r"bank transfer",
            r"purchase.{0,30}(card|gift)",
        ],
        "score": 15,
        "description": "The email requests money, payment, or gift cards.",
    },
    {
        "name": "Bank-detail change request",
        "patterns": [
            r"change.{0,40}bank details",
            r"update.{0,40}bank details",
            r"new bank account",
            r"change.{0,40}account number",
            r"new account details",
        ],
        "score": 20,
        "description": "The email requests or announces a change to banking/payment details.",
    },
    {
        "name": "Credential harvesting language",
        "patterns": [
            r"verify your account",
            r"verify your identity",
            r"confirm your identity",
            r"sign in to verify",
            r"login to verify",
            r"validate your account",
            r"credentials",
        ],
        "score": 15,
        "description": "The email contains language commonly associated with credential harvesting.",
    },
    {
        "name": "Macro-enabling request",
        "patterns": [
            r"enable macros",
            r"enable macro",
            r"enable content",
            r"enable editing",
        ],
        "score": 20,
        "description": "The email asks the recipient to enable macros or active document content.",
    },
    {
        "name": "Invoice or business-payment language",
        "patterns": [
            r"invoice",
            r"payment due",
            r"outstanding payment",
            r"accounts payable",
            r"purchase order",
            r"payment instructions",
        ],
        "score": 8,
        "description": "The email contains invoice or business-payment language that can occur in BEC scams.",
    },
]


def detect_rule_indicators(email_text):
    """
    Scan the email for predefined phishing indicators.
    Returns findings and the total rule score.
    """

    findings = []
    score = 0

    text = email_text.lower()

    for rule in RULES:
        matched = False

        for pattern in rule["patterns"]:
            if re.search(pattern, text, re.IGNORECASE):
                matched = True
                break

        if matched:
            findings.append(
                {
                    "indicator": rule["name"],
                    "score": rule["score"],
                    "description": rule["description"],
                    "source": "Rule-based analysis",
                }
            )

            score += rule["score"]

    return findings, min(score, 100)


def extract_urls(email_text):
    """
    Extract URLs from the email text.
    """

    return re.findall(
        r"https?://[^\s<>\"]+",
        email_text,
        re.IGNORECASE,
    )


def analyze_urls(email_text):
    """
    Look for basic suspicious URL characteristics.
    """

    findings = []
    score = 0

    urls = extract_urls(email_text)

    for url in urls:
        clean_url = url.rstrip(".,);]}>")

        try:
            parsed = urlparse(clean_url)
            hostname = parsed.hostname

            if not hostname:
                continue

            # Raw IP address
            if re.fullmatch(
                r"\d{1,3}(\.\d{1,3}){3}",
                hostname,
            ):
                findings.append(
                    {
                        "indicator": "URL uses a raw IP address",
                        "score": 15,
                        "description": (
                            f"The URL uses an IP address instead of a normal "
                            f"domain name: {hostname}"
                        ),
                        "source": "URL analysis",
                    }
                )
                score += 15

            # Common URL shorteners
            shorteners = {
                "bit.ly",
                "tinyurl.com",
                "t.co",
                "goo.gl",
                "ow.ly",
                "is.gd",
                "buff.ly",
                "cutt.ly",
            }

            if hostname.lower() in shorteners:
                findings.append(
                    {
                        "indicator": "Shortened URL",
                        "score": 10,
                        "description": (
                            f"The email contains a URL-shortening service: "
                            f"{hostname}"
                        ),
                        "source": "URL analysis",
                    }
                )
                score += 10

            # Suspicious URL username component
            if "@" in parsed.netloc:
                findings.append(
                    {
                        "indicator": "URL contains an embedded username",
                        "score": 10,
                        "description": (
                            "The URL contains an '@' character in its network "
                            "location, which can sometimes be used to disguise "
                            "the actual destination."
                        ),
                        "source": "URL analysis",
                    }
                )
                score += 10

        except ValueError:
            continue

    return findings, min(score, 100)


def detect_sender_reply_to_mismatch(email_text):
    """
    Detect simple Sender/Reply-To mismatches when headers are pasted.
    """

    sender_match = re.search(
        r"(?im)^from:\s*(?:.*<)?([^<>\s]+@[^<>\s]+)>?\s*$",
        email_text,
    )

    reply_match = re.search(
        r"(?im)^reply-to:\s*(?:.*<)?([^<>\s]+@[^<>\s]+)>?\s*$",
        email_text,
    )

    if not sender_match or not reply_match:
        return [], 0

    sender = sender_match.group(1).lower()
    reply_to = reply_match.group(1).lower()

    sender_domain = sender.split("@")[-1]
    reply_domain = reply_to.split("@")[-1]

    if sender_domain != reply_domain:
        return [
            {
                "indicator": "Sender and Reply-To domain mismatch",
                "score": 15,
                "description": (
                    f"The From address uses '{sender_domain}' while Reply-To "
                    f"uses '{reply_domain}'."
                ),
                "source": "Header analysis",
            }
        ], 15

    return [], 0


def detect_authentication_results(email_text):
    """
    Detect explicit SPF, DKIM and DMARC failures when authentication
    results are included in pasted headers.

    We only report failures that are explicitly present.
    We do not guess missing authentication results.
    """

    findings = []
    score = 0

    text = email_text.lower()

    checks = [
        (
            "SPF failure",
            r"spf\s*=\s*(fail|softfail|neutral)",
            15,
        ),
        (
            "DKIM failure",
            r"dkim\s*=\s*(fail|temperror|permerror)",
            15,
        ),
        (
            "DMARC failure",
            r"dmarc\s*=\s*(fail)",
            15,
        ),
    ]

    for name, pattern, points in checks:
        if re.search(pattern, text):
            findings.append(
                {
                    "indicator": name,
                    "score": points,
                    "description": (
                        f"The pasted email headers explicitly contain a "
                        f"{name.lower()} result."
                    ),
                    "source": "Email authentication analysis",
                }
            )
            score += points

    return findings, min(score, 100)


def analyze_email(email_text):
    """
    Main rule-based analysis function.
    """

    all_findings = []
    total_score = 0

    rule_findings, rule_score = detect_rule_indicators(email_text)
    all_findings.extend(rule_findings)
    total_score += rule_score

    url_findings, url_score = analyze_urls(email_text)
    all_findings.extend(url_findings)
    total_score += url_score

    header_findings, header_score = detect_sender_reply_to_mismatch(
        email_text
    )
    all_findings.extend(header_findings)
    total_score += header_score

    auth_findings, auth_score = detect_authentication_results(
        email_text
    )
    all_findings.extend(auth_findings)
    total_score += auth_score

    # Prevent the rule-based score from exceeding 100.
    total_score = min(total_score, 100)

    if total_score >= 60:
        classification = "High Risk"
    elif total_score >= 25:
        classification = "Suspicious"
    else:
        classification = "Low Risk"

    return {
        "score": total_score,
        "classification": classification,
        "findings": all_findings,
        "urls": extract_urls(email_text),
    }
