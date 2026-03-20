import re
from dataclasses import dataclass


@dataclass
class EmailCheckResult:
    score: int
    verdict: str
    details: str


def check_email_legitimacy(raw_input: str) -> EmailCheckResult:
    text = (raw_input or "").strip()
    if not text:
        return EmailCheckResult(0, "invalid", "No email content provided.")

    lowered = text.lower()
    score = 50
    notes = []

    # Header-based trust indicators (offline parsing only).
    if "dkim=pass" in lowered:
        score += 20
        notes.append("DKIM pass found.")
    elif "dkim=fail" in lowered or "dkim=none" in lowered:
        score -= 20
        notes.append("DKIM failed or missing.")

    if "spf=pass" in lowered:
        score += 15
        notes.append("SPF pass found.")
    elif "spf=fail" in lowered or "spf=softfail" in lowered:
        score -= 20
        notes.append("SPF fail/softfail found.")

    if "dmarc=pass" in lowered:
        score += 15
        notes.append("DMARC pass found.")
    elif "dmarc=fail" in lowered or "dmarc=none" in lowered:
        score -= 20
        notes.append("DMARC failed or missing.")

    # Suspicious phrasing heuristics.
    suspicious_words = ["urgent", "verify account", "password reset now", "gift card", "crypto payment", "wire transfer"]
    hit_words = [w for w in suspicious_words if w in lowered]
    if hit_words:
        score -= min(30, len(hit_words) * 8)
        notes.append("Phishing-like wording detected.")

    # Basic From/Reply-To mismatch heuristic.
    from_match = re.search(r"from:\s*.*?<?([A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,})>?", text, re.IGNORECASE)
    reply_match = re.search(r"reply-to:\s*.*?<?([A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,})>?", text, re.IGNORECASE)
    if from_match and reply_match:
        from_domain = from_match.group(1).split("@")[-1].lower()
        reply_domain = reply_match.group(1).split("@")[-1].lower()
        if from_domain != reply_domain:
            score -= 18
            notes.append("From and Reply-To domains mismatch.")

    score = max(0, min(score, 100))
    verdict = "likely legit" if score >= 70 else "suspicious" if score < 45 else "needs review"
    details = " | ".join(notes) if notes else "No strong indicators found."
    details += " Offline check only: this does not query live CA/DNS services."
    return EmailCheckResult(score=score, verdict=verdict, details=details)
