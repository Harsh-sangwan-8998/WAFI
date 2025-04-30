import re
import requests
from logger import logger

def detect_xss(url):
    """Detects potential XSS vulnerabilities with expanded payloads."""

    logger.info(f"🔎 Scanning {url} for XSS vulnerabilities...")

    xss_patterns = {
        "Script Tags": r"(?i)<script.*?>.*?</script>",
        "Event Handlers": r"(?i)on\w+\s*=\s*[\"'][^>]+[\"']",
        "Document Cookie Access": r"(?i)document\.cookie",
        "JavaScript Alert": r"(?i)alert\s*\(",
        "Encoded XSS": r"(?i)%3Cscript%3E|%3C%2Fscript%3E",
        "iframe Injection": r"(?i)<iframe.*?>.*?</iframe>",
        "img onerror": r"(?i)<img.*?onerror\s*=\s*[\"'][^>]+[\"']",
        "Input Autocomplete Stealing": r"(?i)autocomplete\s*=\s*['\"]off['\"]",
        "XHR Stealing": r"(?i)XMLHttpRequest",
        # Added Payloads
        "Body onload": r"(?i)<body.*onload=.*?>",
        "HTML Injection": r"(?i)<.*>",
        "JavaScript URL": r"(?i)javascript:",
        "Data URI": r"(?i)data:text/javascript",
    }

    detected_payloads = [desc for desc, pattern in xss_patterns.items() if re.search(pattern, url)]

    if detected_payloads:
        logger.warning(f"⚠️ XSS vulnerability detected in {url}: {detected_payloads}")
        return {
            "status": "⚠️ XSS Detected",
            "payloads": detected_payloads,
            "mitigation": "Sanitize inputs, use Content Security Policy (CSP), and encode outputs."
        }

    logger.info(f"✅ No XSS vulnerabilities detected in {url}.")
    return {"status": "✅ Safe"}
