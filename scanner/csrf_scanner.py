from urllib.parse import urlparse
import requests
from bs4 import BeautifulSoup
import re

def check_csrf(url):
    """
    Detects CSRF vulnerabilities by checking for missing CSRF tokens in forms 
    and notes limitations in SameSite cookie detection.
    """
    try:
        session = requests.Session()
        response = session.get(url, timeout=10)
        response.raise_for_status()  # Raise an exception for bad status codes
        soup = BeautifulSoup(response.text, 'html.parser')

        forms = soup.find_all('form')
        results = []
        token_patterns = re.compile(r'(csrf|token|security)[\w]*', re.IGNORECASE)

        for form in forms:
            action = form.get('action', url)  # Default to current URL if no action
            method = form.get('method', 'GET').upper()
            inputs = form.find_all('input')
            parsed_action = urlparse(action)
            parsed_url = urlparse(url)

            # Check if action is on the same domain
            if parsed_action.netloc and parsed_action.netloc != parsed_url.netloc:
                continue  # Skip external forms

            csrf_token_found = False
            for inp in inputs:
                name = inp.get('name', '').lower()
                if token_patterns.search(name) or (inp.get('type') == 'hidden' and len(inp.get('value', '')) > 10):
                    csrf_token_found = True
                    break

            if not csrf_token_found and method in ['POST', 'PUT', 'DELETE']:
                results.append({
                    "form_action": action,
                    "method": method,
                    "risk_level": "High",
                    "details": "CSRF protection missing (no CSRF token found in form).",
                    "mitigation": "Implement and validate CSRF tokens server-side for all forms."
                })
            elif not csrf_token_found:
                results.append({
                    "form_action": action,
                    "method": method,
                    "risk_level": "Medium",
                    "details": "CSRF protection missing (no CSRF token found in GET form).",
                    "mitigation": "Consider adding CSRF tokens or restricting to POST methods."
                })

        if not results:
            results.append({
                "risk_level": "Info",
                "details": "No CSRF vulnerabilities detected with static analysis.",
                "note": "Dynamic testing with tools like Selenium is recommended to verify SameSite cookie attributes and server-side validation."
            })

        return {"found": len(results) > 0, "results": results}

    except requests.RequestException as e:
        return {"error": f"Request failed: {str(e)}"}
    except Exception as e:
        return {"error": f"Unexpected error: {str(e)}"}