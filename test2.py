import requests
from bs4 import BeautifulSoup

def check_csrf(url):
    """
    Detects CSRF vulnerabilities by checking for missing CSRF tokens and headers.
    """
    try:
        session = requests.Session()
        
        # Get the page content
        response = session.get(url)
        soup = BeautifulSoup(response.text, 'html.parser')

        # Find all forms
        forms = soup.find_all('form')
        results = []

        for form in forms:
            action = form.get('action')
            method = form.get('method', 'GET').upper()
            inputs = form.find_all('input')

            # Check if CSRF token exists
            csrf_token_found = False
            for inp in inputs:
                if 'csrf' in inp.get('name', '').lower() or 'token' in inp.get('name', '').lower():
                    csrf_token_found = True
                    break
            
            if not csrf_token_found:
                results.append({
                    "form_action": action,
                    "method": method,
                    "risk_level": "High",
                    "details": "CSRF protection missing (No anti-CSRF token found).",
                    "mitigation": "Implement CSRF tokens and validate them in server-side requests."
                })
        
        # Check SameSite Cookie flag
        cookies = session.cookies.get_dict()
        if not any('SameSite' in cookie for cookie in cookies):
            results.append({
                "risk_level": "Medium",
                "details": "SameSite cookie flag missing. This can allow CSRF attacks.",
                "mitigation": "Use 'Set-Cookie: SameSite=Strict' or 'Lax' to protect against CSRF."
            })

        return results if results else {"found": False}

    except Exception as e:
        return {"error": str(e)}

# Example Usage
sites = [
    "http://testphp.vulnweb.com/",
    "https://testphp.vulnweb.com/",
    "https://owasp.org/www-project-web-security-testing-guide/v41/4-Web_Application_Security_Testing/04-Authentication_Testing/04-Testing_for_CSRF.html",
    "https://portswigger.net/web-security/csrf"
]

for site in sites:
    print(f"Testing {site}:")
    results = check_csrf(site)
    print(results)
    print("---")