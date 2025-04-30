def assess_risk(vulnerabilities):
    """
    Analyzes the vulnerabilities and assigns a risk level.
    """
    risk_score = 0

    # ✅ Check if SQL Injection vulnerabilities exist
    if vulnerabilities.get("SQLi") and len(vulnerabilities["SQLi"]) > 0:
        risk_score += 3

    # ✅ Check if XSS vulnerabilities exist
    if vulnerabilities.get("XSS") and len(vulnerabilities["XSS"]) > 0:
        risk_score += 3

    # ✅ Check for Missing Security Headers
    missing_headers = vulnerabilities.get("Headers", {}).get("missing_headers", [])
    risk_score += len(missing_headers)

    # ✅ Count Open Ports
    open_ports = vulnerabilities.get("Ports", {}).get("open_ports", [])
    risk_score += len(open_ports)

    # ✅ Assign Risk Level
    if risk_score >= 7:
        return "High Risk"
    elif risk_score >= 3:
        return "Medium Risk"
    else:
        return "Low Risk"
