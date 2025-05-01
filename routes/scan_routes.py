from flask import Blueprint, request, jsonify
from scanner.sqli_scanner import detect_sqli
from scanner.xss_scanner import detect_xss
from scanner.port_scanner import scan_ports
from scanner.risk_assessment import assess_risk
from scanner.csrf_scanner import check_csrf

scan_routes = Blueprint("scan_routes", __name__)

@scan_routes.route('/scan', methods=['POST'])
def scan():
    data = request.json
    url = data.get("url")

    if not url:
        return jsonify({"error": "URL is required"}), 400

    # Call scanner modules
    sqli_results = detect_sqli(url)
    xss_results = detect_xss(url)
    port_results = scan_ports(url)
    csrf_results = check_csrf(url)

    # Risk assessment
    vulnerabilities = {
        "SQL Injection": sqli_results,
        "XSS": xss_results,
        "Open Ports": port_results,
        "CSRF" : csrf_results
    }
    risk_level = assess_risk(vulnerabilities)

    return jsonify({
        "url": url,
        "vulnerabilities": vulnerabilities,
        "risk_level": risk_level
    })
