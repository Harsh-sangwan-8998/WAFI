import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse
from logger import generate_logs, logger
from report import generate_report
from scanner.sqli_scanner import detect_sqli
from scanner.xss_scanner import detect_xss
from scanner.csrf_scanner import check_csrf
from scanner.risk_assessment import assess_risk
import time
from progress import scan_progress

def crawl_website(url, max_pages=30):
    """Crawls a website, extracts links and forms, scans vulnerabilities, logs results, and generates a report."""

    logger.info(f"🌍 Starting crawl for: {url} (Max Pages: {max_pages})")

    visited = set()
    to_visit = [url]
    found_urls = []
    found_forms = []
    vulnerabilities = {
        "SQLi": [],
        "XSS": [],
        "CSRF": []
    }

    while to_visit and len(visited) < max_pages:
        current_url = to_visit.pop(0)
        if current_url in visited:
            continue

        try:
            response = requests.get(current_url, timeout=5)
            visited.add(current_url)

            soup = BeautifulSoup(response.text, "html.parser")

            # Extract Links
            for link in soup.find_all("a", href=True):
                href = link.get("href")
                full_url = urljoin(url, href)
                parsed_url = urlparse(full_url)

                if parsed_url.netloc == urlparse(url).netloc and "?" in full_url:
                    if full_url not in found_urls:
                        found_urls.append(full_url)

                if full_url not in visited and full_url.startswith(url):
                    to_visit.append(full_url)

            # Extract Forms
            for form in soup.find_all("form"):
                action = form.get("action")
                method = form.get("method", "get").lower()
                inputs = [input_tag.get("name") for input_tag in form.find_all("input") if input_tag.get("name")]

                form_details = {
                    "action": urljoin(url, action) if action else url,
                    "method": method,
                    "inputs": inputs
                }
                found_forms.append(form_details)

                # Scan Form Submission URL
                if form_details["action"]:
                    sql_injection = detect_sqli(form_details["action"])
                    xss_vulnerability = detect_xss(form_details["action"])
                    csrf_vulnerability = check_csrf(form_details["action"])

                    if sql_injection:
                        vulnerabilities["SQLi"].append({
                            "url": form_details["action"],
                            "details": sql_injection,
                            "form_inputs": inputs
                        })
                        logger.warning(f"⚠ SQLi detected in form at {form_details['action']}")

                    if xss_vulnerability["status"] == "⚠ XSS Detected":
                        vulnerabilities["XSS"].append({
                            "url": form_details["action"],
                            "details": xss_vulnerability,
                            "form_inputs": inputs
                        })
                        logger.warning(f"⚠ XSS detected in form at {form_details['action']}")

                    if csrf_vulnerability.get("found", False):
                        for result in csrf_vulnerability["results"]:
                            vulnerabilities["CSRF"].append({
                                "url": form_details["action"],
                                "details": result["details"],
                                "risk_level": result["risk_level"],
                                "mitigation": result.get("mitigation", ""),
                                "form_inputs": inputs
                            })
                            logger.warning(f"⚠ CSRF vulnerability detected in form at {form_details['action']} - {result['details']}")

            # Update progress
            scan_progress["progress"] = len(visited)
            logger.info(f"📈 Progress: {len(visited)}/{max_pages} pages scanned")

        except requests.exceptions.RequestException as e:
            logger.error(f"❌ Error crawling {current_url}: {str(e)}")
            continue

        time.sleep(0.5)  # Be polite!

    # Scan Links
    for link in found_urls:
        sql_injection = detect_sqli(link)
        xss_vulnerability = detect_xss(link)

        if sql_injection:
            vulnerabilities["SQLi"].append({"url": link, "details": sql_injection})
            logger.warning(f"⚠ SQLi detected at {link}")

        if xss_vulnerability["status"] == "⚠ XSS Detected":
            vulnerabilities["XSS"].append({"url": link, "details": xss_vulnerability})
            logger.warning(f"⚠ XSS detected at {link}")

    # Assess Risk
    risk_level = assess_risk(vulnerabilities)

    # Log and Report
    scan_report = {
        "status": "success",
        "links": found_urls,
        "forms": found_forms,
        "vulnerabilities": vulnerabilities,
        "risk_level": risk_level,
        "url": url
    }
    log_data = generate_logs(url, scan_report)

    report_path = generate_report(scan_report)
    logger.info(f"✅ Scan completed for {url}! Report saved at: {report_path}")

    return scan_report
