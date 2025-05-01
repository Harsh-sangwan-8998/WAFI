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
                        to_visit.append(full_url)

            # Extract Forms (optional enhancement: support POST)
            for form in soup.find_all("form"):
                found_forms.append({"url": current_url, "form": str(form)})

            scan_progress["progress"] += 1

        except Exception as e:
            logger.error(f"❌ Error crawling {current_url}: {str(e)}")

    # Fallback if no links were found
    if not found_urls:
        logger.warning("⚠️ No links found. Using root page as fallback.")
        found_urls = [url]

    logger.info(f"🔗 Total Links Found: {len(found_urls)} | 📝 Forms: {len(found_forms)}")

    # Begin scanning
    for target_url in found_urls:
        sql_result = detect_sqli(target_url)
        xss_result = detect_xss(target_url)
        csrf_result = check_csrf(target_url)

        if sql_result["found"]:
            vulnerabilities["SQLi"].extend(sql_result["results"])
        if xss_result["found"]:
            vulnerabilities["XSS"].extend(xss_result["results"])
        if csrf_result["found"]:
            vulnerabilities["CSRF"].extend(csrf_result["results"])

    logger.info(f"✅ Scanning complete. Summary: SQLi: {len(vulnerabilities['SQLi'])}, "
                f"XSS: {len(vulnerabilities['XSS'])}, CSRF: {len(vulnerabilities['CSRF'])}")

    return {
        "url": url,
        "links_found": len(found_urls),
        "forms_found": len(found_forms),
        "vulnerabilities": vulnerabilities
    }
