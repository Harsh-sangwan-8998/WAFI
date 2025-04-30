from datetime import datetime
import os
import logging

# Define log directory and file
LOG_DIR = "logs"
os.makedirs(LOG_DIR, exist_ok=True)  # Ensure log directory exists
LOG_FILE = os.path.join(LOG_DIR, f"{datetime.now().strftime('%Y-%m-%d-%H-%M-%S')}-log.txt")

# Clear log file by creating a new one (overwrites existing)
with open(LOG_FILE, 'w') as f:
    pass  # Creates an empty file

# Configure logging
logging.basicConfig(
    filename=LOG_FILE,
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s"
)

# Create a shared logger instance
logger = logging.getLogger("scan_logger")

def generate_logs(url, scan_result):
    """
    Logs scanning details for a given URL.
    """
    # Ensure scan_result is a dictionary
    if not isinstance(scan_result, dict):
        logger.error("❌ scan_result is not a dictionary!")
        return "❌ scan_result format error"

    log_entry = f"\n🔍 Scan Report for {url}\n"
    log_entry += f"Timestamp: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n"

    links = scan_result.get("links", [])
    log_entry += f"Total Links Found: {len(links)}\n"

    if "error" in scan_result.get("status", "").lower():
        log_entry += f"❌ Error: {scan_result.get('message')}\n"
    else:
        for link in links:
            log_entry += f"🔗 {link}\n"

    if isinstance(scan_result.get("open_ports"), list):  # Ensure it's a list before accessing
        log_entry += f"🚪 Open Ports: {scan_result['open_ports']}\n"

    vulnerabilities = scan_result.get("vulnerabilities", [])
    if isinstance(vulnerabilities, list) and vulnerabilities:
        log_entry += "⚠️ Detected Vulnerabilities:\n"
        for vuln in vulnerabilities:
            if isinstance(vuln, dict):  # Ensure vulnerability data is structured correctly
                log_entry += f"🔴 [{vuln.get('type', 'Unknown')}] {vuln.get('url', 'Unknown')} - {vuln.get('details', 'No details')}\n"

    logger.info(log_entry)
    return log_entry  # Return log data for further use