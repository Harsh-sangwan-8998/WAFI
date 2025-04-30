import socket
import threading
from urllib.parse import urlparse
from concurrent.futures import ThreadPoolExecutor
from logger import logger

def scan_ports(url, ports=[21, 22, 80, 443, 3306, 8080], timeout=1.0, max_workers=10):
    """Scans ports concurrently with configurable options."""
    try:
        # Parse URL to extract hostname
        parsed_url = urlparse(url)
        target = parsed_url.hostname or parsed_url.path  # Fallback to path if no hostname
        if not target or '.' not in target:
            raise ValueError("Invalid hostname extracted from URL")
        
        ip = socket.gethostbyname(target)
        open_ports = []
        lock = threading.Lock()  # For thread-safe access to open_ports

        def scan_port(port):
            if not 0 <= port <= 65535:
                logger.warning(f"⚠️ Skipping invalid port: {port}")
                return
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                sock.settimeout(timeout)
                result = sock.connect_ex((ip, port))
                if result == 0:
                    with lock:
                        open_ports.append(port)
                    try:
                        service = socket.getservbyport(port, 'tcp')
                        logger.info(f"Port {port}: Open - {service}")
                    except OSError:
                        logger.info(f"Port {port}: Open - Unknown Service")

        # Use ThreadPoolExecutor for controlled concurrency
        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            executor.map(scan_port, ports)

        return {
            "status": "success",
            "open_ports": sorted(open_ports),
            "ip": ip,
            "scanned_ports": ports
}


    except socket.gaierror as e:
        logger.error(f"❌ Invalid hostname: {str(e)}")
        return {"status": "error", "message": "Invalid hostname"}
    except ValueError as e:
        logger.error(f"❌ Value error: {str(e)}")
        return {"status": "error", "message": str(e)}
    except Exception as e:
        logger.error(f"❌ Unexpected error during port scan: {str(e)}")
        return {"status": "error", "message": str(e)}

if __name__ == "__main__":
    # Example usage
    result = scan_ports("http://example.com", range(1, 1025), timeout=2.0, max_workers=20)
    print(result)