import os
import webbrowser
from datetime import datetime
from urllib.parse import urlparse
from flask import Flask, request, jsonify, render_template, send_from_directory, Response
from routes.scan_routes import scan_routes
from scanner.crawler import crawl_website
from scanner.port_scanner import scan_ports
from report import generate_report
from scanner.risk_assessment import assess_risk
from logger import logger, generate_logs
from progress import scan_progress
import requests

app = Flask(__name__, static_folder="static", template_folder="templates")

# Register blueprint
app.register_blueprint(scan_routes)

@app.route('/')
def home():
    return render_template("welcome.html")

@app.route('/favicon.ico')
def favicon():
    return send_from_directory(os.path.join(app.root_path, 'static'), 'favicon.ico', mimetype='image/vnd.microsoft.icon')

@app.route('/progress')
def progress():
    def generate():
        import time
        while scan_progress["progress"] < scan_progress["total"]:
            yield f"data: {scan_progress['progress']}\n\n"
            time.sleep(0.1)
        yield f"data: {scan_progress['total']}\n\n"
    return Response(generate(), mimetype='text/event-stream')

@app.route('/report/<filename>')
def get_report(filename):
    return send_from_directory(os.path.join(app.root_path, "static"), filename)

@app.route('/scan', methods=['POST'])
def scan():
    try:
        data = request.get_json()
        url = data.get("url", "").strip()
        max_links = int(data.get("max_links", 50))

        logger.info(f"🔍 Received scan request for: {url} (Max Links: {max_links})")

        if not url:
            return jsonify({"status": "error", "message": "No URL provided"}), 400

        parsed_url = urlparse(url)
        if not parsed_url.scheme:
            url = "http://" + url

        scan_progress["progress"] = 0
        scan_progress["total"] = max_links

        scan_report = crawl_website(url, max_links)
        if not isinstance(scan_report, dict) or not scan_report:
            raise ValueError("Invalid scan report generated.")

        # Port scanning
        try:
            hostname = parsed_url.hostname
            open_ports_result = scan_ports(hostname)
            scan_report["open_ports"] = open_ports_result.get("open_ports", [])
        except Exception as e:
            scan_report["open_ports"] = []
            logger.warning(f"⚠️ Port scan error: {str(e)}")

        # Headers
        try:
            response = requests.get(url, timeout=10)
            headers = dict(response.headers)
        except Exception as e:
            headers = {"error": f"Header fetch failed: {str(e)}"}
        scan_report["headers"] = headers

        scan_report["risk_level"] = assess_risk(scan_report.get("vulnerabilities", {}))
        log_data = generate_logs(url, scan_report)

        timestamp = datetime.now().strftime("%Y-%m-%d-%H-%M-%S")
        pdf_filename = f"{timestamp}-report.pdf"
        pdf_path = os.path.join(app.root_path, "static", pdf_filename)

        generated = generate_report(scan_report, output_path=pdf_path)
        if not os.path.exists(generated):
            raise FileNotFoundError("Generated PDF not found.")

        logger.info(f"✅ Scan complete. Report: {pdf_filename}")
        return jsonify({
            "status": "success",
            "risk_level": scan_report["risk_level"],
            "report_path": f"/report/{pdf_filename}",
            "log_data": log_data
        })

    except Exception as e:
        logger.error(f"❌ Scan failed: {str(e)}")
        return jsonify({"status": "error", "message": f"Server error: {str(e)}"}), 500

@app.route('/test')
def test():
    return "✅ Flask is running successfully!"

if __name__ == '__main__':
    port = int(os.environ.get("PORT", 5000))
    url = f"http://127.0.0.1:{port}/"
    print("\n🚀 Web Scanner is running!")
    print(f"🔗 Open your browser: {url}\n")
    webbrowser.open(url)
    app.run(host="0.0.0.0", port=port)
