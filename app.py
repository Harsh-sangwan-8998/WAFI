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
from threading import Thread

app = Flask(__name__, static_folder="static", template_folder="templates")
app.register_blueprint(scan_routes)

@app.route('/')
def home():
    return render_template("welcome.html")

@app.route('/favicon.ico')
def favicon():
    return send_from_directory(
        directory=app.root_path,
        path='favicon.ico',
        mimetype='image/vnd.microsoft.icon'
    )

@app.route('/progress')
def progress():
    def generate():
        import time
        while scan_progress["progress"] < scan_progress["total"]:
            yield f"data: {scan_progress['progress']}\n\n"
            time.sleep(0.1)
        yield f"data: {scan_progress['total']}\n\n"
    return Response(generate(), mimetype='text/event-stream')

def perform_scan(url, max_links):
    try:
        logger.info(f"\U0001f50d Starting scan for: {url}")

        parsed_url = urlparse(url)
        if not parsed_url.scheme:
            url = "http://" + url

        scan_progress["progress"] = 0
        scan_progress["total"] = max_links

        scan_report = crawl_website(url, max_links)
        if not isinstance(scan_report, dict) or not scan_report:
            raise ValueError("Invalid scan report.")

        hostname = urlparse(url).hostname
        open_ports_result = scan_ports(hostname)
        scan_report["open_ports"] = open_ports_result.get("open_ports", [])

        try:
            response = requests.get(url, timeout=10)
            headers = dict(response.headers)
        except Exception as e:
            headers = {"error": str(e)}

        scan_report["headers"] = headers
        scan_report["risk_level"] = assess_risk(scan_report.get("vulnerabilities", {}))
        generate_logs(url, scan_report)

        timestamp = datetime.now().strftime("%Y-%m-%d-%H-%M-%S")
        static_report_path = os.path.join("static", f"{timestamp}-report.pdf")
        generate_report(scan_report, output_path=static_report_path)

        logger.info(f"✅ Scan complete. Report: {static_report_path}")

    except Exception as e:
        logger.error(f"❌ Scan error in thread: {str(e)}")

@app.route('/scanner', methods=['POST'])
def scan():
    data = request.get_json()
    url = data.get("url", "").strip()
    max_links = int(data.get("max_links", 50))

    if not url:
        return jsonify({"status": "error", "message": "No URL provided"}), 400

    
        # Start scan in background thread
    thread = Thread(target=perform_scan, args=(url, max_links))
    thread.start()

    return jsonify({
        "status": "started",
        "message": f"Scan started for {url}",
        "progress_endpoint": "/progress"
    }), 202

@app.route('/test')
def test():
    return "✅ Flask is running successfully!"

@app.route("/download-report")
def download_report():
    return send_file("path/to/scan_report.pdf", as_attachment=True)

@app.errorhandler(500)
def internal_error(e):
    return jsonify({"status": "error", "message": "Internal server error", "details": str(e)}), 500

@app.errorhandler(404)
def not_found_error(e):
    return jsonify({"status": "error", "message": "Not found"}), 404

@app.route('/static/<filename>')
def download_file(filename):
    return send_from_directory(os.path.join(app.root_path, 'static'), filename)

@app.route('/scan_report')
def scan_report():
    report_path = "static/scan_report.pdf"
    if os.path.exists(report_path):
        return send_from_directory(os.path.dirname(report_path), os.path.basename(report_path))
    else:
        return "Report not found", 404

if __name__ == '__main__':
    port = int(os.environ.get("PORT", 5000))
    url = f"http://127.0.0.1:{port}/"
    print("\n🚀 Web Scanner is running!")
    print(f"🔗 Open your browser: {url}\n")
    webbrowser.open(url)
    app.run(host="0.0.0.0", debug=True, port=port)
