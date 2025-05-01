from reportlab.lib.pagesizes import letter
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
from reportlab.lib.styles import getSampleStyleSheet
from reportlab.lib import colors
import os
from datetime import datetime
import logging

# Configure logger
logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger("report_generator")

def generate_report(scan_report, output_path=None):
    if output_path is None:
        timestamp = datetime.now().strftime("%Y-%m-%d-%H-%M-%S")
        output_path = os.path.join("static", f"{timestamp}-report.pdf")

    os.makedirs(os.path.dirname(output_path), exist_ok=True)
    logger.debug(f"Attempting to generate report at: {output_path}")

    doc = SimpleDocTemplate(output_path, pagesize=letter)
    styles = getSampleStyleSheet()
    story = []

    # Header
    story.append(Paragraph("Web Application Security Scan Report", styles['h1']))
    story.append(Spacer(1, 12))

    # Summary Table
    summary_data = [
        ["Item", "Value"],
        ["URL", scan_report.get("url", "N/A")],
        ["Risk Level", scan_report.get("risk_level", "N/A")],
        ["Links Found", len(scan_report.get("links", []))],
    ]
    table = Table(summary_data)
    table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, 0), colors.gray),
        ('TEXTCOLOR', (0, 0), (-1, 0), colors.black),
        ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
        ('GRID', (0, 0), (-1, -1), 0.5, colors.black),
    ]))
    story.append(table)
    story.append(Spacer(1, 12))

    # Open Ports Section
    story.append(Paragraph("Open Ports", styles['h2']))
    open_ports = scan_report.get("open_ports", [])
    if open_ports:
        ports_str = ", ".join(map(str, open_ports))
        story.append(Paragraph(f"Detected Open Ports: {ports_str}", styles['Normal']))
    else:
        story.append(Paragraph("No open ports found or scanning failed.", styles['Normal']))
    story.append(Spacer(1, 12))

    # Headers Section
    story.append(Paragraph("HTTP Response Headers", styles['h2']))
    headers = scan_report.get("headers", {})
    if headers:
        for key, value in headers.items():
            story.append(Paragraph(f"{key}: {value}", styles['Normal']))
    else:
        story.append(Paragraph("No headers received or header scan failed.", styles['Normal']))
    story.append(Spacer(1, 12))

    # Vulnerabilities Section
    story.append(Paragraph("Vulnerabilities", styles['h2']))
    vulnerabilities = scan_report.get("vulnerabilities", {})

    if vulnerabilities and isinstance(vulnerabilities, dict):
        for vuln_type, vuln_list in vulnerabilities.items():
            if vuln_list:
                story.append(Paragraph(f"{vuln_type}:", styles['h3']))
                for vuln in vuln_list:
                    if isinstance(vuln, dict):
                        url = vuln.get("url", "N/A")
                        details = vuln.get("details", "No details available")
                        form_inputs = vuln.get("form_inputs", [])
                        story.append(Paragraph(f"  - URL: {url}", styles['Normal']))
                        story.append(Paragraph(f"    Details: {details}", styles['Normal']))
                        if form_inputs:
                            story.append(Paragraph(f"    Form Inputs: {', '.join(form_inputs)}", styles['Normal']))

                        # Recommendations
                        if vuln_type == "SQLi":
                            story.append(Paragraph("    Recommendation: Use parameterized queries or prepared statements to prevent SQL injection.", styles['Normal']))
                        elif vuln_type == "XSS":
                            story.append(Paragraph("    Recommendation: Sanitize user inputs and encode outputs to prevent XSS attacks.", styles['Normal']))
                        elif vuln_type == "CSRF":
                            story.append(Paragraph("    Recommendation: Implement and validate CSRF tokens server-side.", styles['Normal']))
                    else:
                        logger.warning(f"Invalid vulnerability item for {vuln_type}: {vuln}")
            else:
                story.append(Paragraph(f"No {vuln_type} vulnerabilities found.", styles['Normal']))
    else:
        story.append(Paragraph("No vulnerabilities found.", styles['Normal']))

    try:
        doc.build(story)
        logger.debug(f"Report successfully generated at: {output_path}")
        return output_path
    except Exception as e:
        logger.error(f"Failed to generate report: {str(e)}")
        raise
