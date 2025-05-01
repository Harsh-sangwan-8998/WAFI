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
    try:
        if output_path is None:
            timestamp = datetime.now().strftime("%Y-%m-%d-%H-%M-%S")
            output_path = os.path.join("static", f"{timestamp}-report.pdf")

        os.makedirs(os.path.dirname(output_path), exist_ok=True)
        logger.debug(f"Generating report at: {output_path}")

        doc = SimpleDocTemplate(output_path, pagesize=letter)
        styles = getSampleStyleSheet()
        story = []

        # Title
        story.append(Paragraph("Web Application Security Scan Report", styles['Title']))
        story.append(Spacer(1, 12))

        # Summary Table
        summary_data = [
            ["Item", "Value"],
            ["URL", scan_report.get("url", "N/A")],
            ["Risk Level", scan_report.get("risk_level", "N/A")],
            ["Links Found", str(scan_report.get("links_found", 0))]
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

        # HTTP Headers
        headers = scan_report.get("headers", {})
        story.append(Paragraph("HTTP Response Headers", styles['Heading2']))
        if headers:
            for key, val in headers.items():
                story.append(Paragraph(f"<b>{key}:</b> {val}", styles['Normal']))
        else:
            story.append(Paragraph("No headers available.", styles['Normal']))
        story.append(Spacer(1, 12))

        # Open Ports
        story.append(Paragraph("Open Ports", styles['Heading2']))
        open_ports = scan_report.get("open_ports", [])
        if open_ports:
            story.append(Paragraph(", ".join(str(port) for port in open_ports), styles['Normal']))
        else:
            story.append(Paragraph("No open ports found or scan failed.", styles['Normal']))
        story.append(Spacer(1, 12))

        # Vulnerabilities
        vulnerabilities = scan_report.get("vulnerabilities", {})
        for category, findings in vulnerabilities.items():
            story.append(Paragraph(f"{category} Vulnerabilities", styles['Heading2']))
            if findings:
                for vuln in findings:
                    story.append(Paragraph(f"🛑 <b>{vuln.get('details', 'Issue')}</b>", styles['BodyText']))
                    story.append(Paragraph(f"<b>URL:</b> {vuln.get('url', 'N/A')}", styles['Normal']))
                    story.append(Paragraph(f"<b>Payload:</b> {vuln.get('payload', 'N/A')}", styles['Normal']))
                    story.append(Paragraph(f"<b>Mitigation:</b> {vuln.get('mitigation', 'N/A')}", styles['Normal']))
                    story.append(Spacer(1, 6))
            else:
                story.append(Paragraph("No vulnerabilities found.", styles['Normal']))
            story.append(Spacer(1, 12))

        doc.build(story)
        logger.info(f"✅ PDF report generated: {output_path}")
        return output_path

    except Exception as e:
        logger.error(f"❌ Failed to generate PDF report: {str(e)}")
        raise
