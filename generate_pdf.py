from reportlab.lib.pagesizes import letter
from reportlab.pdfgen import canvas
import requests

def generate_pdf_report(api_url, output_filename="IPsec_Security_Report.pdf"):
    # Local API se assessment data fetch karein
    response = requests.get(api_url)
    data = response.json()

    c = canvas.Canvas(output_filename, pagesize=letter)

    # Header
    c.setFont("Helvetica-Bold", 16)
    c.drawString(40, 750, "IPsec Sentinel - VPN Security Audit Report")
    c.setStrokeColorRGB(0.2, 0.2, 0.2)
    c.line(40, 740, 550, 740)

    # Overview Metrics
    c.setFont("Helvetica", 12)
    c.drawString(40, 710, f"Overall Risk Score: {data.get('risk_score')}/100")
    c.drawString(40, 690, f"Security Posture: {data.get('security_posture')}")
    c.drawString(40, 670, f"AI Model Confidence: {data.get('ai_confidence_score')}%")

    # Threat Matrix Table
    c.setFont("Helvetica-Bold", 14)
    c.drawString(40, 630, "Threat Findings & Vulnerabilities:")

    y = 600
    c.setFont("Helvetica-Bold", 10)
    c.drawString(40, y, "Severity")
    c.drawString(100, y, "Finding")
    c.drawString(300, y, "Mitigation")
    y -= 15

    c.setFont("Helvetica", 9)
    for item in data.get('threat_matrix', []):
        c.drawString(40, y, item.get('severity', 'N/A'))
        c.drawString(100, y, str(item.get('issue', ''))[:35])
        c.drawString(300, y, str(item.get('recommendation', ''))[:45])
        y -= 20
        if y < 50: # Page break handling
            c.showPage()
            y = 750

    c.save()
    print(f"Report successfully saved to {output_filename}")

if __name__ == "__main__":
    # Sample data endpoint se PDF generate karein
    generate_pdf_report("http://127.0.0.1:5000/api/sample")