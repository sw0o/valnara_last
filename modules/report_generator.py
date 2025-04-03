import os
import json
from datetime import datetime
from reportlab.lib.pagesizes import letter
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch
from reportlab.platypus import SimpleDocTemplate, Table, TableStyle, Paragraph, Spacer
from reportlab.lib import colors

def generate_scan_report(scan_data, scan_id):
    # Create reports directory
    os.makedirs('reports', exist_ok=True)
    
    # Generate unique filename
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    base_filename = f"scan_report_{scan_id}_{timestamp}"
    pdf_path = f"reports/{base_filename}.pdf"
    
    # Debug print to check scan_data structure
    print("Scan Data:", json.dumps(scan_data, indent=2))
    
    # Create PDF document
    doc = SimpleDocTemplate(pdf_path, pagesize=letter, 
                            rightMargin=72, leftMargin=72, 
                            topMargin=72, bottomMargin=18)
    story = []
    
    # Custom Styles
    styles = getSampleStyleSheet()
    
    # Title Style
    title_style = ParagraphStyle(
        'TitleStyle',
        parent=styles['Title'],
        fontSize=20,
        textColor=colors.HexColor('#2C3E50'),
        spaceAfter=16
    )
    
    # Heading Style
    heading_style = ParagraphStyle(
        'HeadingStyle',
        parent=styles['Heading2'],
        fontSize=14,
        textColor=colors.HexColor('#34495E'),
        spaceAfter=12
    )
    
    # Normal Text Style
    normal_style = ParagraphStyle(
        'NormalStyle',
        parent=styles['Normal'],
        fontSize=10,
        textColor=colors.HexColor('#2C3E50'),
        leading=14
    )
    
    # Risk Level Styles
    risk_styles = {
        'High': ParagraphStyle('HighRisk', parent=normal_style, textColor=colors.red),
        'Medium': ParagraphStyle('MediumRisk', parent=normal_style, textColor=colors.HexColor('#F39C12')),
        'Low': ParagraphStyle('LowRisk', parent=normal_style, textColor=colors.blue),
        'Informational': ParagraphStyle('InfoRisk', parent=normal_style, textColor=colors.green)
    }
    
    # Title
    story.append(Paragraph("Valnara Security Scan Report", title_style))
    story.append(Spacer(1, 12))
    
    # Scan Details
    story.append(Paragraph("Scan Details:", heading_style))
    scan_details = [
        f"Target URL: {scan_data.get('url', 'N/A')}",
        f"Scan Type: {scan_data.get('scan_type', 'N/A')}",
        f"Scan Depth: {scan_data.get('scan_depth', 'N/A')}",
        f"Start Time: {scan_data.get('start_time', 'N/A')}"
    ]
    for detail in scan_details:
        story.append(Paragraph(detail, normal_style))
    
    story.append(Spacer(1, 12))
    
    # Extract vulnerabilities
    # Try multiple possible paths to get vulnerabilities
    vulnerabilities = []
    if 'results' in scan_data:
        vulnerabilities = scan_data['results'].get('alerts', [])
    elif 'alerts' in scan_data:
        vulnerabilities = scan_data['alerts']
    
    # Debug print vulnerabilities
    print("Vulnerabilities found:", len(vulnerabilities))
    
    # Risk Summary
    risk_summary = {}
    for vuln in vulnerabilities:
        risk = vuln.get('risk', 'Unclassified')
        risk_summary[risk] = risk_summary.get(risk, 0) + 1
    
    story.append(Paragraph("Risk Summary:", heading_style))
    for risk, count in risk_summary.items():
        risk_para = Paragraph(f"{risk} Risk Vulnerabilities: {count}", risk_styles.get(risk, normal_style))
        story.append(risk_para)
    
    story.append(Spacer(1, 12))
    
    # Detailed Vulnerabilities
    story.append(Paragraph("Detailed Vulnerabilities:", heading_style))
    
    if not vulnerabilities:
        story.append(Paragraph("No vulnerabilities detected.", normal_style))
    
    for vuln in vulnerabilities:
        story.append(Paragraph(vuln.get('name', 'Unknown Vulnerability'), 
                                risk_styles.get(vuln.get('risk'), normal_style)))
        story.append(Paragraph(f"URL: {vuln.get('url', 'N/A')}", normal_style))
        story.append(Paragraph(f"Remediation: {vuln.get('solution', 'No remediation suggested')}", normal_style))
        story.append(Spacer(1, 6))
    
    # Build PDF
    doc.build(story)
    
    return pdf_path