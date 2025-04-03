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
        f"Scan Type: {get_scan_type_name(scan_data.get('scan_type', 'N/A'))}",
        f"Scan Depth: {scan_data.get('scan_depth', 'N/A')}",
        f"Start Time: {scan_data.get('start_time', 'N/A')}",
        f"End Time: {scan_data.get('end_time', 'N/A')}"
    ]
    for detail in scan_details:
        story.append(Paragraph(detail, normal_style))
    
    story.append(Spacer(1, 12))
    
    # Extract vulnerabilities - handle different possible structures
    vulnerabilities = []
    
    # Try different possible paths to get vulnerabilities
    if 'results' in scan_data:
        if isinstance(scan_data['results'], dict):
            # Option 1: scan_data['results']['alerts']
            if 'alerts' in scan_data['results']:
                vulnerabilities = scan_data['results']['alerts']
            # Option 2: scan_data['results']['results']['alerts']
            elif 'results' in scan_data['results'] and isinstance(scan_data['results']['results'], dict):
                if 'alerts' in scan_data['results']['results']:
                    vulnerabilities = scan_data['results']['results']['alerts']
    
    # Try another common path if no results found yet
    if not vulnerabilities and 'results_data' in scan_data:
        try:
            results_data = json.loads(scan_data['results_data'])
            if 'alerts' in results_data:
                vulnerabilities = results_data['alerts']
            elif 'results' in results_data and 'alerts' in results_data['results']:
                vulnerabilities = results_data['results']['alerts']
        except (json.JSONDecodeError, TypeError):
            pass
    
    # Debug print vulnerabilities
    print(f"Vulnerabilities found: {len(vulnerabilities)}")
    print(f"Vulnerability data: {json.dumps(vulnerabilities, indent=2)}")
    
    # Get risk summary
    risk_summary = extract_risk_summary(scan_data)
    
    # Add Risk Summary section
    story.append(Paragraph("Risk Summary:", heading_style))
    
    if risk_summary:
        for risk, count in risk_summary.items():
            if count > 0:  # Only show non-zero risks
                risk_para = Paragraph(f"{risk} Risk Vulnerabilities: {count}", risk_styles.get(risk, normal_style))
                story.append(risk_para)
    else:
        story.append(Paragraph("No vulnerability data available.", normal_style))
    
    story.append(Spacer(1, 12))
    
    # Detailed Vulnerabilities
    story.append(Paragraph("Detailed Vulnerabilities:", heading_style))
    
    if not vulnerabilities:
        story.append(Paragraph("No detailed vulnerability data available.", normal_style))
    else:
        for vuln in vulnerabilities:
            try:
                vuln_name = vuln.get('name', 'Unknown Vulnerability')
                vuln_risk = vuln.get('risk', 'Informational')
                vuln_url = vuln.get('url', 'N/A')
                vuln_solution = vuln.get('solution', 'No remediation suggested')
                
                story.append(Paragraph(vuln_name, risk_styles.get(vuln_risk, normal_style)))
                story.append(Paragraph(f"Risk Level: {vuln_risk}", normal_style))
                story.append(Paragraph(f"URL: {vuln_url}", normal_style))
                story.append(Paragraph(f"Remediation: {vuln_solution}", normal_style))
                story.append(Spacer(1, 6))
            except Exception as e:
                print(f"Error processing vulnerability: {e}")
                story.append(Paragraph(f"Error processing vulnerability: {str(e)}", normal_style))
    
    # Build PDF
    doc.build(story)
    
    return pdf_path

def extract_risk_summary(scan_data):
    """
    Extract risk summary from different possible data structures
    Returns a dictionary of risk levels and counts
    """
    # Initialize default summary
    summary = {"High": 0, "Medium": 0, "Low": 0, "Informational": 0}
    
    # Try different possible paths
    if 'results' in scan_data:
        if isinstance(scan_data['results'], dict):
            # Option 1: Direct summary in results
            if 'summary' in scan_data['results']:
                return scan_data['results']['summary']
            # Option 2: Nested in results.results
            elif 'results' in scan_data['results'] and isinstance(scan_data['results']['results'], dict):
                if 'summary' in scan_data['results']['results']:
                    return scan_data['results']['results']['summary']
            # Option 3: Count from alerts
            elif 'alerts' in scan_data['results']:
                for alert in scan_data['results']['alerts']:
                    risk = alert.get('risk', 'Informational')
                    summary[risk] = summary.get(risk, 0) + 1
                return summary
    
    # Try another common path for serialized results
    if 'results_data' in scan_data:
        try:
            results_data = json.loads(scan_data['results_data'])
            if 'summary' in results_data:
                return results_data['summary']
            elif 'results' in results_data and 'summary' in results_data['results']:
                return results_data['results']['summary']
        except (json.JSONDecodeError, TypeError):
            pass
    
    return summary

def get_scan_type_name(scan_type):
    """Convert numeric scan type to readable name"""
    try:
        scan_type_int = int(scan_type)
        scan_types = {
            1: "Spider Scan",
            2: "Ajax Spider Scan",
            3: "Active Scan",
            4: "Passive Scan",
            5: "DOM XSS Scan",
            6: "WordPress Scan"
        }
        return scan_types.get(scan_type_int, f"Unknown ({scan_type})")
    except (ValueError, TypeError):
        return str(scan_type)