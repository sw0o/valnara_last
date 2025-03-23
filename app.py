from flask import Flask, render_template, request, redirect, url_for, flash, session, jsonify
import os
import json
from datetime import datetime

# Import the modules you've already completed
from modules.url_validator import validate_url, check_site_availability, normalize_url
from modules.cms_detector import is_wordpress
from modules.zap_scanner import run_zap_scan, test_zap_connection

# Initialize Flask app
app = Flask(__name__)
app.secret_key = 'valnara-development-key'

# Ensure scan results directory exists
RESULTS_DIR = 'scan_results'
if not os.path.exists(RESULTS_DIR):
    os.makedirs(RESULTS_DIR)

@app.route('/')
def index():
    """Home page with scan configuration form"""
    # Check if ZAP is running
    zap_available, zap_version = test_zap_connection()
    
    return render_template('index.html', 
                          zap_available=zap_available, 
                          zap_version=zap_version)

@app.route('/scan', methods=['GET', 'POST'])
def scan():
    """Handle scan requests and display scan status"""
    if request.method == 'POST':
        # Get form data
        target_url = request.form.get('url', '').strip()
        scan_type = int(request.form.get('scan_type', 4))  # Default to passive scan (4)
        scan_depth = int(request.form.get('scan_depth', 5))  # Default depth is 5
        
        # Validate URL
        if not validate_url(target_url):
            flash('Invalid URL format. Please enter a valid URL.', 'danger')
            return redirect(url_for('index'))
        
        # Normalize URL
        target_url = normalize_url(target_url)
        
        # Check if the site is available
        if not check_site_availability(target_url):
            flash('The target site is not available. Please check the URL and try again.', 'danger')
            return redirect(url_for('index'))
        
        # Generate a unique scan ID based on timestamp
        scan_id = datetime.now().strftime("%Y%m%d%H%M%S")
        
        # Create scan info
        scan_info = {
            'id': scan_id,
            'url': target_url,
            'scan_type': scan_type,
            'scan_depth': scan_depth,
            'is_wordpress': is_wordpress(target_url),
            'status': 'pending',
            'start_time': datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        }
        
        # Store in session for simplicity (in a real app you'd use a database)
        session['current_scan'] = scan_info
        
        # Redirect to scan status page
        return redirect(url_for('scan_status', scan_id=scan_id))
    
    # If this is a GET request, show the form
    return render_template('scan.html')

@app.route('/scan_status/<scan_id>')
def scan_status(scan_id):
    """Display scan status page"""
    scan_info = session.get('current_scan')
    
    if not scan_info or scan_info['id'] != scan_id:
        flash('Scan not found', 'danger')
        return redirect(url_for('index'))
    
    return render_template('scan.html', scan=scan_info, scan_id=scan_id)

@app.route('/start_scan/<scan_id>', methods=['POST'])
def start_scan(scan_id):
    """API endpoint to start the scan"""
    scan_info = session.get('current_scan')
    
    if not scan_info or scan_info['id'] != scan_id:
        return jsonify({'status': 'error', 'message': 'Scan not found'}), 404
    
    try:
        # Update scan status
        scan_info['status'] = 'running'
        session['current_scan'] = scan_info
        
        # Run ZAP scan - no output_file parameter now
        scan_types = [scan_info['scan_type']]
        
        print(f"Starting scan for {scan_info['url']} with scan types {scan_types}")
        
        scan_result = run_zap_scan(
            target=scan_info['url'],
            scan_types=scan_types,
            spider_depth=scan_info['scan_depth']
        )
        
        # Update scan info with results
        scan_info['status'] = 'completed'
        scan_info['end_time'] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        scan_info['results'] = scan_result  # Store results directly in session
        session['current_scan'] = scan_info
        
        return jsonify({
            'status': 'success',
            'message': 'Scan completed successfully',
            'redirect': url_for('results', scan_id=scan_id)
        })
        
    except Exception as e:
        # Detailed error logging
        import traceback
        print(f"Scan failed with error: {str(e)}")
        print(traceback.format_exc())
        
        scan_info['status'] = 'failed'
        scan_info['error'] = str(e)
        session['current_scan'] = scan_info
        
        return jsonify({
            'status': 'error',
            'message': f'Scan failed: {str(e)}'
        }), 500

@app.route('/api/scan_status/<scan_id>')
def api_scan_status(scan_id):
    """API endpoint to get current scan status"""
    scan_info = session.get('current_scan')
    
    if not scan_info or scan_info['id'] != scan_id:
        return jsonify({'status': 'error', 'message': 'Scan not found'}), 404
    
    return jsonify({
        'status': scan_info['status'],
        'message': f"Scan is {scan_info['status']}",
        'redirect': url_for('results', scan_id=scan_id) if scan_info['status'] == 'completed' else None
    })

@app.route('/results/<scan_id>')
def results(scan_id):
    scan_info = session.get('current_scan')
    
    print(f"Debug - Scan info structure: {scan_info.keys() if scan_info else None}")
    
    if not scan_info or scan_info['id'] != scan_id:
        flash('Scan not found', 'danger')
        return redirect(url_for('index'))
    
    if scan_info['status'] != 'completed':
        flash('Scan is still in progress', 'warning')
        return redirect(url_for('scan_status', scan_id=scan_id))
    
    # Get results directly from session and extract the needed parts
    results_data = scan_info.get('results')
    
    # Try different structures to handle possible nested data
    if results_data and 'results' in results_data:
        # Handle nested structure
        extracted_results = results_data['results']
    else:
        # Assume direct structure
        extracted_results = results_data
    
    print(f"Final results data: {extracted_results}")
    
    return render_template('results.html', scan=scan_info, results=extracted_results)