from flask import Flask, render_template, request, redirect, url_for, flash, session, jsonify
import os
import json
from datetime import datetime

# Import the modules you've already completed
from modules.url_validator import validate_url, check_site_availability, normalize_url
from modules.cms_detector import is_wordpress
from modules.zap_scanner import run_zap_scan, test_zap_connection, get_scan_results

# Initialize Flask app
app = Flask(__name__)
app.secret_key = 'valnara-development-key'
app.config['SESSION_TYPE'] = 'filesystem'  # Use filesystem session for persistence

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
            'start_time': datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            'progress': 0,
            'vulnerabilities': []
        }
        
        # Store in session for simplicity (in a real app you'd use a database)
        session['current_scan'] = scan_info
        session.modified = True  # Explicitly mark session as modified
        
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
    
    # Debug output to console
    print(f"Rendering scan status page for scan {scan_id}, status: {scan_info['status']}")
    
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
        scan_info['progress'] = 0
        session['current_scan'] = scan_info
        session.modified = True
        
        # Debug output
        print(f"Starting scan for {scan_info['url']} with scan type {scan_info['scan_type']}")
        
        # Run ZAP scan - no output_file parameter now
        scan_types = [scan_info['scan_type']]
        
        scan_result = run_zap_scan(
            target=scan_info['url'],
            scan_types=scan_types,
            spider_depth=scan_info['scan_depth']
        )
        
        # Debug output
        print(f"Scan completed. Result structure: {type(scan_result)}")
        print(f"Result keys: {scan_result.keys() if isinstance(scan_result, dict) else 'Not a dict'}")
        
        # Update scan info with results
        scan_info['status'] = 'completed'
        scan_info['progress'] = 100
        scan_info['end_time'] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        scan_info['results'] = scan_result  # Store results directly in session
        session['current_scan'] = scan_info
        session.modified = True
        
        # Debug output
        print(f"Scan marked as completed. Status: {scan_info['status']}")
        print(f"Redirecting to: {url_for('results', scan_id=scan_id)}")
        
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
        session.modified = True
        
        return jsonify({
            'status': 'error',
            'message': f'Scan failed: {str(e)}'
        }), 500

@app.route('/api/scan_status/<scan_id>')
def api_scan_status(scan_id):
    """API endpoint to get current scan status and real-time results"""
    scan_info = session.get('current_scan')
    
    # Debug output
    print(f"API scan status check for {scan_id}")
    print(f"Current session data: {scan_info['status'] if scan_info else 'No scan info'}")
    
    if not scan_info or scan_info['id'] != scan_id:
        return jsonify({'status': 'error', 'message': 'Scan not found'}), 404
    
    # If the scan is running, fetch the latest results
    if scan_info['status'] == 'running':
        try:
            # Get the latest scan results from ZAP
            latest_results = get_scan_results(scan_info['url'])
            
            # Store intermediate results in the session
            scan_info['vulnerabilities'] = latest_results.get('alerts', [])
            scan_info['vulnerability_summary'] = latest_results.get('summary', {})
            session['current_scan'] = scan_info
            session.modified = True
            
            print(f"Updated running scan with {len(scan_info.get('vulnerabilities', []))} findings")
            
            return jsonify({
                'status': 'running',
                'progress': scan_info.get('progress', 0),
                'results': latest_results,
                'message': 'Scan in progress'
            })
            
        except Exception as e:
            print(f"Error fetching real-time results: {str(e)}")
            # Return the status without results if there's an error
            return jsonify({
                'status': scan_info['status'],
                'progress': scan_info.get('progress', 0),
                'message': f"Scan is {scan_info['status']}"
            })
    
    # For completed scans, include the full results
    if scan_info['status'] == 'completed':
        print(f"Scan is completed, sending completed status and redirect")
        if 'results' in scan_info:
            results_data = scan_info['results']
            # Check if results are nested
            if isinstance(results_data, dict) and 'results' in results_data:
                extracted_results = results_data['results']
            else:
                extracted_results = results_data
                
            print(f"Returning results with {len(extracted_results.get('alerts', []))} alerts")
            
            return jsonify({
                'status': 'completed',
                'results': extracted_results,
                'message': 'Scan completed',
                'redirect': url_for('results', scan_id=scan_id)
            })
        else:
            print("Completed but no results found in session")
        
    # For other statuses, just return the basic info
    return jsonify({
        'status': scan_info['status'],
        'message': f"Scan is {scan_info['status']}",
        'redirect': url_for('results', scan_id=scan_id) if scan_info['status'] == 'completed' else None
    })

@app.route('/results/<scan_id>')
def results(scan_id):
    """Display the scan results page"""
    scan_info = session.get('current_scan')
    
    print(f"Attempting to show results for scan {scan_id}")
    
    if not scan_info or scan_info['id'] != scan_id:
        flash('Scan not found', 'danger')
        return redirect(url_for('index'))
    
    if scan_info['status'] != 'completed':
        flash('Scan is still in progress', 'warning')
        return redirect(url_for('scan_status', scan_id=scan_id))
    
    # Get results directly from session and extract the needed parts
    results_data = scan_info.get('results')
    
    print(f"Results data keys: {results_data.keys() if isinstance(results_data, dict) else 'Not a dict'}")
    
    # Try different structures to handle possible nested data
    if results_data and isinstance(results_data, dict) and 'results' in results_data:
        # Handle nested structure
        extracted_results = results_data['results']
    else:
        # Assume direct structure
        extracted_results = results_data
    
    print(f"Rendering results page with {len(extracted_results.get('alerts', []))} alerts")
    
    return render_template('results.html', scan=scan_info, results=extracted_results)

# Custom error handlers
@app.errorhandler(404)
def page_not_found(e):
    return render_template('error.html', error_code=404, error_message="Page not found"), 404

@app.errorhandler(500)
def server_error(e):
    return render_template('error.html', error_code=500, error_message="Internal server error"), 500

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000)