from flask import Flask, render_template, request, redirect, url_for, flash, session, jsonify
import os
import json
from datetime import datetime

# Import the modules you've already completed
from modules.url_validator import validate_url, check_site_availability, normalize_url
from modules.cms_detector import is_wordpress
from modules.zap_scanner import run_zap_scan, test_zap_connection, get_scan_results
from modules.wp_scanner import scan_wordpress_site  # Import WordPress scanner
from flask import send_file
from modules.report_generator import generate_scan_report

# Import database modules
from database import init_app
from database.models import db
from database.operations import (
    create_scan, 
    get_scan_by_id, 
    update_scan_status, 
    update_scan_results, 
    get_scan_history,
    delete_scan
)

# Initialize Flask app
app = Flask(__name__)
app.secret_key = 'valnara-development-key'


# Initialize database
init_app(app)

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
                          zap_version=zap_version,
                          is_wordpress_checked=False,
                          is_wordpress=False)

@app.route('/scan', methods=['GET', 'POST'])
def scan():
    if request.method == 'POST':
        target_url = request.form.get('url', '').strip()
        scan_type = int(request.form.get('scan_type', 4))
        scan_depth = int(request.form.get('scan_depth', 5))
        
        if not validate_url(target_url):
            flash('Invalid URL format. Please enter a valid URL.', 'danger')
            return redirect(url_for('index'))
        
        target_url = normalize_url(target_url)
        
        if not check_site_availability(target_url):
            flash('The target site is not available. Please check the URL and try again.', 'danger')
            return redirect(url_for('index'))
        
        scan_id = datetime.now().strftime("%Y%m%d%H%M%S")
        
        wp_site = is_wordpress(target_url)
        print(f"DEBUG - WordPress detection result: {wp_site} for {target_url}")
        
        scan_info = {
            'id': scan_id,
            'url': target_url,
            'scan_type': 6 if wp_site else scan_type,
            'scan_depth': scan_depth,
            'is_wordpress': wp_site,
            'status': 'pending',
            'start_time': datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            'progress': 0,
            'vulnerabilities': []
        }
        
        print(f"DEBUG - Scan info created: WordPress site? {wp_site}, Scan type: {scan_info['scan_type']}, Type of scan_type: {type(scan_info['scan_type'])}")
        
        # Store only scan ID in session, not the full scan info
        session['current_scan_id'] = scan_id
        session.modified = True
        
        create_scan(scan_info)
        
        return redirect(url_for('scan_status', scan_id=scan_id))
    
    return render_template('scan.html')

@app.route('/api/check_wordpress', methods=['POST'])
def check_wordpress():
    """API endpoint to check if a URL is a WordPress site"""
    data = request.json
    url = data.get('url', '')
    
    if not url:
        return jsonify({'error': 'No URL provided'}), 400
    
    # Validate URL
    if not validate_url(url):
        return jsonify({'error': 'Invalid URL format'}), 400
    
    # Normalize URL
    url = normalize_url(url)
    
    # Check if the site is available
    if not check_site_availability(url):
        return jsonify({'error': 'Site not available'}), 400
    
    # Check if it's a WordPress site
    wp_detected = is_wordpress(url)
    
    return jsonify({
        'url': url,
        'is_wordpress': wp_detected
    })

@app.route('/scan_status/<scan_id>')
def scan_status(scan_id):
    """Display scan status page"""
    # Always get scan info from database
    scan_info = get_scan_by_id(scan_id)
    if not scan_info:
        flash('Scan not found', 'danger')
        return redirect(url_for('index'))
    
    # Debug output to console
    print(f"Rendering scan status page for scan {scan_id}, status: {scan_info['status']}")
    
    return render_template('scan.html', scan=scan_info, scan_id=scan_id)

@app.route('/start_scan/<scan_id>', methods=['POST'])
def start_scan(scan_id):
    # Always get scan info from database
    scan_info = get_scan_by_id(scan_id)
    if not scan_info:
        return jsonify({'status': 'error', 'message': 'Scan not found'}), 404
    
    # First update to running state and save it before starting the scan
    scan_info['status'] = 'running'
    scan_info['progress'] = 0
    update_scan_status(scan_id, 'running')
    
    try:
        # WordPress scan condition
        if scan_info.get('is_wordpress', False) or scan_info.get('scan_type') == 6:
            print("ATTEMPTING WORDPRESS SCAN")
            scan_result = scan_wordpress_site(scan_info['url'])
        else:
            print("ATTEMPTING ZAP SCAN")
            scan_types = [scan_info['scan_type']]
            scan_result = run_zap_scan(
                target=scan_info['url'],
                scan_types=scan_types,
                spider_depth=scan_info['scan_depth']
            )
        
        # Update to completed status
        scan_info['status'] = 'completed'
        scan_info['progress'] = 100
        scan_info['end_time'] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        
        # Save to database - this stores the full results
        update_scan_results(scan_id, scan_result)
        
        # Update session with just the ID
        session['current_scan_id'] = scan_id
        session.modified = True
        
        return jsonify({
            'status': 'completed',
            'message': 'Scan completed successfully',
            'redirect': url_for('results', scan_id=scan_id)
        })
        
    except Exception as e:
        import traceback
        print(f"Scan failed with error: {str(e)}")
        print(traceback.format_exc())
        
        # Update status to failed
        update_scan_status(scan_id, 'failed')
        
        # Store only ID in session
        session['current_scan_id'] = scan_id
        session.modified = True
        
        return jsonify({
            'status': 'error',
            'message': f'Scan failed: {str(e)}'
        }), 500

@app.route('/api/scan_status/<scan_id>')
def api_scan_status(scan_id):
    """API endpoint to get current scan status and real-time results"""
    # Always get scan info from database
    scan_info = get_scan_by_id(scan_id)
    if not scan_info:
        return jsonify({'status': 'error', 'message': 'Scan not found'}), 404
    
    # Debug output
    print(f"API scan status check for {scan_id}")
    print(f"Current scan status: {scan_info['status'] if scan_info else 'No scan info'}")
    
    # If the scan is running, fetch the latest results
    if scan_info['status'] == 'running':
        try:
            # Get the latest scan results based on scan type
            if scan_info['scan_type'] == 6:  # WordPress scan
                # For WordPress scans, we don't have real-time updates
                # Just return the current status
                return jsonify({
                    'status': 'running',
                    'progress': scan_info.get('progress', 50),  # Default to 50% for WordPress scans
                    'message': 'WordPress scan in progress'
                })
            else:
                # Get the latest scan results from ZAP
                latest_results = get_scan_results(scan_info['url'])
                
                # For real-time updates, update database directly (don't store in session)
                if 'alerts' in latest_results:
                    # Create a temporary results object to update the database
                    temp_results = {
                        'alerts': latest_results.get('alerts', []),
                        'summary': latest_results.get('summary', {})
                    }
                    # Update database with current progress
                    update_scan_results(scan_id, temp_results)
                
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
            print("Completed but no results found in database")
        
    # For other statuses, just return the basic info
    return jsonify({
        'status': scan_info['status'],
        'message': f"Scan is {scan_info['status']}",
        'redirect': url_for('results', scan_id=scan_id) if scan_info['status'] == 'completed' else None
    })

@app.route('/results/<scan_id>')
def results(scan_id):
    """Display the scan results page"""
    # Always get scan info from database
    scan_info = get_scan_by_id(scan_id)
    if not scan_info:
        flash('Scan not found', 'danger')
        return redirect(url_for('index'))
    
    if scan_info['status'] != 'completed':
        flash('Scan is still in progress', 'warning')
        return redirect(url_for('scan_status', scan_id=scan_id))
    
    # Get results from the scan_info
    results_data = scan_info.get('results')
    
    # Try different structures to handle possible nested data
    if results_data and isinstance(results_data, dict) and 'results' in results_data:
        extracted_results = results_data['results']
    else:
        extracted_results = results_data
    
    print(f"Rendering results with {len(extracted_results.get('alerts', []))} alerts")
    
    return render_template('results.html', scan=scan_info, results=extracted_results)

@app.route('/history')
def history():
    """Display scan history page"""
    scans = get_scan_history()
    return render_template('history.html', scans=scans)

@app.route('/delete_scan/<scan_id>', methods=['POST'])
def delete_scan_route(scan_id):
    """Delete a scan from the database"""
    if delete_scan(scan_id):
        flash('Scan deleted successfully', 'success')
    else:
        flash('Error deleting scan', 'danger')
    return redirect(url_for('history'))

@app.route('/test_results')
def test_results():
    """Test route to view the results page with sample data"""
    # Create a mock scan with test data
    scan_id = "test" + datetime.now().strftime("%Y%m%d%H%M%S")
    
    # Sample scan info
    scan_info = {
        'id': scan_id,
        'url': 'https://example.com',
        'scan_type': 3,  # Active scan
        'scan_depth': 5,
        'is_wordpress': False,
        'status': 'completed',
        'start_time': datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        'end_time': datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        'results': {
            'alerts': [
                {
                    'name': 'Cross-Site Scripting (Reflected)',
                    'risk': 'High',
                    'url': 'https://example.com/search?q=test',
                    'solution': 'Validate all input and encode output properly.'
                },
                {
                    'name': 'SQL Injection',
                    'risk': 'High',
                    'url': 'https://example.com/product?id=1',
                    'solution': 'Use prepared statements and parameterized queries.'
                },
                {
                    'name': 'Insecure Cookie',
                    'risk': 'Medium',
                    'url': 'https://example.com',
                    'solution': 'Set secure and HttpOnly flags on cookies.'
                },
                {
                    'name': 'Missing Security Headers',
                    'risk': 'Low',
                    'url': 'https://example.com',
                    'solution': 'Implement proper security headers (Content-Security-Policy, X-XSS-Protection, etc).'
                }
            ],
            'summary': {
                'High': 2,
                'Medium': 1,
                'Low': 1,
                'Informational': 0
            }
        }
    }
    
    # Store in database and only ID in session
    session['current_scan_id'] = scan_id
    session.modified = True
    create_scan(scan_info)
    
    return redirect(url_for('results', scan_id=scan_id))

@app.route('/test_wordpress_results')
def test_wordpress_results():
    """Test route to view WordPress scan results with sample data"""
    # Create a mock WordPress scan with test data
    scan_id = "wptest" + datetime.now().strftime("%Y%m%d%H%M%S")
    
    # Sample WordPress scan info
    scan_info = {
        'id': scan_id,
        'url': 'https://example-wordpress.com',
        'scan_type': 6,  # WordPress scan
        'scan_depth': 5,
        'is_wordpress': True,
        'status': 'completed',
        'start_time': datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        'end_time': datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        'results': {
            'alerts': [
                {
                    'name': 'WordPress Core 5.9.3 - Authentication Bypass',
                    'risk': 'High',
                    'url': 'https://example-wordpress.com',
                    'solution': 'Update WordPress to the latest version.'
                },
                {
                    'name': 'Plugin: contact-form-7 (v5.4.2) - SQL Injection',
                    'risk': 'High',
                    'url': 'https://example-wordpress.com/wp-content/plugins/contact-form-7/',
                    'solution': 'Update contact-form-7 to the latest version or remove it if unused. Update to version 5.5.0 or later.'
                },
                {
                    'name': 'Theme: twentytwenty (v1.8) - XSS Vulnerability',
                    'risk': 'Medium',
                    'url': 'https://example-wordpress.com/wp-content/themes/twentytwenty/',
                    'solution': 'Update twentytwenty to the latest version or switch to a more secure theme. Update to version 1.9 or later.'
                },
                {
                    'name': 'WordPress User Enumeration Possible',
                    'risk': 'Medium',
                    'url': 'https://example-wordpress.com/?author=1',
                    'solution': 'Configure your site to prevent user enumeration by modifying .htaccess or using a security plugin.'
                },
                {
                    'name': 'XML-RPC Interface Enabled',
                    'risk': 'Medium',
                    'url': 'https://example-wordpress.com/xmlrpc.php',
                    'solution': 'Disable XML-RPC if not needed or restrict access to it through .htaccess.'
                },
                {
                    'name': 'WordPress 5.9.3 Detected',
                    'risk': 'Informational',
                    'url': 'https://example-wordpress.com',
                    'solution': 'Keep WordPress core updated to the latest secure version.'
                }
            ],
            'summary': {
                'High': 2,
                'Medium': 3,
                'Low': 0,
                'Informational': 1
            },
            'scan_info': {
                'wordpress': {
                    'duration': 15,
                    'duration_formatted': '00:00:15',
                    'wp_version': '5.9.3'
                }
            }
        }
    }
    
    # Store in database and only ID in session
    session['current_scan_id'] = scan_id
    session.modified = True
    create_scan(scan_info)
    
    return redirect(url_for('results', scan_id=scan_id))

# Add favicon route
@app.route('/favicon.ico')
def favicon():
    return app.send_static_file('favicon.ico')

# Custom error handlers
@app.errorhandler(404)
def page_not_found(e):
    return render_template('error.html', error_code=404, error_message="Page not found"), 404

@app.errorhandler(500)
def server_error(e):
    return render_template('error.html', error_code=500, error_message="Internal server error"), 500

@app.route('/download_report/<scan_id>')
def download_report(scan_id):
    # Retrieve scan results from database
    scan = get_scan_by_id(scan_id)
    
    if not scan:
        flash('Scan report not found', 'danger')
        return redirect(url_for('index'))
    
    try:
        # Generate report
        pdf_path = generate_scan_report(scan, scan_id)
        
        return send_file(pdf_path, as_attachment=True, 
                         download_name=f"valnara_scan_report_{scan_id}.pdf")
    
    except Exception as e:
        print(f"Report generation error: {e}")
        flash('Error generating report', 'danger')
        return redirect(url_for('results', scan_id=scan_id))

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=8000)