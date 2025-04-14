from flask import Flask, render_template, request, redirect, url_for, flash, session, jsonify
import os
import json
from datetime import datetime

from modules.url_validator import validate_url, check_site_availability, normalize_url
from modules.cms_detector import is_wordpress
from modules.zap_scanner import run_zap_scan, test_zap_connection, get_scan_results
from modules.wp_scanner import scan_wordpress_site
from flask import send_file
from modules.report_generator import generate_scan_report

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

app = Flask(__name__)
app.secret_key = 'valnara-development-key'

init_app(app)

RESULTS_DIR = 'scan_results'
if not os.path.exists(RESULTS_DIR):
    os.makedirs(RESULTS_DIR)

@app.route('/')
def index():
    """Home page with scan configuration form"""
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
    
    if not validate_url(url):
        return jsonify({'error': 'Invalid URL format'}), 400
    
    url = normalize_url(url)
    
    if not check_site_availability(url):
        return jsonify({'error': 'Site not available'}), 400
    
    wp_detected = is_wordpress(url)
    
    return jsonify({
        'url': url,
        'is_wordpress': wp_detected
    })

@app.route('/scan_status/<scan_id>')
def scan_status(scan_id):
    """Display scan status page"""
    scan_info = get_scan_by_id(scan_id)
    if not scan_info:
        flash('Scan not found', 'danger')
        return redirect(url_for('index'))
    
    print(f"Rendering scan status page for scan {scan_id}, status: {scan_info['status']}")
    
    return render_template('scan.html', scan=scan_info, scan_id=scan_id)

@app.route('/start_scan/<scan_id>', methods=['POST'])
def start_scan(scan_id):
    scan_info = get_scan_by_id(scan_id)
    if not scan_info:
        return jsonify({'status': 'error', 'message': 'Scan not found'}), 404
    
    scan_info['status'] = 'running'
    scan_info['progress'] = 0
    update_scan_status(scan_id, 'running')
    
    try:
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
        
        scan_info['status'] = 'completed'
        scan_info['progress'] = 100
        scan_info['end_time'] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        
        update_scan_results(scan_id, scan_result)
        
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
        
        update_scan_status(scan_id, 'failed')
        
        session['current_scan_id'] = scan_id
        session.modified = True
        
        return jsonify({
            'status': 'error',
            'message': f'Scan failed: {str(e)}'
        }), 500

@app.route('/api/scan_status/<scan_id>')
def api_scan_status(scan_id):
    """API endpoint to get current scan status and real-time results"""
    scan_info = get_scan_by_id(scan_id)
    if not scan_info:
        return jsonify({'status': 'error', 'message': 'Scan not found'}), 404
    
    print(f"API scan status check for {scan_id}")
    print(f"Current scan status: {scan_info['status'] if scan_info else 'No scan info'}")
    
    if scan_info['status'] == 'running':
        try:
            if scan_info['scan_type'] == 6:  # WordPress scan
                return jsonify({
                    'status': 'running',
                    'progress': scan_info.get('progress', 50),
                    'message': 'WordPress scan in progress'
                })
            else:
                latest_results = get_scan_results(scan_info['url'])
                
                if 'alerts' in latest_results:
                    temp_results = {
                        'alerts': latest_results.get('alerts', []),
                        'summary': latest_results.get('summary', {})
                    }
                    update_scan_results(scan_id, temp_results)
                
                return jsonify({
                    'status': 'running',
                    'progress': scan_info.get('progress', 0),
                    'results': latest_results,
                    'message': 'Scan in progress'
                })
            
        except Exception as e:
            print(f"Error fetching real-time results: {str(e)}")
            return jsonify({
                'status': scan_info['status'],
                'progress': scan_info.get('progress', 0),
                'message': f"Scan is {scan_info['status']}"
            })
    
    if scan_info['status'] == 'completed':
        print(f"Scan is completed, sending completed status and redirect")
        if 'results' in scan_info:
            results_data = scan_info['results']
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
        
    return jsonify({
        'status': scan_info['status'],
        'message': f"Scan is {scan_info['status']}",
        'redirect': url_for('results', scan_id=scan_id) if scan_info['status'] == 'completed' else None
    })

@app.route('/results/<scan_id>')
def results(scan_id):
    """Display the scan results page"""
    scan_info = get_scan_by_id(scan_id)
    if not scan_info:
        flash('Scan not found', 'danger')
        return redirect(url_for('index'))
    
    if scan_info['status'] != 'completed':
        flash('Scan is still in progress', 'warning')
        return redirect(url_for('scan_status', scan_id=scan_id))
    
    results_data = scan_info.get('results')
    
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

@app.route('/favicon.ico')
def favicon():
    return app.send_static_file('favicon.ico')

@app.errorhandler(404)
def page_not_found(e):
    return render_template('error.html', error_code=404, error_message="Page not found"), 404

@app.errorhandler(500)
def server_error(e):
    return render_template('error.html', error_code=500, error_message="Internal server error"), 500

@app.route('/download_report/<scan_id>')
def download_report(scan_id):
    scan = get_scan_by_id(scan_id)
    
    if not scan:
        flash('Scan report not found', 'danger')
        return redirect(url_for('index'))
    
    try:
        pdf_path = generate_scan_report(scan, scan_id)
        
        return send_file(pdf_path, as_attachment=True, 
                         download_name=f"valnara_scan_report_{scan_id}.pdf")
    
    except Exception as e:
        print(f"Report generation error: {e}")
        flash('Error generating report', 'danger')
        return redirect(url_for('results', scan_id=scan_id))

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=8000)