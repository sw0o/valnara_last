import time
import requests
import json
from datetime import datetime, timedelta

# Configuration settings
API_KEY = 'bg8oefavmqe4a9be5s4t4oo8rs'
ZAP_API_URL = 'http://localhost:8080/JSON'

def zap_api_call(component, operation_type, operation, params=None):
    url = f"{ZAP_API_URL}/{component}/{operation_type}/{operation}/"
    if params is None:
        params = {}
    params['apikey'] = API_KEY
    response = requests.get(url, params=params)
    return response.json()

def format_time(seconds):
    return str(timedelta(seconds=seconds)).split('.')[0]

def ensure_url_in_context(target):
    """Make sure the URL is in ZAP's context before scanning"""
    try:
        # First try accessing the target site through ZAP's proxy
        zap_api_call('core', 'action', 'accessUrl', {'url': target})
        time.sleep(2)
        
        # Then run a quick spider to make sure it's in the tree
        spider_result = zap_api_call('spider', 'action', 'scan', {'url': target, 'maxChildren': '5'})
        if 'scan' not in spider_result:
            print(f"Spider response: {spider_result}")
            return False
        
        scan_id = spider_result['scan']
        # Wait for spider to finish
        for _ in range(10):  # Wait max 10 seconds
            progress = zap_api_call('spider', 'view', 'status', {'scanId': scan_id})
            if int(progress.get('status', 0)) >= 100:
                return True
            time.sleep(1)
        
        return True
    except Exception as e:
        print(f"Error ensuring URL in context: {str(e)}")
        return False

def run_spider_scan(target, max_depth=5):
    start_time = time.time()
    
    # Ensure URL is in context first
    ensure_url_in_context(target)
    
    zap_api_call('spider', 'action', 'setOptionMaxDepth', {'Integer': str(max_depth)})
    
    scan_result = zap_api_call('spider', 'action', 'scan', {'url': target})
    
    # Handle potential error
    if 'scan' not in scan_result:
        print(f"Unexpected ZAP API response: {scan_result}")
        if 'code' in scan_result and scan_result['code'] == 'url not found':
            # Let's try a different endpoint to see if it helps
            scan_result = zap_api_call('spider', 'action', 'scanAsUser', 
                                       {'url': target, 'contextId': '1', 'userId': '0'})
        
        # If still no scan ID, use a default value
        if 'scan' not in scan_result:
            scan_id = '1'  # Default value
        else:
            scan_id = scan_result['scan']
    else:
        scan_id = scan_result['scan']
    
    while True:
        progress = zap_api_call('spider', 'view', 'status', {'scanId': scan_id})
        current = int(progress.get('status', 0))
        if current >= 100:
            break
        time.sleep(2)
    
    duration = time.time() - start_time
    
    return {
        'duration': int(duration),
        'duration_formatted': format_time(int(duration))
    }

def run_ajax_spider_scan(target, max_duration=600):
    start_time = time.time()
    
    # Ensure URL is in context first
    ensure_url_in_context(target)
    
    zap_api_call('ajaxSpider', 'action', 'scan', {'url': target})
    
    while True:
        status = zap_api_call('ajaxSpider', 'view', 'status')
        running = status['running']
        
        elapsed = time.time() - start_time
        if not running == 'true' or elapsed > max_duration:
            break
            
        time.sleep(5)
    
    duration = time.time() - start_time
    
    return {
        'duration': int(duration),
        'duration_formatted': format_time(int(duration))
    }

def run_active_scan(target, scan_policy=None):
    start_time = time.time()
    
    # Ensure URL is in context first
    if not ensure_url_in_context(target):
        raise Exception("Cannot add URL to scan tree")
    
    params = {'url': target}
    if scan_policy:
        params['scanPolicyName'] = scan_policy
    
    # Try to use the scanAsUser method instead if regular scan fails
    try:
        scan_result = zap_api_call('ascan', 'action', 'scan', params)
        
        # Check for error response
        if 'code' in scan_result and scan_result['code'] == 'url not found':
            # Try alternative method
            print("URL not found in scan tree, trying scanAsUser method...")
            scan_result = zap_api_call('ascan', 'action', 'scanAsUser', 
                                      {'url': target, 'contextId': '1', 'userId': '0'})
    except Exception as e:
        print(f"Error starting active scan: {str(e)}")
        raise
    
    print(f"Active scan result: {scan_result}")
    
    # Handle missing scan key
    if 'scan' not in scan_result:
        if 'code' in scan_result:
            raise Exception(f"ZAP API Error: {scan_result.get('code')} - {scan_result.get('message')}")
        scan_id = '1'  # Default value
    else:
        scan_id = scan_result['scan']
    
    # Monitor scan progress
    try:
        while True:
            progress = zap_api_call('ascan', 'view', 'status', {'scanId': scan_id})
            current = int(progress.get('status', 0))
            print(f"Active scan progress: {current}%")
            if current >= 100:
                break
            time.sleep(5)
    except Exception as e:
        print(f"Error monitoring scan: {str(e)}")
    
    duration = time.time() - start_time
    
    return {
        'duration': int(duration),
        'duration_formatted': format_time(int(duration))
    }

def run_passive_scan(wait_time=60):
    start_time = time.time()
    
    max_records = 0
    while True:
        records = zap_api_call('pscan', 'view', 'recordsToScan')
        current = int(records['recordsToScan'])
        
        if current > max_records:
            max_records = current
        
        progress = 100 if max_records == 0 else int(100 - (current / max_records) * 100)
        
        elapsed = time.time() - start_time
        if progress >= 100 or elapsed > wait_time:
            break
            
        time.sleep(2)
    
    duration = time.time() - start_time
    
    return {
        'duration': int(duration),
        'duration_formatted': format_time(int(duration))
    }

def run_dom_xss_scan(target):
    start_time = time.time()
    
    # Ensure URL is in context first
    ensure_url_in_context(target)
    
    zap_api_call('domxss', 'action', 'setEnabled', {'Boolean': 'true'})
    
    scan_result = zap_api_call('domxss', 'action', 'scan', {'url': target})
    
    time.sleep(10)
    
    duration = time.time() - start_time
    
    return {
        'duration': int(duration),
        'duration_formatted': format_time(int(duration))
    }

def setup_authentication(auth_url, username, password):
    context_id = zap_api_call('context', 'action', 'newContext', 
                             {'contextName': 'auth-context'})['contextId']
    
    target_domain = auth_url.split('//')[1].split('/')[0]
    include_regex = f".*{target_domain}.*"
    zap_api_call('context', 'action', 'includeInContext', 
                {'contextName': 'auth-context', 'regex': include_regex})
    
    zap_api_call('authentication', 'action', 'setAuthenticationMethod', 
                {'contextId': context_id, 'authMethodName': 'formBasedAuthentication',
                 'authMethodConfigParams': f'loginUrl={auth_url}&loginRequestData=username%3D{username}%26password%3D{password}'})
    
    zap_api_call('authentication', 'action', 'setLoggedInIndicator', 
                {'contextId': context_id, 'loggedInIndicatorRegex': 'logout|sign out|profile'})
    
    user_id = zap_api_call('users', 'action', 'newUser', 
                          {'contextId': context_id, 'name': username})['userId']
    
    zap_api_call('users', 'action', 'setUserEnabled', 
                {'contextId': context_id, 'userId': user_id, 'enabled': 'true'})
    
    auth_creds = f'username={username}&password={password}'
    zap_api_call('users', 'action', 'setAuthenticationCredentials', 
                {'contextId': context_id, 'userId': user_id, 'authCredentialsConfigParams': auth_creds})
    
    return {
        'context_id': context_id,
        'user_id': user_id
    }

def get_scan_results(target):
    alerts = zap_api_call('core', 'view', 'alerts', {'baseurl': target})
    
    focused_results = []
    for alert in alerts.get('alerts', []):
        focused_alert = {
            'name': alert.get('name', ''),
            'risk': alert.get('risk', ''),
            'url': alert.get('url', ''),
            'solution': alert.get('solution', '')
        }
        focused_results.append(focused_alert)
    
    risk_levels = {"High": 0, "Medium": 0, "Low": 0, "Informational": 0}
    for alert in focused_results:
        risk_levels[alert['risk']] += 1
    
    return {
        'alerts': focused_results,
        'summary': risk_levels
    }

def save_scan_results(target, scan_info, results, filename):
    output = {
        "scan_info": {
            "target": target,
            "scan_time": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            **scan_info
        },
        "vulnerability_summary": results['summary'],
        "vulnerabilities": results['alerts']
    }
    
    with open(filename, 'w') as f:
        json.dump(output, f, indent=4)
    
    return filename

def run_zap_scan(target, scan_types=None, spider_depth=5, use_auth=False, auth_info=None):
    if scan_types is None:
        scan_types = [1, 3, 4]  # Default to Spider, Active, and Passive scans
        
    scan_info = {}
    
    try:
        # First ensure the URL is in the scan tree
        ensure_url_in_context(target)
        
        if use_auth and auth_info:
            auth_result = setup_authentication(auth_info['url'], auth_info['username'], auth_info['password'])
            scan_info['authentication'] = auth_result
        
        if 1 in scan_types:
            print(f"Running spider scan for {target}")
            spider_result = run_spider_scan(target, spider_depth)
            scan_info['spider'] = spider_result
        
        if 2 in scan_types:
            print(f"Running AJAX spider scan for {target}")
            ajax_result = run_ajax_spider_scan(target)
            scan_info['ajax_spider'] = ajax_result
        
        if 4 in scan_types:
            print(f"Running passive scan for {target}")
            passive_result = run_passive_scan()
            scan_info['passive'] = passive_result
        
        if 3 in scan_types:
            print(f"Running active scan for {target}")
            active_result = run_active_scan(target)
            scan_info['active'] = active_result
        
        if 5 in scan_types:
            print(f"Running DOM XSS scan for {target}")
            dom_result = run_dom_xss_scan(target)
            scan_info['dom_xss'] = dom_result
        
        print(f"Gathering scan results for {target}")
        results = get_scan_results(target)
        
        # Return results without saving to file
        # Add a test alert for debugging
        if len(results['alerts']) == 0:
         print("No real alerts found, adding a test alert")
        results['alerts'].append({
        'name': 'Test Vulnerability',
        'risk': 'Low',
        'url': target,
        'solution': 'This is a test vulnerability added to verify the results display is working.'
    })
        results['summary']['Low'] += 1
        return {
            'scan_info': scan_info,
            'results': results
        }
    except Exception as e:
        import traceback
        print(f"Error during ZAP scan: {str(e)}")
        print(traceback.format_exc())
        # Return partial results if available
        try:
            results = get_scan_results(target)
            return {
                'scan_info': scan_info,
                'results': results,
                'error': str(e)
            }
        except:
            return {
                'scan_info': scan_info,
                'results': {"alerts": [], "summary": {"High": 0, "Medium": 0, "Low": 0, "Informational": 0}},
                'error': str(e)
            }

def test_zap_connection():
    try:
        version = zap_api_call('core', 'view', 'version')
        return True, version['version']
    except Exception as e:
        return False, str(e)

def get_scan_progress(scan_id=None, scan_type=None):
    """
    Get the current progress of a running scan
    
    Args:
        scan_id (str): The ID of the active scan (if checking active scan)
        scan_type (int): The type of scan to check progress for
        
    Returns:
        int: Percentage of scan completion (0-100)
    """
    try:
        if scan_type == 3:  # Active scan
            if scan_id:
                progress = zap_api_call('ascan', 'view', 'status', {'scanId': scan_id})
                return int(progress.get('status', 0))
            else:
                # Get the most recent scan if no ID provided
                return 50  # Default to 50% if no specific scan ID
                
        elif scan_type == 1:  # Spider scan
            if scan_id:
                progress = zap_api_call('spider', 'view', 'status', {'scanId': scan_id})
                return int(progress.get('status', 0))
            else:
                return 50
                
        elif scan_type == 2:  # Ajax spider
            status = zap_api_call('ajaxSpider', 'view', 'status')
            # Ajax spider doesn't have a percentage, just running/not running
            return 50 if status.get('running') == 'true' else 100
            
        elif scan_type == 4:  # Passive scan
            records = zap_api_call('pscan', 'view', 'recordsToScan')
            current = int(records.get('recordsToScan', 0))
            # Approximate progress based on records left to scan
            return 100 if current == 0 else min(95, max(0, 100 - current))
            
        elif scan_type == 5:  # DOM XSS scan
            # DOM XSS doesn't provide progress info, estimate based on time
            return 50  # Default to 50%
            
        return 50  # Default fallback
    except Exception as e:
        print(f"Error getting scan progress: {str(e)}")
        return 50  # Default on error