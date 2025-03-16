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

def run_spider_scan(target, max_depth=5):
    start_time = time.time()
    
    zap_api_call('spider', 'action', 'setOptionMaxDepth', {'Integer': str(max_depth)})
    
    scan_result = zap_api_call('spider', 'action', 'scan', {'url': target})
    scan_id = scan_result['scan']
    
    while True:
        progress = zap_api_call('spider', 'view', 'status', {'scanId': scan_id})
        current = int(progress['status'])
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
    
    params = {'url': target}
    if scan_policy:
        params['scanPolicyName'] = scan_policy
    
    scan_result = zap_api_call('ascan', 'action', 'scan', params)
    scan_id = scan_result['scan']
    
    while True:
        progress = zap_api_call('ascan', 'view', 'status', {'scanId': scan_id})
        current = int(progress['status'])
        if current >= 100:
            break
        time.sleep(5)
    
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
    for alert in alerts['alerts']:
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

def run_zap_scan(target, scan_types=None, spider_depth=5, use_auth=False, auth_info=None, output_file="zap_results.json"):
    if scan_types is None:
        scan_types = [1, 3, 4]  # Default to Spider, Active, and Passive scans
        
    scan_info = {}
    
    if use_auth and auth_info:
        auth_result = setup_authentication(auth_info['url'], auth_info['username'], auth_info['password'])
        scan_info['authentication'] = auth_result
    
    if 1 in scan_types:
        spider_result = run_spider_scan(target, spider_depth)
        scan_info['spider'] = spider_result
    
    if 2 in scan_types:
        ajax_result = run_ajax_spider_scan(target)
        scan_info['ajax_spider'] = ajax_result
    
    if 4 in scan_types:
        passive_result = run_passive_scan()
        scan_info['passive'] = passive_result
    
    if 3 in scan_types:
        active_result = run_active_scan(target)
        scan_info['active'] = active_result
    
    if 5 in scan_types:
        dom_result = run_dom_xss_scan(target)
        scan_info['dom_xss'] = dom_result
    
    results = get_scan_results(target)
    
    if output_file:
        save_scan_results(target, scan_info, results, output_file)
    
    return {
        'scan_info': scan_info,
        'results': results
    }

def test_zap_connection():
    try:
        version = zap_api_call('core', 'view', 'version')
        return True, version['version']
    except Exception as e:
        return False, str(e)