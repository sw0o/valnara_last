import requests
import time
from datetime import datetime

# WPScan API configuration
WPSCAN_API_URL = "https://wpscan.com/api/v3/scan"

def scan_wordpress_site(target_url, api_token):
    """
    Perform a WordPress security scan using WPScan API
    
    Args:
        target_url (str): The URL of the WordPress site to scan
        api_token (str): WPScan API token
        
    Returns:
        dict: Scan results in Valnara format
    """
    start_time = time.time()
    
    # Run the scan
    raw_results = call_wpscan_api(target_url, api_token)
    
    # Process the results
    processed_results = process_wpscan_results(raw_results, target_url)
    
    # Add duration information
    scan_duration = time.time() - start_time
    processed_results["scan_info"]["wordpress"]["duration"] = int(scan_duration)
    processed_results["scan_info"]["wordpress"]["duration_formatted"] = format_duration(scan_duration)
    
    return {
        "results": processed_results,
        "scan_info": {
            "6": processed_results["scan_info"]["wordpress"]
        }
    }

def call_wpscan_api(target_url, api_token):
    """
    Call the WPScan API to scan a WordPress site
    
    Args:
        target_url (str): The URL of the WordPress site to scan
        api_token (str): WPScan API token
        
    Returns:
        dict: Raw scan results from WPScan API
    """
    scan_options = {
        "enumerate": ["plugins", "themes", "users", "medias"],
        "check_vuln_api_token": True,
        "plugins_detection": {
            "mode": "passive"
        },
        "themes_detection": {
            "mode": "passive"
        }
    }
    
    payload = {
        "url": target_url,
        "api_token": api_token,
        "scan_mode": "passive",
        "scan_options": scan_options
    }
    
    headers = {
        'User-Agent': 'Valnara-Security-Scanner/1.0',
        'Content-Type': 'application/json'
    }
    
    print(f"Initiating WPScan API scan for {target_url}")
    
    try:
        response = requests.post(WPSCAN_API_URL, json=payload, headers=headers)
        response.raise_for_status()
        
        return response.json()
    except requests.exceptions.HTTPError as e:
        error_message = f"WPScan API HTTP error: {e}"
        if response.status_code == 401:
            error_message = "Invalid WPScan API token"
        elif response.status_code == 429:
            error_message = "WPScan API rate limit exceeded"
        print(error_message)
        return {"error": error_message}
    except requests.exceptions.RequestException as e:
        error_message = f"WPScan API request error: {str(e)}"
        print(error_message)
        return {"error": error_message}
    except Exception as e:
        error_message = f"WPScan API unexpected error: {str(e)}"
        print(error_message)
        return {"error": error_message}

def process_wpscan_results(scan_results, target_url):
    """
    Process the WPScan API results to match the format expected by Valnara scanner
    
    Args:
        scan_results (dict): Raw WPScan API results
        target_url (str): The URL that was scanned
        
    Returns:
        dict: Processed scan results in Valnara format
    """
    if "error" in scan_results:
        return {
            "alerts": [],
            "summary": {"High": 0, "Medium": 0, "Low": 0, "Informational": 0},
            "scan_info": {
                "wordpress": {
                    "duration": 0,
                    "duration_formatted": "00:00:00",
                    "error": scan_results["error"]
                }
            },
            "error": scan_results["error"]
        }
    
    # Initialize result structure
    processed_results = {
        "alerts": [],
        "summary": {"High": 0, "Medium": 0, "Low": 0, "Informational": 0},
        "scan_info": {
            "wordpress": {
                "duration": scan_results.get("elapsed_time", 0),
                "duration_formatted": format_duration(scan_results.get("elapsed_time", 0)),
                "wp_version": scan_results.get("wordpress", {}).get("version", {}).get("number", "Unknown")
            }
        }
    }
    
    # Process WordPress version vulnerabilities
    wp_version_data = scan_results.get("wordpress", {}).get("version", {})
    if wp_version_data and "vulnerabilities" in wp_version_data:
        for vuln in wp_version_data.get("vulnerabilities", []):
            alert = create_alert_from_vuln(
                vuln, 
                f"WordPress Core {wp_version_data.get('number', 'Unknown')}", 
                target_url, 
                "Update WordPress to the latest version."
            )
            processed_results["alerts"].append(alert)
            processed_results["summary"][alert["risk"]] += 1
    
    # Process plugin vulnerabilities
    for plugin_name, plugin_data in scan_results.get("plugins", {}).items():
        for vuln in plugin_data.get("vulnerabilities", []):
            alert = create_alert_from_vuln(
                vuln, 
                f"Plugin: {plugin_name} (v{plugin_data.get('version', {}).get('number', 'Unknown')})", 
                f"{target_url}/wp-content/plugins/{plugin_name}/", 
                f"Update {plugin_name} to the latest version or remove it if unused."
            )
            processed_results["alerts"].append(alert)
            processed_results["summary"][alert["risk"]] += 1
    
    # Process theme vulnerabilities
    for theme_name, theme_data in scan_results.get("themes", {}).items():
        for vuln in theme_data.get("vulnerabilities", []):
            alert = create_alert_from_vuln(
                vuln, 
                f"Theme: {theme_name} (v{theme_data.get('version', {}).get('number', 'Unknown')})", 
                f"{target_url}/wp-content/themes/{theme_name}/", 
                f"Update {theme_name} to the latest version or switch to a more secure theme."
            )
            processed_results["alerts"].append(alert)
            processed_results["summary"][alert["risk"]] += 1
    
    # Process user enumeration issues
    if "users" in scan_results and scan_results["users"]:
        user_alert = {
            "name": "WordPress User Enumeration Possible",
            "risk": "Medium",
            "url": f"{target_url}/?author=1",
            "solution": "Configure your site to prevent user enumeration by modifying .htaccess or using a security plugin."
        }
        processed_results["alerts"].append(user_alert)
        processed_results["summary"]["Medium"] += 1
    
    # Check for XML-RPC
    if scan_results.get("interesting_findings", {}).get("xmlrpc_file", {}).get("found", False):
        xmlrpc_alert = {
            "name": "XML-RPC Interface Enabled",
            "risk": "Medium",
            "url": f"{target_url}/xmlrpc.php",
            "solution": "Disable XML-RPC if not needed or restrict access to it through .htaccess."
        }
        processed_results["alerts"].append(xmlrpc_alert)
        processed_results["summary"]["Medium"] += 1
    
    # Add WordPress detection as informational finding
    if scan_results.get("wordpress", {}).get("version", {}).get("number"):
        wp_info_alert = {
            "name": f"WordPress {scan_results['wordpress']['version']['number']} Detected",
            "risk": "Informational",
            "url": target_url,
            "solution": "Keep WordPress core updated to the latest secure version."
        }
        processed_results["alerts"].append(wp_info_alert)
        processed_results["summary"]["Informational"] += 1
        
        # Add outdated WordPress warning if needed
        if not scan_results.get("wordpress", {}).get("version", {}).get("latest"):
            wp_outdated_alert = {
                "name": "Outdated WordPress Version",
                "risk": "Medium",
                "url": target_url,
                "solution": f"Update WordPress from version {scan_results['wordpress']['version']['number']} to the latest version."
            }
            processed_results["alerts"].append(wp_outdated_alert)
            processed_results["summary"]["Medium"] += 1
    
    return processed_results

def create_alert_from_vuln(vuln, name_prefix, url, solution_prefix):
    """
    Create a standardized alert object from a vulnerability
    
    Args:
        vuln (dict): Vulnerability data from WPScan
        name_prefix (str): Prefix for the vulnerability name
        url (str): URL associated with the vulnerability
        solution_prefix (str): Prefix for the solution text
        
    Returns:
        dict: Alert object in Valnara format
    """
    # Map CVSS scores to risk levels
    cvss_score = vuln.get("cvss", {}).get("score", 0)
    if cvss_score >= 7.0:
        risk = "High"
    elif cvss_score >= 4.0:
        risk = "Medium"
    elif cvss_score > 0:
        risk = "Low"
    else:
        risk = "Informational"
    
    references = []
    if vuln.get("references", {}).get("url"):
        references = vuln["references"]["url"]
    
    references_text = ""
    if references:
        references_text = "\n\nReferences:\n" + "\n".join([f"- {ref}" for ref in references[:3]])
    
    solution = f"{solution_prefix}"
    if vuln.get("fixed_in"):
        solution += f" Update to version {vuln['fixed_in']} or later."
    
    return {
        "name": f"{name_prefix} - {vuln.get('title', 'Unknown Vulnerability')}",
        "risk": risk,
        "url": url,
        "solution": solution + references_text
    }

def format_duration(seconds):
    """
    Format seconds into HH:MM:SS string
    
    Args:
        seconds (float): Duration in seconds
        
    Returns:
        str: Formatted duration string
    """
    hours, remainder = divmod(int(seconds), 3600)
    minutes, seconds = divmod(remainder, 60)
    return f"{hours:02d}:{minutes:02d}:{seconds:02d}"