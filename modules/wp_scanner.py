import requests
import time
import re

def scan_wordpress_site(target_url, *args):
    start_time = time.time()
    
    results = {
        "alerts": [],
        "summary": {"High": 0, "Medium": 0, "Low": 0, "Informational": 0},
        "scan_info": {
            "wordpress": {
                "duration": 0,
                "duration_formatted": "00:00:00",
                "wp_version": "Unknown"
            }
        }
    }
    
    try:
        # Fetch latest WordPress version from GitHub releases
        releases_url = "https://api.github.com/repos/WordPress/WordPress/releases"
        releases_response = requests.get(releases_url, timeout=10)
        releases = releases_response.json()
        
        # Safety check for empty releases list
        if not releases:
            results["alerts"].append({
                "name": "Version Check Failed",
                "risk": "Medium",
                "url": target_url,
                "solution": "Unable to fetch latest WordPress version"
            })
            results["summary"]["Medium"] += 1
        else:
            # Take the first release (typically the latest)
            latest_release = releases[0]
            latest_version = latest_release.get('tag_name', 'Unknown').lstrip('v')
            
            # Version detection alert
            results["alerts"].append({
                "name": f"Latest WordPress Version: {latest_version}",
                "risk": "Informational",
                "url": target_url,
                "solution": "Monitor WordPress updates"
            })
            results["summary"]["Informational"] += 1
        
        # Generic WordPress security recommendations
        generic_alerts = [
            {
                "name": "Potential Plugin Vulnerabilities",
                "risk": "Medium",
                "url": target_url,
                "solution": "Regularly update all WordPress plugins and themes"
            },
            {
                "name": "Potential Authentication Risks",
                "risk": "Low",
                "url": target_url,
                "solution": "Use strong passwords, limit login attempts, use two-factor authentication"
            }
        ]
        
        for alert in generic_alerts:
            results["alerts"].append(alert)
            results["summary"][alert["risk"]] += 1
    
    except Exception as e:
        # Comprehensive error handling
        results["alerts"].append({
            "name": "WordPress Scan Error",
            "risk": "High",
            "url": target_url,
            "solution": f"Scan encountered an unexpected error: {str(e)}"
        })
        results["summary"]["High"] += 1
    
    # Calculate and format duration
    scan_duration = time.time() - start_time
    results["scan_info"]["wordpress"]["duration"] = int(scan_duration)
    results["scan_info"]["wordpress"]["duration_formatted"] = format_duration(scan_duration)
    
    return {
        "results": results,
        "scan_info": {
            "6": results["scan_info"]["wordpress"]
        }
    }

def format_duration(seconds):
    """Format duration in HH:MM:SS format"""
    hours, remainder = divmod(int(seconds), 3600)
    minutes, seconds = divmod(remainder, 60)
    return f"{hours:02d}:{minutes:02d}:{seconds:02d}"