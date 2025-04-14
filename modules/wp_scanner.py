import subprocess
import json
import time
import os
import re
from pathlib import Path

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
        output_dir = Path(os.getcwd()) / "scan_results"
        output_dir.mkdir(exist_ok=True)
        output_file = output_dir / f"wpscan_{int(start_time)}.json"
        
        cmd = [
            "wpscan", 
            "--url", target_url,
            "--format", "json",
            "--output", str(output_file),
            "--disable-tls-checks",
            "--random-user-agent"
        ]
        
        cmd.extend(["--enumerate", "vp,vt"])
        
        print(f"Executing WPScan command: {' '.join(cmd)}")
        
        process = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=600,
            env={**os.environ, "LANG": "C.UTF-8"}
        )
        
        if process.returncode != 0:
            error_msg = process.stderr or process.stdout or "Unknown error"
            print(f"WPScan error: {error_msg}")
            
            try:
                version_check = subprocess.run(
                    ["wpscan", "--version"], 
                    capture_output=True, 
                    text=True
                )
                if version_check.returncode != 0:
                    results["alerts"].append({
                        "name": "WPScan Not Installed",
                        "risk": "High",
                        "url": target_url,
                        "solution": "WPScan is not properly installed. Install it with: sudo gem install wpscan"
                    })
                else:
                    results["alerts"].append({
                        "name": "WPScan Error",
                        "risk": "High",
                        "url": target_url,
                        "solution": f"WPScan failed. Error: {error_msg[:200]}..."
                    })
            except:
                results["alerts"].append({
                    "name": "WPScan Error",
                    "risk": "High",
                    "url": target_url,
                    "solution": f"WPScan failed. Make sure it's installed with: sudo gem install wpscan"
                })
            
            results["summary"]["High"] += 1
        else:
            if output_file.exists():
                try:
                    with open(output_file, 'r') as f:
                        wpscan_data = json.load(f)
                    
                    if "wordpress" in wpscan_data and "version" in wpscan_data["wordpress"]:
                        version_info = wpscan_data["wordpress"]["version"]
                        wp_version = version_info.get("number", "Unknown")
                        results["scan_info"]["wordpress"]["wp_version"] = wp_version
                        
                        version_alert = {
                            "name": f"WordPress {wp_version} Detected",
                            "risk": "Informational",
                            "url": target_url,
                            "solution": "Keep WordPress core updated to the latest secure version."
                        }
                        
                        if version_info.get("status") == "insecure":
                            version_alert["risk"] = "High"
                            version_alert["name"] = f"Insecure WordPress Version: {wp_version}"
                            version_alert["solution"] = "Update WordPress immediately to the latest version."
                            results["summary"]["High"] += 1
                        else:
                            results["summary"]["Informational"] += 1
                            
                        results["alerts"].append(version_alert)
                    
                    if "plugins" in wpscan_data:
                        for plugin_name, plugin_data in wpscan_data["plugins"].items():
                            process_plugin(plugin_name, plugin_data, results, target_url)
                    
                    if "themes" in wpscan_data:
                        for theme_name, theme_data in wpscan_data["themes"].items():
                            process_theme(theme_name, theme_data, results, target_url)
                    
                    if "interesting_findings" in wpscan_data:
                        if isinstance(wpscan_data["interesting_findings"], dict):
                            findings_to_process = wpscan_data["interesting_findings"].values()
                        else:
                          findings_to_process = wpscan_data["interesting_findings"]

                        for finding in findings_to_process:
                            process_finding(finding, results, target_url)
                    
                    if len(results["alerts"]) < 3:
                        add_generic_recommendations(results, target_url)
                
                except json.JSONDecodeError:
                    print(f"Error: WPScan output is not valid JSON")
                    results["alerts"].append({
                        "name": "WPScan Output Error",
                        "risk": "Medium",
                        "url": target_url,
                        "solution": "WPScan completed but produced invalid output. Check WPScan installation."
                    })
                    results["summary"]["Medium"] += 1
            else:
                print(f"Error: WPScan output file not found at {output_file}")
                results["alerts"].append({
                    "name": "WPScan Output Missing",
                    "risk": "Medium",
                    "url": target_url,
                    "solution": "WPScan ran successfully but didn't produce output file. Check disk permissions."
                })
                results["summary"]["Medium"] += 1
    
    except subprocess.TimeoutExpired:
        print(f"Error: WPScan timed out after 10 minutes")
        results["alerts"].append({
            "name": "WPScan Timeout",
            "risk": "Medium",
            "url": target_url,
            "solution": "The scan took too long and was terminated. Try a more focused scan or check site responsiveness."
        })
        results["summary"]["Medium"] += 1
    
    except Exception as e:
        import traceback
        print(f"WordPress scan error: {str(e)}")
        print(traceback.format_exc())
        results["alerts"].append({
            "name": "WordPress Scan Error",
            "risk": "High",
            "url": target_url,
            "solution": f"Scan encountered an unexpected error: {str(e)}"
        })
        results["summary"]["High"] += 1
    
    scan_duration = time.time() - start_time
    results["scan_info"]["wordpress"]["duration"] = int(scan_duration)
    results["scan_info"]["wordpress"]["duration_formatted"] = format_duration(scan_duration)
    
    if not results["alerts"]:
        results["alerts"].append({
            "name": "No WordPress Issues Found",
            "risk": "Informational",
            "url": target_url,
            "solution": "No specific issues were identified. Continue maintaining good security practices."
        })
        results["summary"]["Informational"] += 1
    
    return {
        "results": results,
        "scan_info": {
            "6": results["scan_info"]["wordpress"]
        }
    }
    # Scans a WordPress site using WPScan and returns formatted results

def process_plugin(plugin_name, plugin_data, results, target_url):
    if "vulnerabilities" in plugin_data and plugin_data["vulnerabilities"]:
        for vuln in plugin_data["vulnerabilities"]:
            risk = "High"
            if "cvss" in vuln:
                cvss_score = float(vuln.get("cvss", {}).get("score", 0))
                if cvss_score >= 9.0:
                    risk = "High"
                elif cvss_score >= 7.0:
                    risk = "High"
                elif cvss_score >= 4.0:
                    risk = "Medium"
                else:
                    risk = "Low"
            
            version_text = f"(v{plugin_data.get('version', {}).get('number', 'unknown')})"
            vuln_title = vuln.get("title", "Vulnerability")
            
            results["alerts"].append({
                "name": f"Plugin: {plugin_name} {version_text} - {vuln_title}",
                "risk": risk,
                "url": f"{target_url}/wp-content/plugins/{plugin_name}/",
                "solution": vuln.get("fixed_in", "Update the plugin to the latest version or remove it if unused.")
            })
            results["summary"][risk] += 1
    elif "version" in plugin_data:
        results["alerts"].append({
            "name": f"Plugin: {plugin_name} (v{plugin_data['version'].get('number', 'unknown')})",
            "risk": "Informational",
            "url": f"{target_url}/wp-content/plugins/{plugin_name}/",
            "solution": "Keep plugins updated to the latest versions."
        })
        results["summary"]["Informational"] += 1
    # Processes plugin information and adds findings to results

def process_theme(theme_name, theme_data, results, target_url):
    if "vulnerabilities" in theme_data and theme_data["vulnerabilities"]:
        for vuln in theme_data["vulnerabilities"]:
            risk = "High"
            if "cvss" in vuln:
                cvss_score = float(vuln.get("cvss", {}).get("score", 0))
                if cvss_score >= 9.0:
                    risk = "High"
                elif cvss_score >= 7.0:
                    risk = "High"
                elif cvss_score >= 4.0:
                    risk = "Medium"
                else:
                    risk = "Low"
            
            version_text = f"(v{theme_data.get('version', {}).get('number', 'unknown')})"
            vuln_title = vuln.get("title", "Vulnerability")
            
            results["alerts"].append({
                "name": f"Theme: {theme_name} {version_text} - {vuln_title}",
                "risk": risk,
                "url": f"{target_url}/wp-content/themes/{theme_name}/",
                "solution": vuln.get("fixed_in", "Update the theme to the latest version or switch to a more secure theme.")
            })
            results["summary"][risk] += 1
    # Processes theme information and adds findings to results

def process_finding(finding, results, target_url):
    finding_type = finding.get("type", "")
    finding_url = finding.get("url", target_url)
    
    risk_mappings = {
        "debug_log": "Medium",
        "emergency_pwd_reset_script": "High",
        "upload_directory_listing": "Medium",
        "multisite": "Informational",
        "registration_enabled": "Low",
        "xml_rpc": "Medium",
        "readme_html": "Low",
        "duplicator_installer_log": "High"
    }
    
    risk = risk_mappings.get(finding_type, "Informational")
    
    alert = {
        "name": finding.get("to_s", "Interesting Finding"),
        "risk": risk,
        "url": finding_url,
        "solution": finding.get("references", {}).get("url", "Investigate and secure this issue based on best practices.")
    }
    
    if finding_type == "debug_log":
        alert["solution"] = "Remove or secure debug.log files. They can expose sensitive information."
    elif finding_type == "emergency_pwd_reset_script":
        alert["solution"] = "Remove the emergency password reset script immediately after use."
    elif finding_type == "upload_directory_listing":
        alert["solution"] = "Disable directory listing in your uploads folder using .htaccess or web server configuration."
    elif finding_type == "xml_rpc":
        alert["solution"] = "Disable XML-RPC if not needed or restrict access to it through .htaccess."
    elif finding_type == "readme_html":
        alert["solution"] = "Remove or restrict access to readme.html to avoid exposing WordPress version."
    
    results["alerts"].append(alert)
    results["summary"][risk] += 1
    # Processes interesting findings and adds them to results

def add_generic_recommendations(results, target_url):
    recommendations = [
        {
            "name": "WordPress Security Best Practices",
            "risk": "Informational",
            "url": target_url,
            "solution": "Implement security best practices: regular updates, strong passwords, security plugins, and file permissions review."
        },
        {
            "name": "Potential Authentication Risks",
            "risk": "Low",
            "url": target_url,
            "solution": "Use strong passwords, limit login attempts, and implement two-factor authentication."
        }
    ]
    
    for rec in recommendations:
        results["alerts"].append(rec)
        results["summary"][rec["risk"]] += 1
    # Adds generic security recommendations when few findings are detected

def format_duration(seconds):
    hours, remainder = divmod(int(seconds), 3600)
    minutes, seconds = divmod(remainder, 60)
    return f"{hours:02d}:{minutes:02d}:{seconds:02d}"
    # Formats duration in HH:MM:SS format