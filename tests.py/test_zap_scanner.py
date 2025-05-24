import unittest
import sys
import os
import time
from unittest.mock import patch, Mock
from datetime import datetime

# Add the project root to the Python path
sys.path.insert(0, os.path.abspath(os.path.dirname(os.path.dirname(__file__))))

from modules.zap_scanner import run_zap_scan, get_scan_results

class TestZAPVulnerabilityDetection(unittest.TestCase):
    """Test suite for ZAP vulnerability detection."""

    def test_zap_vulnerability_detection(self):
        """Test ZAP vulnerability detection against non-CMS websites."""
        
        # Define test targets with known vulnerabilities
        test_targets = [
            "https://demo.testfire.net/",
            "http://testphp.vulnweb.com/",
            "https://public-firing-range.appspot.com/"
        ]
        
        # Define vulnerability types to track
        vulnerability_types = {
            "SQL Injection": {"known": 12, "detected": 0},
            "XSS": {"known": 18, "detected": 0},
            "CSRF": {"known": 8, "detected": 0},
            "File Inclusion": {"known": 7, "detected": 0},
            "Authentication Flaws": {"known": 10, "detected": 0},
            "Configuration Issues": {"known": 15, "detected": 0}
        }
        
        # Run scans on test targets
        for target in test_targets:
            try:
                print(f"\nScanning target: {target}")
                start_time = time.time()
                
                # Run the ZAP scan with only spider and passive scans (no AJAX or active scans)
                scan_result = run_zap_scan(
                    target=target,
                    scan_types=[1, 4],  # 1=Spider, 4=Passive scan (no 2=AJAX spider or 3=Active scan)
                    spider_depth=3
                )
                
                scan_duration = time.time() - start_time
                print(f"Scan completed in {scan_duration:.2f} seconds")
                
                # Process scan results
                if 'results' in scan_result and 'alerts' in scan_result['results']:
                    alerts = scan_result['results']['alerts']
                    print(f"Found {len(alerts)} alerts")
                    
                    # Categorize vulnerabilities
                    for alert in alerts:
                        name = alert.get('name', '').lower()
                        
                        # Categorize by vulnerability type
                        if any(x in name for x in ['sql', 'injection', 'sqli']):
                            vulnerability_types["SQL Injection"]["detected"] += 1
                        elif any(x in name for x in ['xss', 'cross site', 'cross-site scripting']):
                            vulnerability_types["XSS"]["detected"] += 1
                        elif any(x in name for x in ['csrf', 'cross site request forgery']):
                            vulnerability_types["CSRF"]["detected"] += 1
                        elif any(x in name for x in ['file inclusion', 'path traversal', 'lfi', 'rfi']):
                            vulnerability_types["File Inclusion"]["detected"] += 1
                        elif any(x in name for x in ['auth', 'authentication', 'password', 'credential']):
                            vulnerability_types["Authentication Flaws"]["detected"] += 1
                        elif any(x in name for x in ['config', 'misconfiguration', 'header', 'certificate', 'ssl', 'tls']):
                            vulnerability_types["Configuration Issues"]["detected"] += 1
            
            except Exception as e:
                print(f"Error scanning {target}: {str(e)}")
        
        # Print first results table
        print("\n" + "="*80)
        print("4.4.2 ZAP Vulnerability Detection: Testing against non-CMS websites")
        print("with known vulnerabilities produced the following results:")
        print("="*80)
        print("{:<25} {:<20} {:<15} {:<15}".format(
            "Vulnerability Type", "Known Vulnerabilities", "Detected", "Detection Rate"))
        print("-"*80)
        
        # First table: SQL Injection, XSS, CSRF
        first_table_types = ["SQL Injection", "XSS", "CSRF"]
        for vuln_type in first_table_types:
            known = vulnerability_types[vuln_type]["known"]
            detected = vulnerability_types[vuln_type]["detected"]
            rate = (detected / known * 100) if known > 0 else 0
            
            print("{:<25} {:<20} {:<15} {:.2f}%".format(
                vuln_type, known, detected, rate
            ))
        
        print("\nZap Vulnerability Detection Result table (4.5)")
        
        # Second table: File Inclusion, Authentication Flaws, Configuration Issues
        print("\n" + "-"*80)
        second_table_types = ["File Inclusion", "Authentication Flaws", "Configuration Issues"]
        for vuln_type in second_table_types:
            known = vulnerability_types[vuln_type]["known"]
            detected = vulnerability_types[vuln_type]["detected"]
            rate = (detected / known * 100) if known > 0 else 0
            
            print("{:<25} {:<20} {:<15} {:.2f}%".format(
                vuln_type, known, detected, rate
            ))
        
        print("-"*80)
        
        # Return the results for use in other tests if needed
        return vulnerability_types


if __name__ == '__main__':
    unittest.main()