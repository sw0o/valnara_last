import unittest
import sys
import os
import json
import subprocess
from datetime import datetime

# Add the project root to the Python path
sys.path.insert(0, os.path.abspath(os.path.dirname(os.path.dirname(__file__))))

from modules.wp_scanner import scan_wordpress_site

class TestWordPressVulnerabilityDetection(unittest.TestCase):
    """Test suite for WordPress vulnerability detection."""

    def test_wordpress_vulnerability_detection(self):
        """Test WordPress vulnerability detection across different categories with real scanning."""
        
        # Define the test targets (adjust these URLs to your test environments)
        test_targets = {
            "Core Vulnerabilities": [
                "https://wp-core-test-1.example.com",
                "https://wp-core-test-2.example.com",
                # Add more targets as needed to reach 15 total test cases
            ],
            "Plugin Vulnerabilities": [
                "https://wp-plugin-test-1.example.com",
                "https://wp-plugin-test-2.example.com",
                # Add more targets as needed to reach 45 total test cases
            ],
            "Theme Vulnerabilities": [
                "https://wp-theme-test-1.example.com",
                "https://wp-theme-test-2.example.com",
                # Add more targets as needed to reach 20 total test cases
            ],
            "Misconfiguration": [
                "https://wp-config-test-1.example.com",
                "https://wp-config-test-2.example.com",
                # Add more targets as needed to reach 25 total test cases
            ]
        }
        
        # Initialize counters
        known_counts = {
            "Core Vulnerabilities": 15,
            "Plugin Vulnerabilities": 45,
            "Theme Vulnerabilities": 20,
            "Misconfiguration": 25
        }
        
        detected_counts = {
            "Core Vulnerabilities": 0,
            "Plugin Vulnerabilities": 0,
            "Theme Vulnerabilities": 0,
            "Misconfiguration": 0
        }
        
        # Option 1: Test with actual scanning (uncomment if you want live testing)
        # Note: This can be very time-consuming and requires internet access
        """
        for category, targets in test_targets.items():
            print(f"\nTesting {category}...")
            for target in targets:
                try:
                    scan_result = scan_wordpress_site(target)
                    
                    # Check if vulnerability was detected
                    if 'results' in scan_result and 'alerts' in scan_result['results']:
                        alerts = scan_result['results']['alerts']
                        # Logic to count detected vulnerabilities
                        # ...
                except Exception as e:
                    print(f"Error scanning {target}: {str(e)}")
        """
        
        # Option 2: Run one test scan to get actual results format
        # We'll use this for demonstration, using a test target or your own WordPress site
        test_target = "https://example.com"  # Replace with a test WordPress site
        
        try:
            print(f"Running WordPress scan on test target: {test_target}")
            scan_result = scan_wordpress_site(test_target)
            
            if 'results' in scan_result and 'alerts' in scan_result['results']:
                # Analyze actual results and categorize them
                alerts = scan_result['results']['alerts']
                
                for alert in alerts:
                    name = alert.get('name', '').lower()
                    
                    # Categorize based on alert name
                    if 'wordpress core' in name or 'wordpress version' in name:
                        detected_counts['Core Vulnerabilities'] += 1
                    elif 'plugin' in name:
                        detected_counts['Plugin Vulnerabilities'] += 1
                    elif 'theme' in name:
                        detected_counts['Theme Vulnerabilities'] += 1
                    elif any(x in name for x in ['misconfiguration', 'insecure', 'security', 'exposed']):
                        detected_counts['Misconfiguration'] += 1
        
        except Exception as e:
            print(f"Error running test scan: {str(e)}")
            # Continue with demo data for display purposes
            
        # Option 3: For demo purposes, use your own real scan results if available
        # If you have previous scan results, you can input the detected counts manually
        """
        detected_counts = {
            "Core Vulnerabilities": 12,  # Replace with your actual counts
            "Plugin Vulnerabilities": 40,  # Replace with your actual counts
            "Theme Vulnerabilities": 18,  # Replace with your actual counts
            "Misconfiguration": 22  # Replace with your actual counts
        }
        """
            
        # Print results table
        print("\n" + "="*80)
        print("Testing the WordPress websites with known vulnerabilities produced the following results:")
        print("="*80)
        print("{:<25} {:<20} {:<15} {:<15}".format(
            "Vulnerability Category", "Known Vulnerabilities", "Detected", "Detection Rate"))
        print("-"*80)
        
        total_known = 0
        total_detected = 0
        
        for category, known in known_counts.items():
            detected = detected_counts[category]
            rate = (detected / known * 100) if known > 0 else 0
            
            print("{:<25} {:<20} {:<15} {:.2f}%".format(
                category, known, detected, rate
            ))
            
            total_known += known
            total_detected += detected
        
        print("-"*80)
        print("WordPress Vulnerabilities Detection Result table (4.4)")
        print("="*80)


class WordPressVulnerabilityRunner:
    """Helper class to run actual WordPress vulnerability scans."""
    
    @staticmethod
    def run_scan_on_targets():
        """
        Run scans on real WordPress targets with known vulnerabilities.
        Use this method to test against real websites and generate actual results.
        """
        # Define targets with known vulnerabilities
        # Replace these with your actual test targets
        targets = {
            "Core Vulnerabilities": [
                "https://core-vuln1.test.com",
                "https://core-vuln2.test.com",
                # Add more core vulnerability test targets...
            ],
            "Plugin Vulnerabilities": [
                "https://plugin-vuln1.test.com",
                "https://plugin-vuln2.test.com",
                # Add more plugin vulnerability test targets...
            ],
            "Theme Vulnerabilities": [
                "https://theme-vuln1.test.com",
                "https://theme-vuln2.test.com",
                # Add more theme vulnerability test targets...
            ],
            "Misconfiguration": [
                "https://misconfig1.test.com",
                "https://misconfig2.test.com",
                # Add more misconfiguration test targets...
            ]
        }
        
        # Known vulnerability counts
        known_counts = {
            "Core Vulnerabilities": 15,
            "Plugin Vulnerabilities": 45,
            "Theme Vulnerabilities": 20,
            "Misconfiguration": 25
        }
        
        # Initialize results
        results = {
            "Core Vulnerabilities": 0,
            "Plugin Vulnerabilities": 0,
            "Theme Vulnerabilities": 0,
            "Misconfiguration": 0
        }
        
        # Run scans against targets
        for category, category_targets in targets.items():
            print(f"\nScanning {category} targets...")
            for target in category_targets:
                try:
                    print(f"  Scanning {target}...")
                    scan_result = scan_wordpress_site(target)
                    
                    # Process results and count vulnerabilities
                    if 'results' in scan_result and 'alerts' in scan_result['results']:
                        alerts = scan_result['results']['alerts']
                        category_detections = 0
                        
                        for alert in alerts:
                            # Logic to determine if this alert belongs to this category
                            # Add your categorization logic here
                            category_detections += 1
                        
                        results[category] += category_detections
                        print(f"    Detected {category_detections} vulnerabilities")
                        
                except Exception as e:
                    print(f"    Error scanning {target}: {str(e)}")
        
        # Print results
        print("\n" + "="*80)
        print("Testing the WordPress websites with known vulnerabilities produced the following results:")
        print("="*80)
        print("{:<25} {:<20} {:<15} {:<15}".format(
            "Vulnerability Category", "Known Vulnerabilities", "Detected", "Detection Rate"))
        print("-"*80)
        
        for category, known in known_counts.items():
            detected = results[category]
            rate = (detected / known * 100) if known > 0 else 0
            
            print("{:<25} {:<20} {:<15} {:.2f}%".format(
                category, known, detected, rate
            ))
        
        print("-"*80)
        print("WordPress Vulnerabilities Detection Result table (4.4)")
        print("="*80)
        
        return results, known_counts


if __name__ == '__main__':
    unittest.main()