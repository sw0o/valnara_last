import os
import sys
import csv
import time
import random
import psutil
import subprocess
from datetime import datetime

# Add the project root directory to Python path
project_root = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', '..'))
sys.path.insert(0, project_root)

# Now import your application modules
from app import app
from modules.url_validator import validate_url, normalize_url
from modules.zap_scanner import run_zap_scan
from modules.cms_detector import is_wordpress

class StabilityTester:
    def __init__(self, 
                 test_duration_hours=6, 
                 scan_interval_minutes=10, 
                 results_dir='stability_results'):
        """
        Initialize the stability tester
        
        :param test_duration_hours: Total hours to run the test
        :param scan_interval_minutes: Time between starting new scans
        :param results_dir: Directory to store test results
        """
        self.test_duration_hours = test_duration_hours
        self.scan_interval_minutes = scan_interval_minutes
        self.results_dir = results_dir
        
        # Ensure results directory exists
        os.makedirs(self.results_dir, exist_ok=True)
        
        # Predefined test targets (mix of real and test sites)
        self.test_targets = [
            'http://example.com',
            'http://wordpress.org',
            'http://www.vulnerablesite.com',  # Replace with actual test sites
            'https://owasp.org',
            'http://testphp.vulnweb.com',
            'https://demo.testfire.net'
        ]
        
        # Predefined scan types
        self.scan_types = [
            [4],  # Passive scan
            [1],  # Spider scan
            [3],  # Active scan
            [1, 3],  # Combined spider and active
            [5]   # DOM XSS scan
        ]
        
        # Results file
        self.results_csv_path = os.path.join(
            self.results_dir, 
            f'stability_test_{datetime.now().strftime("%Y%m%d_%H%M%S")}.csv'
        )
        
    def _record_system_metrics(self, process=None):
        """
        Record system metrics
        
        :param process: Optional process to monitor
        :return: Dictionary of system metrics
        """
        metrics = {
            'timestamp': datetime.now().isoformat(),
            'cpu_percent': psutil.cpu_percent(),
            'memory_total': psutil.virtual_memory().total,
            'memory_available': psutil.virtual_memory().available,
            'memory_used_percent': psutil.virtual_memory().percent
        }
        
        if process:
            try:
                metrics.update({
                    'process_memory_rss': process.memory_info().rss,
                    'process_memory_vms': process.memory_info().vms,
                    'process_cpu_percent': process.cpu_percent()
                })
            except Exception as e:
                metrics.update({
                    'process_memory_error': str(e)
                })
        
        return metrics
    
    def run_single_scan(self, target, scan_types):
        """
        Run a single scan with error handling and performance tracking
        
        :param target: URL to scan
        :param scan_types: List of scan type integers
        :return: Scan result dictionary
        """
        start_time = time.time()
        scan_result = {
            'target': target,
            'scan_types': scan_types,
            'start_time': datetime.now().isoformat(),
            'status': 'failed',
            'duration': 0,
            'error': None
        }
        
        try:
            # Validate URL first
            if not validate_url(target):
                scan_result['error'] = 'Invalid URL'
                return scan_result
            
            # Run ZAP scan
            zap_result = run_zap_scan(target, scan_types)
            
            # Update scan result
            scan_result['status'] = 'completed'
            scan_result['results_summary'] = zap_result.get('results', {}).get('summary', {})
        
        except Exception as e:
            scan_result['error'] = str(e)
            scan_result['status'] = 'error'
        
        finally:
            # Calculate duration
            scan_result['duration'] = time.time() - start_time
            scan_result['end_time'] = datetime.now().isoformat()
        
        return scan_result
    
    def run_stability_test(self):
        """
        Run comprehensive stability test
        """
        # Prepare CSV results file
        csv_headers = [
            'timestamp', 'target', 'scan_types', 'status', 'duration', 
            'error', 'cpu_percent', 'memory_used_percent', 
            'high_risks', 'medium_risks', 'low_risks', 'info_risks'
        ]
        
        with open(self.results_csv_path, 'w', newline='') as csvfile:
            csvwriter = csv.DictWriter(csvfile, fieldnames=csv_headers)
            csvwriter.writeheader()
            
            # Track test start time
            test_start_time = time.time()
            
            # Counter for total scans
            scan_count = 0
            
            while time.time() - test_start_time < (self.test_duration_hours * 3600):
                # Randomly select target and scan type
                target = random.choice(self.test_targets)
                scan_type = random.choice(self.scan_types)
                
                print(f"Running scan {scan_count + 1}: {target} with types {scan_type}")
                
                # Run scan
                scan_result = self.run_single_scan(target, scan_type)
                
                # Collect system metrics
                system_metrics = self._record_system_metrics()
                
                # Combine scan and system metrics
                full_result = {
                    'timestamp': system_metrics['timestamp'],
                    'target': scan_result['target'],
                    'scan_types': str(scan_result.get('scan_types', [])),
                    'status': scan_result['status'],
                    'duration': scan_result['duration'],
                    'error': scan_result.get('error', ''),
                    'cpu_percent': system_metrics['cpu_percent'],
                    'memory_used_percent': system_metrics['memory_used_percent'],
                    'high_risks': scan_result.get('results_summary', {}).get('High', 0),
                    'medium_risks': scan_result.get('results_summary', {}).get('Medium', 0),
                    'low_risks': scan_result.get('results_summary', {}).get('Low', 0),
                    'info_risks': scan_result.get('results_summary', {}).get('Informational', 0)
                }
                
                # Write to CSV
                with open(self.results_csv_path, 'a', newline='') as csvfile:
                    csvwriter = csv.DictWriter(csvfile, fieldnames=csv_headers)
                    csvwriter.writerow(full_result)
                
                # Increment scan count
                scan_count += 1
                
                # Wait before next scan
                time.sleep(self.scan_interval_minutes * 60)
        
        print(f"Stability test completed. Total scans: {scan_count}")
        print(f"Results saved to: {self.results_csv_path}")
        
        return self.results_csv_path

def main():
    # Create stability tester
    tester = StabilityTester(
        test_duration_hours=6,  # 6-hour test
        scan_interval_minutes=10  # 10 minutes between scans
    )
    
    # Run stability test
    results_file = tester.run_stability_test()
    
    # Optional: Generate a quick summary report
    print("\nStability Test Summary")
    print("-" * 30)
    with open(results_file, 'r') as f:
        reader = csv.DictReader(f)
        results = list(reader)
        
        # Basic stats
        total_scans = len(results)
        successful_scans = sum(1 for r in results if r['status'] == 'completed')
        failed_scans = sum(1 for r in results if r['status'] != 'completed')
        
        print(f"Total Scans: {total_scans}")
        print(f"Successful Scans: {successful_scans}")
        print(f"Failed Scans: {failed_scans}")
        print(f"Success Rate: {successful_scans/total_scans*100:.2f}%")

if __name__ == '__main__':
    main()