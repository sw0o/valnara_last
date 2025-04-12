#!/usr/bin/env python3
"""
Valnara Security Scanner Test Runner
Run all unit tests and generate a comprehensive test report
"""

import os
import sys
import unittest
import time
import datetime
import coverage
from contextlib import contextmanager
import io
import importlib
import argparse

# Add project root to path
sys.path.insert(0, os.path.abspath(os.path.dirname(__file__)))

# Import test modules
# Import test modules directly
import test_validators
import test_database_operations
import test_cms_detector
import test_report_generator
import test_wp_scanner
import test_zap_scanner
import test_app_routes
import test_integration

@contextmanager
def capture_stdout():
    """Capture stdout for tests."""
    new_out = io.StringIO()
    old_out = sys.stdout
    try:
        sys.stdout = new_out
        yield new_out
    finally:
        sys.stdout = old_out

def run_test_suite(test_class, verbose=False):
    """Run a test suite and return results."""
    start_time = time.time()
    
    with capture_stdout() as output:
        loader = unittest.TestLoader()
        suite = loader.loadTestsFromTestCase(test_class)
        
        runner = unittest.TextTestRunner(
            verbosity=2 if verbose else 1, 
            stream=sys.stdout
        )
        result = runner.run(suite)
    
    end_time = time.time()
    
    return {
        'name': test_class.__name__,
        'total': result.testsRun,
        'failures': len(result.failures),
        'errors': len(result.errors),
        'skipped': len(result.skipped),
        'successes': result.testsRun - len(result.failures) - len(result.errors) - len(result.skipped),
        'time': end_time - start_time,
        'output': output.getvalue() if verbose else None,
        'result_obj': result
    }

def print_test_results(results):
    """Print test results summary."""
    total_tests = sum(r['total'] for r in results)
    total_failures = sum(r['failures'] for r in results)
    total_errors = sum(r['errors'] for r in results)
    total_skipped = sum(r['skipped'] for r in results)
    total_time = sum(r['time'] for r in results)
    
    print("\n" + "="*80)
    print(f"VALNARA SECURITY SCANNER - TEST SUMMARY")
    print("="*80)
    print(f"Ran {total_tests} tests in {total_time:.3f} seconds")
    print(f"- Successes: {total_tests - total_failures - total_errors - total_skipped}")
    print(f"- Failures: {total_failures}")
    print(f"- Errors: {total_errors}")
    print(f"- Skipped: {total_skipped}")
    print("-"*80)
    
    # Print individual test suite results
    for result in results:
        status = "PASSED" if result['failures'] == 0 and result['errors'] == 0 else "FAILED"
        print(f"{result['name']:<30} | {result['successes']}/{result['total']} tests | {result['time']:.3f}s | {status}")
    
    print("="*80)
    if total_failures == 0 and total_errors == 0:
        print("ALL TESTS PASSED")
    else:
        print(f"TESTS FAILED: {total_failures} failures, {total_errors} errors")
    print("="*80)

def run_coverage(target_modules, test_modules, show_missing=False):
    """Run tests with coverage and return report."""
    cov = coverage.Coverage(
        source=target_modules,
        omit=['*/test*', r'*/\.*', '*/venv/*', '*/env/*', '*/site-packages/*']
    )
    
    # Start coverage
    cov.start()
    
    # Run all tests
    test_results = []
    for test_class in test_modules:
        result = run_test_suite(test_class)
        test_results.append(result)
    
    # Stop coverage
    cov.stop()
    
    # Generate report
    print("\n" + "="*80)
    print("COVERAGE REPORT")
    print("="*80)
    
    cov.report(show_missing=show_missing)
    
    # Generate HTML report
    cov_dir = 'coverage_report'
    os.makedirs(cov_dir, exist_ok=True)
    cov.html_report(directory=cov_dir)
    
    print(f"\nDetailed HTML coverage report generated in {cov_dir}/")
    
    # Return both test results and coverage
    return test_results, cov

def main():
    """Main test runner function."""
    parser = argparse.ArgumentParser(description='Valnara Security Scanner Test Runner')
    parser.add_argument('-v', '--verbose', action='store_true', help='Verbose output')
    parser.add_argument('-c', '--coverage', action='store_true', help='Run with coverage')
    parser.add_argument('-m', '--missing', action='store_true', help='Show missing lines in coverage')
    parser.add_argument('-t', '--test', help='Run specific test class only')
    
    args = parser.parse_args()
    
    print("="*80)
    print(f"VALNARA SECURITY SCANNER - TEST RUNNER")
    print(f"Date: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print("="*80)
    
    # Define test modules to run
    all_test_classes = [
        test_validators.TestUrlValidator,
        test_database_operations.TestDatabaseOperations,
        test_cms_detector.TestCmsDetector,
        test_report_generator.TestReportGenerator,
        test_wp_scanner.TestWpScanner,
        test_zap_scanner.TestZapScanner,
        test_app_routes.TestAppRoutes,
        test_integration.TestIntegrationTests
    ]
    
    # Filter test classes if a specific test was requested
    if args.test:
        test_classes = [cls for cls in all_test_classes if cls.__name__ == args.test]
        if not test_classes:
            print(f"Error: Test class '{args.test}' not found.")
            print("Available test classes:")
            for cls in all_test_classes:
                print(f"  {cls.__name__}")
            return 1
    else:
        test_classes = all_test_classes
    
    target_modules = [
        'modules',
        'database',
        'app'
    ]
    
    if args.coverage:
        # Run with coverage
        test_results, _ = run_coverage(target_modules, test_classes, args.missing)
        print_test_results(test_results)
    else:
        # Run tests normally
        results = []
        for test_class in test_classes:
            print(f"\nRunning tests for {test_class.__name__}...")
            result = run_test_suite(test_class, args.verbose)
            results.append(result)
            
            # Print verbose output for failed tests if not in verbose mode
            if not args.verbose and (result['failures'] > 0 or result['errors'] > 0):
                print("\nTest failures or errors detected. Details:")
                for failure in result['result_obj'].failures:
                    print(f"\n--- FAILURE in {failure[0]}")
                    print(failure[1])
                for error in result['result_obj'].errors:
                    print(f"\n--- ERROR in {error[0]}")
                    print(error[1])
        
        print_test_results(results)
        
        # Return exit code based on test results
        if sum(r['failures'] for r in results) > 0 or sum(r['errors'] for r in results) > 0:
            return 1
    
    return 0

if __name__ == '__main__':
    sys.exit(main())