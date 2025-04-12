import unittest
import sys
import os
import json
from unittest.mock import patch, Mock, MagicMock
from datetime import datetime, timedelta

# Add the project root to the Python path
sys.path.insert(0, os.path.abspath(os.path.dirname(os.path.dirname(__file__))))

from modules.zap_scanner import (
    zap_api_call,
    format_time,
    ensure_url_in_context,
    run_spider_scan,
    run_ajax_spider_scan,
    run_active_scan,
    run_passive_scan,
    run_dom_xss_scan,
    setup_authentication,
    get_scan_results,
    run_zap_scan,
    test_zap_connection,
    get_scan_progress
)

class TestZapScanner(unittest.TestCase):
    """Test suite for the ZAP scanner module."""
    
    def setUp(self):
        """Set up test environment."""
        # Sample constants for testing
        self.target_url = "https://example.com"
        self.sample_alerts = [
            {
                'name': 'Cross-Site Scripting (Reflected)',
                'risk': 'High',
                'url': 'https://example.com/search?q=test',
                'solution': 'Validate all input and encode output properly.'
            },
            {
                'name': 'SQL Injection',
                'risk': 'High',
                'url': 'https://example.com/product?id=1',
                'solution': 'Use prepared statements and parameterized queries.'
            },
            {
                'name': 'Insecure Cookie',
                'risk': 'Medium',
                'url': 'https://example.com',
                'solution': 'Set secure and HttpOnly flags on cookies.'
            }
        ]
    
    @patch('requests.get')
    def test_zap_api_call(self, mock_get):
        """Test ZAP API call function."""
        # Mock response
        mock_response = Mock()
        mock_response.json.return_value = {'result': 'success'}
        mock_get.return_value = mock_response
        
        # Call function
        result = zap_api_call('core', 'view', 'version')
        
        # Verify request was made with correct URL and params
        mock_get.assert_called_once()
        args, kwargs = mock_get.call_args
        self.assertEqual(args[0], 'http://localhost:8080/JSON/core/view/version/')
        self.assertIn('apikey', kwargs['params'])
        
        # Verify result
        self.assertEqual(result, {'result': 'success'})
    
    def test_format_time(self):
        """Test time formatting function."""
        test_cases = [
            (0, '0:00:00'),
            (30, '0:00:30'),
            (65, '0:01:05'),
            (3600, '1:00:00'),
            (3661, '1:01:01'),
            (86400, '1 day, 0:00:00'),  # 1 day
            (172800, '2 days, 0:00:00'),  # 2 days
        ]
        
        for seconds, expected in test_cases:
            with self.subTest(seconds=seconds):
                result = format_time(seconds)
                self.assertEqual(result, expected)
    
    @patch('modules.zap_scanner.zap_api_call')
    @patch('time.sleep')
    def test_ensure_url_in_context_success(self, mock_sleep, mock_zap_api_call):
        """Test ensuring URL is in ZAP context - successful case."""
        # Mock API responses
        mock_zap_api_call.side_effect = [
            {},  # accessUrl response
            {'scan': '1'},  # spider scan response
            {'status': '100'}  # spider status response
        ]
        
        result = ensure_url_in_context(self.target_url)
        
        # Verify API calls were made
        self.assertEqual(mock_zap_api_call.call_count, 3)
        
        # Verify result
        self.assertTrue(result)
    
    @patch('modules.zap_scanner.zap_api_call')
    @patch('time.sleep')
    def test_ensure_url_in_context_failure(self, mock_sleep, mock_zap_api_call):
        """Test ensuring URL is in ZAP context - failure case."""
        # Mock API responses with error
        mock_zap_api_call.side_effect = [
            {},  # accessUrl response
            {'error': 'Failed to access URL'}  # spider scan error response
        ]
        
        result = ensure_url_in_context(self.target_url)
        
        # Verify result
        self.assertFalse(result)
    
    @patch('modules.zap_scanner.ensure_url_in_context')
    @patch('modules.zap_scanner.zap_api_call')
    @patch('time.sleep')
    @patch('time.time')
    def test_run_spider_scan(self, mock_time, mock_sleep, mock_zap_api_call, mock_ensure_context):
        """Test running a spider scan."""
        # Mock time.time() to return consistent values
        mock_time.side_effect = [1000, 1030, 1030]  # Start time, end time, extra value
        
        # Mock API responses
        mock_ensure_context.return_value = True
        mock_zap_api_call.side_effect = [
            {},  # setOptionMaxDepth response
            {'scan': '1'},  # spider scan response
            {'status': '100'}  # spider status response
        ]
        
        result = run_spider_scan(self.target_url, max_depth=5)
        
        # Verify API calls were made
        self.assertEqual(mock_zap_api_call.call_count, 3)
        
        # Verify result
        self.assertEqual(result['duration'], 30)
        self.assertEqual(result['duration_formatted'], '0:00:30')
    
    @patch('modules.zap_scanner.ensure_url_in_context')
    @patch('modules.zap_scanner.zap_api_call')
    @patch('time.sleep')
    @patch('time.time')
    def test_run_ajax_spider_scan(self, mock_time, mock_sleep, mock_zap_api_call, mock_ensure_context):
        """Test running an AJAX spider scan."""
        # Mock time.time() to return consistent values - adding more values to prevent StopIteration
        mock_time.side_effect = [1000, 1030, 1060, 1060]  # Start time, status check, elapsed check, end time
        
        # Mock API responses
        mock_ensure_context.return_value = True
        mock_zap_api_call.side_effect = [
            {},  # ajax spider scan response
            {'running': 'false'}  # ajax spider status response
        ]
        
        result = run_ajax_spider_scan(self.target_url, max_duration=600)
        
        # Verify API calls were made
        self.assertEqual(mock_zap_api_call.call_count, 2)
        
        # Verify result
        self.assertEqual(result['duration'], 60)
        self.assertEqual(result['duration_formatted'], '0:01:00')
    
    @patch('modules.zap_scanner.ensure_url_in_context')
    @patch('modules.zap_scanner.zap_api_call')
    @patch('time.sleep')
    @patch('time.time')
    def test_run_active_scan(self, mock_time, mock_sleep, mock_zap_api_call, mock_ensure_context):
        """Test running an active scan."""
        # Mock time.time() to return consistent values
        mock_time.side_effect = [1000, 1120, 1120]  # Start time, end time, extra value
        
        # Mock API responses
        mock_ensure_context.return_value = True
        mock_zap_api_call.side_effect = [
            {'scan': '1'},  # active scan response
            {'status': '100'}  # active scan status response
        ]
        
        result = run_active_scan(self.target_url)
        
        # Verify API calls were made
        self.assertEqual(mock_zap_api_call.call_count, 2)
        
        # Verify result
        self.assertEqual(result['duration'], 120)
        self.assertEqual(result['duration_formatted'], '0:02:00')
    
    @patch('modules.zap_scanner.zap_api_call')
    @patch('time.sleep')
    @patch('time.time')
    def test_run_passive_scan(self, mock_time, mock_sleep, mock_zap_api_call):
        """Test running a passive scan."""
        # Mock time.time() to return consistent values - adding more values to prevent StopIteration
        mock_time.side_effect = [1000, 1010, 1020, 1020]  # Start time, first check, second check, end time
        
        # Mock API responses
        mock_zap_api_call.side_effect = [
            {'recordsToScan': '10'},  # First check
            {'recordsToScan': '0'}    # Second check (complete)
        ]
        
        result = run_passive_scan(wait_time=60)
        
        # Verify API calls were made
        self.assertEqual(mock_zap_api_call.call_count, 2)
        
        # Verify result
        self.assertEqual(result['duration'], 20)
        self.assertEqual(result['duration_formatted'], '0:00:20')
    
    @patch('modules.zap_scanner.ensure_url_in_context')
    @patch('modules.zap_scanner.zap_api_call')
    @patch('time.sleep')
    @patch('time.time')
    def test_run_dom_xss_scan(self, mock_time, mock_sleep, mock_zap_api_call, mock_ensure_context):
        """Test running a DOM XSS scan."""
        # Mock time.time() to return consistent values
        mock_time.side_effect = [1000, 1015, 1015]  # Start time, end time, extra value
        
        # Mock API responses
        mock_ensure_context.return_value = True
        mock_zap_api_call.side_effect = [
            {},  # setEnabled response
            {}   # dom xss scan response
        ]
        
        result = run_dom_xss_scan(self.target_url)
        
        # Verify API calls were made
        self.assertEqual(mock_zap_api_call.call_count, 2)
        
        # Verify result
        self.assertEqual(result['duration'], 15)
        self.assertEqual(result['duration_formatted'], '0:00:15')
    
    @patch('modules.zap_scanner.zap_api_call')
    def test_setup_authentication(self, mock_zap_api_call):
        """Test setting up authentication."""
        # Mock API responses
        mock_zap_api_call.side_effect = [
            {'contextId': '1'},  # newContext response
            {},  # includeInContext response
            {},  # setAuthenticationMethod response
            {},  # setLoggedInIndicator response
            {'userId': '1'},  # newUser response
            {},  # setUserEnabled response
            {}   # setAuthenticationCredentials response
        ]
        
        result = setup_authentication(
            'https://example.com/login',
            'testuser',
            'testpass'
        )
        
        # Verify API calls were made
        self.assertEqual(mock_zap_api_call.call_count, 7)
        
        # Verify result
        self.assertEqual(result['context_id'], '1')
        self.assertEqual(result['user_id'], '1')
    
    @patch('modules.zap_scanner.zap_api_call')
    def test_get_scan_results(self, mock_zap_api_call):
        """Test getting scan results."""
        # Mock API response
        mock_zap_api_call.return_value = {
            'alerts': self.sample_alerts
        }
        
        result = get_scan_results(self.target_url)
        
        # Verify API call was made
        mock_zap_api_call.assert_called_once()
        
        # Verify result structure
        self.assertIn('alerts', result)
        self.assertIn('summary', result)
        
        # Verify alert count
        self.assertEqual(len(result['alerts']), 3)
        
        # Verify risk summary
        self.assertEqual(result['summary']['High'], 2)
        self.assertEqual(result['summary']['Medium'], 1)
        self.assertEqual(result['summary']['Low'], 0)
        self.assertEqual(result['summary']['Informational'], 0)
    
    @patch('modules.zap_scanner.ensure_url_in_context')
    @patch('modules.zap_scanner.run_spider_scan')
    @patch('modules.zap_scanner.run_active_scan')
    @patch('modules.zap_scanner.run_passive_scan')
    @patch('modules.zap_scanner.get_scan_results')
    def test_run_zap_scan(self, mock_get_results, mock_passive, mock_active, 
                         mock_spider, mock_ensure_context):
        """Test running a complete ZAP scan."""
        # Mock function responses
        mock_ensure_context.return_value = True
        mock_spider.return_value = {'duration': 30, 'duration_formatted': '0:00:30'}
        mock_active.return_value = {'duration': 120, 'duration_formatted': '0:02:00'}
        mock_passive.return_value = {'duration': 20, 'duration_formatted': '0:00:20'}
        mock_get_results.return_value = {
            'alerts': self.sample_alerts,
            'summary': {
                'High': 2,
                'Medium': 1,
                'Low': 0,
                'Informational': 0
            }
        }
        
        result = run_zap_scan(self.target_url, scan_types=[1, 3, 4])
        
        # Verify functions were called
        mock_ensure_context.assert_called_once()
        mock_spider.assert_called_once()
        mock_active.assert_called_once()
        mock_passive.assert_called_once()
        mock_get_results.assert_called_once()
        
        # Verify result structure
        self.assertIn('scan_info', result)
        self.assertIn('results', result)
        
        # Verify scan info contains all scan types
        self.assertIn('spider', result['scan_info'])
        self.assertIn('active', result['scan_info'])
        self.assertIn('passive', result['scan_info'])
        
        # Verify results contains alerts and summary
        self.assertIn('alerts', result['results'])
        self.assertIn('summary', result['results'])
    
    @patch('modules.zap_scanner.zap_api_call')
    def test_test_zap_connection_success(self, mock_zap_api_call):
        """Test ZAP connection test - success case."""
        # Mock API response
        mock_zap_api_call.return_value = {'version': '2.12.0'}
        
        result, version = test_zap_connection()
        
        # Verify API call was made
        mock_zap_api_call.assert_called_once_with('core', 'view', 'version')
        
        # Verify result
        self.assertTrue(result)
        self.assertEqual(version, '2.12.0')
    
    @patch('modules.zap_scanner.zap_api_call')
    def test_test_zap_connection_failure(self, mock_zap_api_call):
        """Test ZAP connection test - failure case."""
        # Mock API response with exception
        mock_zap_api_call.side_effect = Exception("Connection refused")
        
        result, error = test_zap_connection()
        
        # Verify API call was attempted
        mock_zap_api_call.assert_called_once_with('core', 'view', 'version')
        
        # Verify result
        self.assertFalse(result)
        self.assertEqual(error, "Connection refused")
    
    @patch('modules.zap_scanner.zap_api_call')
    def test_get_scan_progress_active(self, mock_zap_api_call):
        """Test getting active scan progress."""
        # Mock API response
        mock_zap_api_call.return_value = {'status': '75'}
        
        result = get_scan_progress(scan_id='1', scan_type=3)
        
        # Verify API call was made
        mock_zap_api_call.assert_called_once_with('ascan', 'view', 'status', {'scanId': '1'})
        
        # Verify result
        self.assertEqual(result, 75)
    
    @patch('modules.zap_scanner.zap_api_call')
    def test_get_scan_progress_spider(self, mock_zap_api_call):
        """Test getting spider scan progress."""
        # Mock API response
        mock_zap_api_call.return_value = {'status': '60'}
        
        result = get_scan_progress(scan_id='1', scan_type=1)
        
        # Verify API call was made
        mock_zap_api_call.assert_called_once_with('spider', 'view', 'status', {'scanId': '1'})
        
        # Verify result
        self.assertEqual(result, 60)
    
    @patch('modules.zap_scanner.zap_api_call')
    def test_get_scan_progress_ajax(self, mock_zap_api_call):
        """Test getting AJAX spider scan progress."""
        # Mock API response
        mock_zap_api_call.return_value = {'running': 'true'}
        
        result = get_scan_progress(scan_type=2)
        
        # Verify API call was made
        mock_zap_api_call.assert_called_once_with('ajaxSpider', 'view', 'status')
        
        # Verify result
        self.assertEqual(result, 50)  # Should return 50% for running ajax spider
    
    @patch('modules.zap_scanner.zap_api_call')
    def test_get_scan_progress_passive(self, mock_zap_api_call):
        """Test getting passive scan progress."""
        # Mock API response
        mock_zap_api_call.return_value = {'recordsToScan': '5'}
        
        result = get_scan_progress(scan_type=4)
        
        # Verify API call was made
        mock_zap_api_call.assert_called_once_with('pscan', 'view', 'recordsToScan')
        
        # Verify result
        self.assertEqual(result, 95)  # Should be 100 - recordsToScan with minimum 0, maximum 95
    
    @patch('modules.zap_scanner.zap_api_call')
    def test_get_scan_progress_error(self, mock_zap_api_call):
        """Test scan progress handling of errors."""
        # Mock API response with exception
        mock_zap_api_call.side_effect = Exception("API Error")
        
        result = get_scan_progress(scan_id='1', scan_type=3)
        
        # Verify API call was attempted
        mock_zap_api_call.assert_called_once()
        
        # Verify result - should default to 50% on error
        self.assertEqual(result, 50)

if __name__ == '__main__':
    unittest.main()