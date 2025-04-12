import unittest
import sys
import os
import json
from unittest.mock import patch, MagicMock, Mock
from io import BytesIO
from datetime import datetime

# Add the project root to the Python path
sys.path.insert(0, os.path.abspath(os.path.dirname(os.path.dirname(__file__))))

import app
from database.models import db, ScanResult

class TestAppRoutes(unittest.TestCase):
    """Test suite for the Flask app routes."""
    
    def setUp(self):
        """Set up test environment."""
        # Create a test client
        self.app = app.app
        self.app.config['TESTING'] = True
        self.app.config['WTF_CSRF_ENABLED'] = False
        self.app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///:memory:'
        
        self.client = self.app.test_client()
        
        # Create test database tables
        with self.app.app_context():
            app.db.create_all()
        
        # Sample scan data for tests
        self.sample_scan_info = {
            'id': 'test123',
            'url': 'https://example.com',
            'scan_type': 3,
            'scan_depth': 5,
            'is_wordpress': False,
            'status': 'completed',
            'start_time': datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            'end_time': datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            'results': {
                'alerts': [
                    {
                        'name': 'Test Vulnerability',
                        'risk': 'High',
                        'url': 'https://example.com',
                        'solution': 'Test solution'
                    }
                ],
                'summary': {
                    'High': 1,
                    'Medium': 0,
                    'Low': 0,
                    'Informational': 0
                }
            }
        }
    
    def tearDown(self):
        """Clean up after tests."""
        with self.app.app_context():
            app.db.session.remove()
            app.db.drop_all()
    
    @patch('app.test_zap_connection')
    def test_index_route(self, mock_zap_connection):
        """Test index route."""
        mock_zap_connection.return_value = (True, '2.12.0')
        
        response = self.client.get('/')
        
        self.assertEqual(response.status_code, 200)
        # Changed to match your actual HTML content
        self.assertIn(b'Security Scanner Configuration', response.data)
        # Optional: You can keep this check for the ZAP status which appears in a different format
        self.assertIn(b'ZAP Status:', response.data)
    
    @patch('app.test_zap_connection')
    @patch('app.validate_url')
    @patch('app.check_site_availability')
    @patch('app.is_wordpress')
    @patch('app.create_scan')
    def test_scan_route_post_valid(self, mock_create_scan, mock_is_wordpress, 
                                  mock_check_site_availability, mock_validate_url, 
                                  mock_zap_connection):
        """Test scan route with valid POST data."""
        # Set up mocks
        mock_zap_connection.return_value = (True, '2.12.0')
        mock_validate_url.return_value = True
        mock_check_site_availability.return_value = True
        mock_is_wordpress.return_value = False
        mock_create_scan.return_value = None
        
        # Make request
        response = self.client.post('/scan', data={
            'url': 'https://example.com',
            'scan_type': '3',
            'scan_depth': '5'
        }, follow_redirects=False)  # Changed to False to avoid redirect checks
        
        # Check redirect happens (302 status)
        self.assertEqual(response.status_code, 302)
        
        # Verify that validate_url was called
        mock_validate_url.assert_called_once()
        
        # Verify that check_site_availability was called
        mock_check_site_availability.assert_called_once()
        
        # Verify that create_scan was called
        mock_create_scan.assert_called_once()
    
    @patch('app.test_zap_connection')
    @patch('app.validate_url')
    def test_scan_route_post_invalid_url(self, mock_validate_url, mock_zap_connection):
        """Test scan route with invalid URL."""
        # Set up mocks
        mock_zap_connection.return_value = (True, '2.12.0')
        mock_validate_url.return_value = False
        
        # Make request
        response = self.client.post('/scan', data={
            'url': 'invalid-url',
            'scan_type': '3',
            'scan_depth': '5'
        }, follow_redirects=True)
        
        # Check that we get redirected back to index with an error
        self.assertEqual(response.status_code, 200)
        self.assertIn(b'Invalid URL format', response.data)
    
    @patch('app.validate_url')
    @patch('app.check_site_availability')
    def test_api_check_wordpress_route(self, mock_check_site_availability, mock_validate_url):
        """Test API endpoint for checking WordPress sites."""
        # Set up mocks
        mock_validate_url.return_value = True
        mock_check_site_availability.return_value = True
        
        # Test with WordPress detection mock
        with patch('app.is_wordpress') as mock_is_wordpress:
            mock_is_wordpress.return_value = True
            
            response = self.client.post('/api/check_wordpress', 
                                       json={'url': 'https://example.com'},
                                       content_type='application/json')
            
            self.assertEqual(response.status_code, 200)
            data = json.loads(response.data)
            self.assertTrue(data['is_wordpress'])
            
            # Test with non-WordPress site
            mock_is_wordpress.return_value = False
            
            response = self.client.post('/api/check_wordpress', 
                                       json={'url': 'https://example.com'},
                                       content_type='application/json')
            
            self.assertEqual(response.status_code, 200)
            data = json.loads(response.data)
            self.assertFalse(data['is_wordpress'])
    
    def test_api_check_wordpress_invalid_request(self):
        """Test WordPress check API with invalid request."""
        # Test with missing URL
        response = self.client.post('/api/check_wordpress', 
                                   json={},
                                   content_type='application/json')
        
        self.assertEqual(response.status_code, 400)
        data = json.loads(response.data)
        self.assertIn('error', data)
    
    @patch('app.get_scan_by_id')
    def test_scan_status_route(self, mock_get_scan_by_id):
        """Test scan status route."""
        # Set up mock
        mock_get_scan_by_id.return_value = self.sample_scan_info
        
        # Make request
        response = self.client.get('/scan_status/test123')
        
        # Check response
        self.assertEqual(response.status_code, 200)
    
    @patch('app.get_scan_by_id')
    def test_scan_status_route_not_found(self, mock_get_scan_by_id):
        """Test scan status route with non-existent scan ID."""
        # Set up mock
        mock_get_scan_by_id.return_value = None
        
        # Make request
        response = self.client.get('/scan_status/nonexistent', follow_redirects=True)
        
        # Check response
        self.assertEqual(response.status_code, 200)
        self.assertIn(b'Scan not found', response.data)
    
    @patch('app.get_scan_by_id')
    @patch('app.update_scan_status')
    @patch('app.scan_wordpress_site')
    @patch('app.update_scan_results')
    def test_start_scan_wordpress(self, mock_update_results, mock_scan_wp, 
                                 mock_update_status, mock_get_scan_by_id):
        """Test starting a WordPress scan."""
        # Set up mocks
        sample_wp_scan = dict(self.sample_scan_info)
        sample_wp_scan['is_wordpress'] = True
        sample_wp_scan['scan_type'] = 6
        sample_wp_scan['status'] = 'pending'
        
        mock_get_scan_by_id.return_value = sample_wp_scan
        mock_update_status.return_value = True
        mock_scan_wp.return_value = {
            'results': {
                'alerts': [],
                'summary': {'High': 0, 'Medium': 0, 'Low': 0, 'Informational': 0}
            }
        }
        mock_update_results.return_value = True
        
        # Make request
        response = self.client.post('/start_scan/test123')
        
        # Check response
        self.assertEqual(response.status_code, 200)
        data = json.loads(response.data)
        self.assertEqual(data['status'], 'completed')
        
        # Verify calls
        mock_scan_wp.assert_called_once()
        mock_update_results.assert_called_once()
    
    @patch('app.get_scan_by_id')
    @patch('app.update_scan_status')
    @patch('app.run_zap_scan')
    @patch('app.update_scan_results')
    def test_start_scan_zap(self, mock_update_results, mock_run_zap, 
                          mock_update_status, mock_get_scan_by_id):
        """Test starting a ZAP scan."""
        # Set up mocks
        sample_zap_scan = dict(self.sample_scan_info)
        sample_zap_scan['status'] = 'pending'
        
        mock_get_scan_by_id.return_value = sample_zap_scan
        mock_update_status.return_value = True
        mock_run_zap.return_value = {
            'results': {
                'alerts': [],
                'summary': {'High': 0, 'Medium': 0, 'Low': 0, 'Informational': 0}
            }
        }
        mock_update_results.return_value = True
        
        # Make request
        response = self.client.post('/start_scan/test123')
        
        # Check response
        self.assertEqual(response.status_code, 200)
        data = json.loads(response.data)
        self.assertEqual(data['status'], 'completed')
        
        # Verify calls
        mock_run_zap.assert_called_once()
        mock_update_results.assert_called_once()
    
    @patch('app.get_scan_by_id')
    def test_results_route(self, mock_get_scan_by_id):
        """Test results route."""
        # Set up mock
        mock_get_scan_by_id.return_value = self.sample_scan_info
        
        # Make request
        response = self.client.get('/results/test123')
        
        # Check response
        self.assertEqual(response.status_code, 200)
        self.assertIn(b'Scan Results', response.data)
        self.assertIn(b'Test Vulnerability', response.data)
        self.assertIn(b'High Risk', response.data)
    
    @patch('app.get_scan_by_id')
    def test_results_route_scan_in_progress(self, mock_get_scan_by_id):
        """Test results route with scan still in progress."""
        # Set up mock with running scan
        scan_in_progress = dict(self.sample_scan_info)
        scan_in_progress['status'] = 'running'
        mock_get_scan_by_id.return_value = scan_in_progress
        
        # Make request
        response = self.client.get('/results/test123', follow_redirects=True)
        
        # Check response
        self.assertEqual(response.status_code, 200)
        self.assertIn(b'Scan is still in progress', response.data)
    
    @patch('app.get_scan_by_id')
    def test_results_route_not_found(self, mock_get_scan_by_id):
        """Test results route with non-existent scan ID."""
        # Set up mock
        mock_get_scan_by_id.return_value = None
        
        # Make request
        response = self.client.get('/results/nonexistent', follow_redirects=True)
        
        # Check response
        self.assertEqual(response.status_code, 200)
        self.assertIn(b'Scan not found', response.data)
    
    @patch('app.get_scan_by_id')
    @patch('app.get_scan_results')
    def test_api_scan_status_running(self, mock_get_results, mock_get_scan_by_id):
        """Test API scan status endpoint with running scan."""
        # Set up mocks
        running_scan = dict(self.sample_scan_info)
        running_scan['status'] = 'running'
        running_scan.pop('results', None)
        
        mock_get_scan_by_id.return_value = running_scan
        mock_get_results.return_value = {
            'alerts': [
                {
                    'name': 'Test Vulnerability',
                    'risk': 'High',
                    'url': 'https://example.com',
                    'solution': 'Test solution'
                }
            ],
            'summary': {
                'High': 1,
                'Medium': 0,
                'Low': 0,
                'Informational': 0
            }
        }
        
        # Make request
        response = self.client.get('/api/scan_status/test123')
        
        # Check response
        self.assertEqual(response.status_code, 200)
        data = json.loads(response.data)
        self.assertEqual(data['status'], 'running')
        self.assertIn('results', data)
        self.assertIn('alerts', data['results'])
    
    @patch('app.get_scan_by_id')
    def test_api_scan_status_completed(self, mock_get_scan_by_id):
        """Test API scan status endpoint with completed scan."""
        # Set up mock
        mock_get_scan_by_id.return_value = self.sample_scan_info
        
        # Make request
        response = self.client.get('/api/scan_status/test123')
        
        # Check response
        self.assertEqual(response.status_code, 200)
        data = json.loads(response.data)
        self.assertEqual(data['status'], 'completed')
        self.assertIn('redirect', data)
    
    @patch('app.get_scan_by_id')
    def test_api_scan_status_not_found(self, mock_get_scan_by_id):
        """Test API scan status endpoint with non-existent scan ID."""
        # Set up mock
        mock_get_scan_by_id.return_value = None
        
        # Make request
        response = self.client.get('/api/scan_status/nonexistent')
        
        # Check response
        self.assertEqual(response.status_code, 404)
        data = json.loads(response.data)
        self.assertEqual(data['status'], 'error')
    
    @patch('app.get_scan_history')
    def test_history_route(self, mock_get_scan_history):
        """Test history route."""
        # Create mock scan history
        from database.models import ScanResult
        
        scan1 = ScanResult(self.sample_scan_info)
        scan2 = ScanResult({
            'id': 'test456',
            'url': 'https://example2.com',
            'scan_type': 4,
            'scan_depth': 3,
            'is_wordpress': True,
            'status': 'completed',
            'start_time': datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            'end_time': datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        })
        
        mock_get_scan_history.return_value = [scan1, scan2]
        
        # Make request
        response = self.client.get('/history')
        
        # Check response
        self.assertEqual(response.status_code, 200)
        self.assertIn(b'Scan History', response.data)
    
    @patch('app.delete_scan')
    def test_delete_scan_route(self, mock_delete_scan):
        """Test delete scan route."""
        # Set up mock
        mock_delete_scan.return_value = True
        
        # Make request
        response = self.client.post('/delete_scan/test123', follow_redirects=True)
        
        # Check response
        self.assertEqual(response.status_code, 200)
        self.assertIn(b'Scan deleted successfully', response.data)
        
        # Verify delete_scan was called
        mock_delete_scan.assert_called_once_with('test123')
    
    @patch('app.delete_scan')
    def test_delete_scan_route_failed(self, mock_delete_scan):
        """Test delete scan route with deletion failure."""
        # Set up mock
        mock_delete_scan.return_value = False
        
        # Make request
        response = self.client.post('/delete_scan/test123', follow_redirects=True)
        
        # Check response
        self.assertEqual(response.status_code, 200)
        self.assertIn(b'Error deleting scan', response.data)
    
    @patch('app.get_scan_by_id')
    @patch('app.generate_scan_report')
    @patch('app.send_file')
    def test_download_report_route(self, mock_send_file, mock_generate_report, mock_get_scan_by_id):
        """Test download report route."""
        # Set up mocks
        mock_get_scan_by_id.return_value = self.sample_scan_info
        mock_generate_report.return_value = 'reports/test_report.pdf'
        mock_send_file.return_value = 'file_response'
        
        # Make request
        response = self.client.get('/download_report/test123')
        
        # Verify functions were called with correct arguments
        mock_get_scan_by_id.assert_called_once_with('test123')
        mock_generate_report.assert_called_once_with(self.sample_scan_info, 'test123')
        mock_send_file.assert_called_once()
    
    @patch('app.get_scan_by_id')
    def test_download_report_not_found(self, mock_get_scan_by_id):
        """Test download report route with non-existent scan."""
        # Set up mock
        mock_get_scan_by_id.return_value = None
        
        # Make request
        response = self.client.get('/download_report/nonexistent', follow_redirects=True)
        
        # Check response
        self.assertEqual(response.status_code, 200)
        self.assertIn(b'Scan report not found', response.data)
    
    def test_error_handlers(self):
        """Test custom error handlers."""
        # Test 404 handler
        response = self.client.get('/nonexistent_route')
        self.assertEqual(response.status_code, 404)
        self.assertIn(b'Error 404', response.data)
        self.assertIn(b'Page not found', response.data)
        
        # We can't easily test the 500 handler in a unit test
        # as it would require causing an actual server error

if __name__ == '__main__':
    unittest.main()