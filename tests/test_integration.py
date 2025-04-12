import unittest
import sys
import os
import tempfile
import shutil
from unittest.mock import patch, MagicMock

# Add the project root to the Python path
sys.path.insert(0, os.path.abspath(os.path.dirname(os.path.dirname(__file__))))

import app
from database.models import db

class TestIntegrationTests(unittest.TestCase):
    """Integration tests for the Valnara Security Scanner."""
    
    def setUp(self):
        """Set up test environment with temporary database."""
        # Create a temporary directory for testing
        self.test_dir = tempfile.mkdtemp()
        self.db_path = os.path.join(self.test_dir, 'test.db')
        self.db_uri = f'sqlite:///{self.db_path}'
        
        # Configure the app for testing
        app.app.config['TESTING'] = True
        app.app.config['SQLALCHEMY_DATABASE_URI'] = self.db_uri
        app.app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
        app.app.config['WTF_CSRF_ENABLED'] = False
        
        # Create a test client
        self.client = app.app.test_client()
        
        # Create the database tables
        with app.app.app_context():
            db.create_all()
    
    def tearDown(self):
        """Clean up test environment."""
        # Remove the test database and directory
        with app.app.app_context():
            db.session.remove()
            db.drop_all()
        
        shutil.rmtree(self.test_dir)
    
    @patch('app.test_zap_connection')
    @patch('app.validate_url')
    @patch('app.check_site_availability')
    @patch('app.is_wordpress')
    @patch('app.run_zap_scan')
    def test_complete_scan_flow(self, mock_zap_scan, mock_is_wordpress, 
                               mock_check_site, mock_validate_url, mock_zap_connection):
        """Test a complete scan flow from start to finish."""
        # Set up mocks
        mock_zap_connection.return_value = (True, '2.12.0')
        mock_validate_url.return_value = True
        mock_check_site.return_value = True
        mock_is_wordpress.return_value = False
        
        # Mock ZAP scan result
        mock_zap_scan.return_value = {
            'scan_info': {
                '3': {
                    'duration': 60,
                    'duration_formatted': '0:01:00'
                }
            },
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
        
        # Step 1: Visit the home page
        response = self.client.get('/')
        self.assertEqual(response.status_code, 200)
        self.assertIn(b'Security Scanner Configuration', response.data)
        
        # Step 2: Start a new scan
        with self.client.session_transaction() as sess:
            # Need to set up the session here if needed
            pass
            
        response = self.client.post('/scan', data={
            'url': 'https://example.com',
            'scan_type': '3',  # Active scan
            'scan_depth': '5'
        }, follow_redirects=True)
        
        self.assertEqual(response.status_code, 200)
        self.assertIn(b'Scan Status', response.data)
        
        # Extract scan ID from the response
        scan_id = None
        with app.app.app_context():
            # Get all scans from the database
            from database.operations import get_scan_history
            scans = get_scan_history()
            self.assertEqual(len(scans), 1)
            scan_id = scans[0].id
        
        self.assertIsNotNone(scan_id)
        
        # Step 3: Start the scan
        response = self.client.post(f'/start_scan/{scan_id}')
        self.assertEqual(response.status_code, 200)
        
        # Step 4: Check scan status
        response = self.client.get(f'/api/scan_status/{scan_id}')
        self.assertEqual(response.status_code, 200)
        
        # Step 5: View results
        response = self.client.get(f'/results/{scan_id}')
        self.assertEqual(response.status_code, 200)
        self.assertIn(b'Scan Results', response.data)
        self.assertIn(b'Test Vulnerability', response.data)
        
        # Step 6: Download report (mocked)
        with patch('app.generate_scan_report') as mock_generate_report:
            with patch('app.send_file') as mock_send_file:
                mock_generate_report.return_value = 'test_report.pdf'
                mock_send_file.return_value = 'file_response'
                
                response = self.client.get(f'/download_report/{scan_id}')
                self.assertEqual(response.status_code, 200)
        
        # Step 7: Check history
        response = self.client.get('/history')
        self.assertEqual(response.status_code, 200)
        self.assertIn(b'Scan History', response.data)
        self.assertIn(b'example.com', response.data)
        
        # Step 8: Delete the scan
        response = self.client.post(f'/delete_scan/{scan_id}', follow_redirects=True)
        self.assertEqual(response.status_code, 200)
        self.assertIn(b'Scan deleted successfully', response.data)
        
        # Verify the scan was deleted
        with app.app.app_context():
            # Get all scans from the database
            from database.operations import get_scan_history
            scans = get_scan_history()
            self.assertEqual(len(scans), 0)
    
    @patch('app.test_zap_connection')
    @patch('app.validate_url')
    @patch('app.check_site_availability')
    @patch('app.is_wordpress')
    @patch('app.scan_wordpress_site')
    def test_wordpress_scan_flow(self, mock_wp_scan, mock_is_wordpress, 
                                mock_check_site, mock_validate_url, mock_zap_connection):
        """Test a complete WordPress scan flow."""
        # Set up mocks
        mock_zap_connection.return_value = (True, '2.12.0')
        mock_validate_url.return_value = True
        mock_check_site.return_value = True
        mock_is_wordpress.return_value = True
        
        # Mock WordPress scan result
        mock_wp_scan.return_value = {
            'scan_info': {
                '6': {
                    'duration': 45,
                    'duration_formatted': '0:00:45',
                    'wp_version': '5.9.3'
                }
            },
            'results': {
                'alerts': [
                    {
                        'name': 'WordPress 5.9.3 Detected',
                        'risk': 'Informational',
                        'url': 'https://example-wp.com',
                        'solution': 'Keep WordPress core updated to the latest secure version.'
                    },
                    {
                        'name': 'Plugin: contact-form-7 (v5.4.2) - SQL Injection',
                        'risk': 'High',
                        'url': 'https://example-wp.com/wp-content/plugins/contact-form-7/',
                        'solution': 'Update to version 5.5.0 or later.'
                    }
                ],
                'summary': {
                    'High': 1,
                    'Medium': 0,
                    'Low': 0,
                    'Informational': 1
                }
            }
        }
        
        # Step 1: Visit the home page
        response = self.client.get('/')
        self.assertEqual(response.status_code, 200)
        
        # Step 2: Start a new scan
        response = self.client.post('/scan', data={
            'url': 'https://example-wp.com',
            'scan_type': '4',  # Passive scan (will be overridden for WordPress)
            'scan_depth': '5'
        }, follow_redirects=True)
        
        self.assertEqual(response.status_code, 200)
        
        # Extract scan ID from the response
        scan_id = None
        with app.app.app_context():
            # Get all scans from the database
            from database.operations import get_scan_history
            scans = get_scan_history()
            self.assertEqual(len(scans), 1)
            scan_id = scans[0].id
            
            # Verify it was correctly identified as WordPress
            self.assertTrue(scans[0].is_wordpress)
            self.assertEqual(scans[0].scan_type, 6)  # WordPress scan type
        
        # Step 3: Start the scan
        response = self.client.post(f'/start_scan/{scan_id}')
        self.assertEqual(response.status_code, 200)
        
        # Step 4: View results
        response = self.client.get(f'/results/{scan_id}')
        self.assertEqual(response.status_code, 200)
        self.assertIn(b'WordPress 5.9.3', response.data)
        self.assertIn(b'contact-form-7', response.data)
    
    @patch('app.test_zap_connection')
    def test_api_check_wordpress(self, mock_zap_connection):
        """Test the WordPress detection API endpoint."""
        # Set up ZAP connection mock
        mock_zap_connection.return_value = (True, '2.12.0')
        
        # Test WordPress detection
        with patch('app.validate_url') as mock_validate:
            with patch('app.check_site_availability') as mock_check_site:
                with patch('app.is_wordpress') as mock_is_wordpress:
                    # Configure mocks
                    mock_validate.return_value = True
                    mock_check_site.return_value = True
                    
                    # Test positive WordPress detection
                    mock_is_wordpress.return_value = True
                    
                    response = self.client.post('/api/check_wordpress', 
                                               json={'url': 'https://example-wp.com'},
                                               content_type='application/json')
                    
                    self.assertEqual(response.status_code, 200)
                    data = response.get_json()
                    self.assertTrue(data['is_wordpress'])
                    
                    # Test negative WordPress detection
                    mock_is_wordpress.return_value = False
                    
                    response = self.client.post('/api/check_wordpress', 
                                               json={'url': 'https://example.com'},
                                               content_type='application/json')
                    
                    self.assertEqual(response.status_code, 200)
                    data = response.get_json()
                    self.assertFalse(data['is_wordpress'])
    
    def test_error_pages(self):
        """Test error pages are correctly rendered."""
        # Test 404 page
        response = self.client.get('/nonexistent_page')
        self.assertEqual(response.status_code, 404)
        self.assertIn(b'Error 404', response.data)
        self.assertIn(b'Page not found', response.data)
        
        # We can't easily test 500 errors directly
        # but we can verify the template exists
        self.assertTrue(os.path.exists(os.path.join('templates', 'error.html')))

if __name__ == '__main__':
    unittest.main()