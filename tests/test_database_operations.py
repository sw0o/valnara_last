import unittest
import sys
import os
import json
from datetime import datetime
from unittest.mock import patch, MagicMock

# Add the project root to the Python path
sys.path.insert(0, os.path.abspath(os.path.dirname(os.path.dirname(__file__))))

# Import the database modules
from database.models import db, ScanResult
from database.operations import (
    create_scan,
    get_scan_by_id,
    update_scan_status,
    update_scan_results,
    get_scan_history,
    delete_scan
)

class TestDatabaseOperations(unittest.TestCase):
    """Test suite for database operations."""
    
    def setUp(self):
        """Set up test environment."""
        # Create a mock Flask app for testing
        from flask import Flask
        self.app = Flask(__name__)
        self.app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///:memory:'
        self.app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
        
        # Initialize the app with the database
        db.init_app(self.app)
        
        # Create all tables in the in-memory database
        with self.app.app_context():
            db.create_all()
        
        # Create a sample scan info dictionary
        self.sample_scan_info = {
            'id': 'test123',
            'url': 'https://example.com',
            'scan_type': 3,
            'scan_depth': 5,
            'is_wordpress': False,
            'status': 'pending',
            'start_time': datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            'end_time': None,
            'results': None
        }
        
        # Create a sample scan with results
        self.sample_scan_with_results = {
            'id': 'test456',
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
            db.session.remove()
            db.drop_all()
    
    def test_create_scan(self):
        """Test creating a new scan in the database."""
        with self.app.app_context():
            # Create scan
            scan = create_scan(self.sample_scan_info)
            
            # Verify scan was created
            self.assertIsNotNone(scan)
            self.assertEqual(scan.id, 'test123')
            self.assertEqual(scan.url, 'https://example.com')
            self.assertEqual(scan.scan_type, 3)
            self.assertEqual(scan.status, 'pending')
            
            # Verify it was added to the database
            db_scan = ScanResult.query.get('test123')
            self.assertIsNotNone(db_scan)
    
    def test_create_scan_with_results(self):
        """Test creating a scan with results data."""
        with self.app.app_context():
            # Create scan with results
            scan = create_scan(self.sample_scan_with_results)
            
            # Verify scan was created with results
            self.assertIsNotNone(scan)
            self.assertEqual(scan.id, 'test456')
            self.assertIsNotNone(scan.results_data)
            
            # Verify JSON data was stored correctly
            results_data = json.loads(scan.results_data)
            self.assertIn('alerts', results_data)
            self.assertEqual(len(results_data['alerts']), 1)
            self.assertEqual(results_data['alerts'][0]['name'], 'Test Vulnerability')
    
    def test_get_scan_by_id(self):
        """Test retrieving a scan by ID."""
        with self.app.app_context():
            # Create a scan first
            create_scan(self.sample_scan_info)
            
            # Get the scan by ID
            scan = get_scan_by_id('test123')
            
            # Verify scan data
            self.assertIsNotNone(scan)
            self.assertEqual(scan['id'], 'test123')
            self.assertEqual(scan['url'], 'https://example.com')
            self.assertEqual(scan['scan_type'], 3)
            self.assertEqual(scan['status'], 'pending')
    
    def test_get_scan_by_id_nonexistent(self):
        """Test retrieving a non-existent scan by ID."""
        with self.app.app_context():
            # Try to get a scan that doesn't exist
            scan = get_scan_by_id('nonexistent')
            
            # Verify no scan was returned
            self.assertIsNone(scan)
    
    def test_update_scan_status(self):
        """Test updating a scan's status."""
        with self.app.app_context():
            # Create a scan first
            create_scan(self.sample_scan_info)
            
            # Update the scan status
            result = update_scan_status('test123', 'running')
            
            # Verify update was successful
            self.assertTrue(result)
            
            # Verify the status was updated in the database
            scan = get_scan_by_id('test123')
            self.assertEqual(scan['status'], 'running')
    
    def test_update_scan_status_with_end_time(self):
        """Test updating a scan's status with an end time."""
        with self.app.app_context():
            # Create a scan first
            create_scan(self.sample_scan_info)
            
            # Update the scan status with end time
            end_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            result = update_scan_status('test123', 'completed', end_time)
            
            # Verify update was successful
            self.assertTrue(result)
            
            # Verify the status and end time were updated
            scan = get_scan_by_id('test123')
            self.assertEqual(scan['status'], 'completed')
            self.assertEqual(scan['end_time'], end_time)
    
    def test_update_scan_status_nonexistent(self):
        """Test updating a non-existent scan's status."""
        with self.app.app_context():
            # Try to update a scan that doesn't exist
            result = update_scan_status('nonexistent', 'running')
            
            # Verify update failed
            self.assertFalse(result)
    
    def test_update_scan_results(self):
        """Test updating a scan's results."""
        with self.app.app_context():
            # Create a scan first
            create_scan(self.sample_scan_info)
            
            # Update the scan results
            results = {
                'alerts': [
                    {
                        'name': 'Updated Vulnerability',
                        'risk': 'Medium',
                        'url': 'https://example.com/page',
                        'solution': 'Update this'
                    }
                ],
                'summary': {
                    'High': 0,
                    'Medium': 1,
                    'Low': 0,
                    'Informational': 0
                }
            }
            
            result = update_scan_results('test123', results)
            
            # Verify update was successful
            self.assertTrue(result)
            
            # Verify the results were updated in the database
            scan = get_scan_by_id('test123')
            self.assertIn('results', scan)
            self.assertEqual(scan['results']['alerts'][0]['name'], 'Updated Vulnerability')
            self.assertEqual(scan['status'], 'completed')  # Status should be auto-updated to completed
    
    def test_update_scan_results_nonexistent(self):
        """Test updating a non-existent scan's results."""
        with self.app.app_context():
            # Try to update a scan that doesn't exist
            results = {'alerts': [], 'summary': {}}
            result = update_scan_results('nonexistent', results)
            
            # Verify update failed
            self.assertFalse(result)
    
    def test_get_scan_history(self):
        """Test retrieving scan history."""
        with self.app.app_context():
            # Create multiple scans
            create_scan(self.sample_scan_info)
            create_scan(self.sample_scan_with_results)
            
            # Get scan history
            scans = get_scan_history()
            
            # Verify scans were retrieved
            self.assertEqual(len(scans), 2)
            
            # Verify they're ordered by start_time descending (newest first)
            # This test assumes the scans were created within a very short time frame
            # and thus may have the same timestamp
            scan_ids = [scan.id for scan in scans]
            self.assertIn('test123', scan_ids)
            self.assertIn('test456', scan_ids)
    
    def test_delete_scan(self):
        """Test deleting a scan."""
        with self.app.app_context():
            # Create a scan first
            create_scan(self.sample_scan_info)
            
            # Verify scan exists
            self.assertIsNotNone(get_scan_by_id('test123'))
            
            # Delete the scan
            result = delete_scan('test123')
            
            # Verify deletion was successful
            self.assertTrue(result)
            
            # Verify scan no longer exists in the database
            self.assertIsNone(get_scan_by_id('test123'))
    
    def test_delete_scan_nonexistent(self):
        """Test deleting a non-existent scan."""
        with self.app.app_context():
            # Try to delete a scan that doesn't exist
            result = delete_scan('nonexistent')
            
            # Verify deletion "failed" but didn't crash
            self.assertFalse(result)

if __name__ == '__main__':
    unittest.main()