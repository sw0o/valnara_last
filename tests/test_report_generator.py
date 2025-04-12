import unittest
import sys
import os
import json
from unittest.mock import patch, mock_open, MagicMock
from datetime import datetime

# Add the project root to the Python path
sys.path.insert(0, os.path.abspath(os.path.dirname(os.path.dirname(__file__))))

# Import the module directly and then patch its internal SimpleDocTemplate reference
import modules.report_generator
from modules.report_generator import generate_scan_report, extract_risk_summary, get_scan_type_name

class TestReportGenerator(unittest.TestCase):
    """Test suite for the report generator module."""
    
    def setUp(self):
        """Set up test environment."""
        # Create sample scan data for testing
        self.sample_scan_data = {
            'id': 'test123',
            'url': 'https://example.com',
            'scan_type': 3,
            'scan_depth': 5,
            'is_wordpress': False,
            'status': 'completed',
            'start_time': '2023-04-01 12:00:00',
            'end_time': '2023-04-01 12:05:00',
            'results': {
                'alerts': [
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
                ],
                'summary': {
                    'High': 2,
                    'Medium': 1,
                    'Low': 0,
                    'Informational': 0
                }
            }
        }
        
        # Sample scan data with nested results
        self.nested_results_scan_data = {
            'id': 'test456',
            'url': 'https://example.com',
            'scan_type': 4,
            'scan_depth': 5,
            'is_wordpress': False,
            'status': 'completed',
            'start_time': '2023-04-01 12:00:00',
            'end_time': '2023-04-01 12:05:00',
            'results': {
                'results': {
                    'alerts': [
                        {
                            'name': 'Test Vulnerability',
                            'risk': 'Medium',
                            'url': 'https://example.com',
                            'solution': 'Test solution'
                        }
                    ],
                    'summary': {
                        'High': 0,
                        'Medium': 1,
                        'Low': 0,
                        'Informational': 0
                    }
                }
            }
        }
        
        # Sample scan data with results in results_data (serialized)
        self.serialized_results_scan_data = {
            'id': 'test789',
            'url': 'https://example.com',
            'scan_type': 5,
            'scan_depth': 5,
            'is_wordpress': False,
            'status': 'completed',
            'start_time': '2023-04-01 12:00:00',
            'end_time': '2023-04-01 12:05:00',
            'results_data': json.dumps({
                'alerts': [
                    {
                        'name': 'DOM XSS Vulnerability',
                        'risk': 'Low',
                        'url': 'https://example.com/js',
                        'solution': 'Fix DOM XSS issues.'
                    }
                ],
                'summary': {
                    'High': 0,
                    'Medium': 0,
                    'Low': 1,
                    'Informational': 0
                }
            })
        }
    
    @patch('os.makedirs')
    def test_generate_scan_report(self, mock_makedirs):
        """Test generating a scan report."""
        # Use a specific datetime for testing
        fake_now = datetime(2023, 4, 1, 12, 0, 0)
        
        # Mock the build method directly at the module level
        mock_doc = MagicMock()
        mock_build = MagicMock()
        mock_doc.build = mock_build
        
        # Save the original and replace
        original_doc_class = modules.report_generator.SimpleDocTemplate
        modules.report_generator.SimpleDocTemplate = lambda *args, **kwargs: mock_doc
        
        try:
            # Create a patching context for datetime
            with patch('modules.report_generator.datetime') as mock_dt:
                # Configure the mocked datetime
                mock_dt.now.return_value = fake_now
                mock_dt.strftime.return_value = '20230401_120000'
                
                # Call generate_scan_report with sample data
                result = generate_scan_report(self.sample_scan_data, 'test123')
            
            # Verify report directory was created
            mock_makedirs.assert_called_once_with('reports', exist_ok=True)
            
            # Verify document.build was called
            mock_build.assert_called_once()
            
            # Verify function returned correct file path
            self.assertTrue('test123' in result)
        finally:
            # Restore original class
            modules.report_generator.SimpleDocTemplate = original_doc_class
    
    @patch('os.makedirs')
    def test_generate_scan_report_with_nested_results(self, mock_makedirs):
        """Test generating a scan report with nested results structure."""
        # Use a specific datetime for testing
        fake_now = datetime(2023, 4, 1, 12, 0, 0)
        
        # Mock the build method directly at the module level
        mock_doc = MagicMock()
        mock_build = MagicMock()
        mock_doc.build = mock_build
        
        # Save the original and replace
        original_doc_class = modules.report_generator.SimpleDocTemplate
        modules.report_generator.SimpleDocTemplate = lambda *args, **kwargs: mock_doc
        
        try:
            # Create a patching context for datetime
            with patch('modules.report_generator.datetime') as mock_dt:
                # Configure the mocked datetime
                mock_dt.now.return_value = fake_now
                mock_dt.strftime.return_value = '20230401_120000'
                
                # Call generate_scan_report with nested results data
                result = generate_scan_report(self.nested_results_scan_data, 'test456')
            
            # Verify document.build was called
            mock_build.assert_called_once()
            
            # Verify function returned correct file path
            self.assertTrue('test456' in result)
        finally:
            # Restore original class
            modules.report_generator.SimpleDocTemplate = original_doc_class
    
    @patch('os.makedirs')
    def test_generate_scan_report_with_serialized_results(self, mock_makedirs):
        """Test generating a scan report with serialized results data."""
        # Use a specific datetime for testing
        fake_now = datetime(2023, 4, 1, 12, 0, 0)
        
        # Mock the build method directly at the module level
        mock_doc = MagicMock()
        mock_build = MagicMock()
        mock_doc.build = mock_build
        
        # Save the original and replace
        original_doc_class = modules.report_generator.SimpleDocTemplate
        modules.report_generator.SimpleDocTemplate = lambda *args, **kwargs: mock_doc
        
        try:
            # Create a patching context for datetime
            with patch('modules.report_generator.datetime') as mock_dt:
                # Configure the mocked datetime
                mock_dt.now.return_value = fake_now
                mock_dt.strftime.return_value = '20230401_120000'
                
                # Call generate_scan_report with serialized results data
                result = generate_scan_report(self.serialized_results_scan_data, 'test789')
            
            # Verify document.build was called
            mock_build.assert_called_once()
            
            # Verify function returned correct file path
            self.assertTrue('test789' in result)
        finally:
            # Restore original class
            modules.report_generator.SimpleDocTemplate = original_doc_class
    
    def test_extract_risk_summary_direct(self):
        """Test extracting risk summary directly from results."""
        # Test with direct summary structure
        summary = extract_risk_summary(self.sample_scan_data)
        
        self.assertEqual(summary['High'], 2)
        self.assertEqual(summary['Medium'], 1)
        self.assertEqual(summary['Low'], 0)
        self.assertEqual(summary['Informational'], 0)
    
    def test_extract_risk_summary_nested(self):
        """Test extracting risk summary from nested results structure."""
        # Test with nested summary structure
        summary = extract_risk_summary(self.nested_results_scan_data)
        
        self.assertEqual(summary['High'], 0)
        self.assertEqual(summary['Medium'], 1)
        self.assertEqual(summary['Low'], 0)
        self.assertEqual(summary['Informational'], 0)
    
    def test_extract_risk_summary_serialized(self):
        """Test extracting risk summary from serialized results data."""
        # Test with serialized summary data
        summary = extract_risk_summary(self.serialized_results_scan_data)
        
        self.assertEqual(summary['High'], 0)
        self.assertEqual(summary['Medium'], 0)
        self.assertEqual(summary['Low'], 1)
        self.assertEqual(summary['Informational'], 0)
    
    def test_extract_risk_summary_empty(self):
        """Test extracting risk summary from empty data."""
        # Test with empty data
        empty_data = {'id': 'empty'}
        summary = extract_risk_summary(empty_data)
        
        # Should return default empty summary
        self.assertEqual(summary['High'], 0)
        self.assertEqual(summary['Medium'], 0)
        self.assertEqual(summary['Low'], 0)
        self.assertEqual(summary['Informational'], 0)
    
    def test_get_scan_type_name(self):
        """Test getting scan type names from numeric values."""
        test_cases = [
            (1, "Spider Scan"),
            (2, "Ajax Spider Scan"),
            (3, "Active Scan"),
            (4, "Passive Scan"),
            (5, "DOM XSS Scan"),
            (6, "WordPress Scan"),
            (99, "Unknown (99)"),  # Unknown scan type
            ("3", "Active Scan"),  # String input
            (None, "None"),       # None input
            ({}, "{}"),           # Invalid input
        ]
        
        for scan_type, expected_name in test_cases:
            with self.subTest(scan_type=scan_type):
                result = get_scan_type_name(scan_type)
                self.assertEqual(result, expected_name)

if __name__ == '__main__':
    unittest.main()