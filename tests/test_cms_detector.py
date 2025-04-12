import unittest
import sys
import os
from unittest.mock import patch, Mock

# Add the project root to the Python path
sys.path.insert(0, os.path.abspath(os.path.dirname(os.path.dirname(__file__))))

from modules.cms_detector import is_wordpress

class TestCmsDetector(unittest.TestCase):
    """Test suite for the CMS detector module."""
    
    @patch('requests.get')
    def test_is_wordpress_positive(self, mock_get):
        """Test WordPress detection with positive indicators."""
        # Create several mock responses with different WordPress indicators
        test_cases = [
            # Response with wp-content
            ('<link rel="stylesheet" href="/wp-content/themes/mytheme/style.css">', True),
            # Response with wp-includes
            ('<script src="/wp-includes/js/jquery/jquery.min.js"></script>', True),
            # Response with wordpress mention
            ('<meta name="generator" content="WordPress 5.9.3">', True),
            # Response with multiple wp- mentions
            ('<div class="wp-block"></div><div class="wp-post"></div><div class="wp-menu"></div><div class="wp-admin"></div>', True),
        ]
        
        for html_content, expected_result in test_cases:
            mock_response = Mock()
            mock_response.text = html_content
            mock_get.return_value = mock_response
            
            with self.subTest(html=html_content[:30]):
                result = is_wordpress("example.com")
                self.assertEqual(result, expected_result)
    
    @patch('requests.get')
    def test_is_wordpress_negative(self, mock_get):
        """Test WordPress detection with negative indicators."""
        # Create mock responses without WordPress indicators
        test_cases = [
            # Empty response
            ('', False),
            # Generic HTML with no WordPress indicators
            ('<!DOCTYPE html><html><head><title>Test</title></head><body><h1>Hello World</h1></body></html>', False),
            # Response mentioning other CMS
            ('<meta name="generator" content="Drupal 9">', False),
        ]
        
        for html_content, expected_result in test_cases:
            mock_response = Mock()
            mock_response.text = html_content
            mock_get.return_value = mock_response
            
            with self.subTest(html=html_content[:30]):
                result = is_wordpress("example.com")
                self.assertEqual(result, expected_result)
    
    @patch('requests.get')
    def test_is_wordpress_exceptions(self, mock_get):
        """Test WordPress detection with request exceptions."""
        # Test different exceptions
        exceptions = [
            Exception("General error"),
            TimeoutError("Connection timeout"),
            ConnectionError("Connection refused"),
        ]
        
        for exception in exceptions:
            mock_get.side_effect = exception
            
            with self.subTest(exception=type(exception).__name__):
                # Should return False on any exception
                result = is_wordpress("example.com")
                self.assertFalse(result)
    
    def test_is_wordpress_url_normalization(self):
        """Test URL normalization in is_wordpress function."""
        with patch('requests.get') as mock_get:
            mock_response = Mock()
            mock_response.text = '<link rel="stylesheet" href="/wp-content/themes/mytheme/style.css">'
            mock_get.return_value = mock_response
            
            # Test various URL formats
            test_urls = [
                'example.com',
                'http://example.com',
                'https://example.com',
                'www.example.com',
                'https://www.example.com',
            ]
            
            for url in test_urls:
                with self.subTest(url=url):
                    result = is_wordpress(url)
                    self.assertTrue(result)
                    
                    # Verify the URL was normalized (should start with http:// or https://)
                    called_url = mock_get.call_args[0][0]
                    self.assertTrue(called_url.startswith('http://') or called_url.startswith('https://'))

if __name__ == '__main__':
    unittest.main()