import unittest
import sys
import os
import time
from unittest.mock import patch, Mock
from datetime import datetime

# Add the project root to the Python path
sys.path.insert(0, os.path.abspath(os.path.dirname(os.path.dirname(__file__))))

from modules.url_validator import validate_url, check_site_availability, normalize_url, get_domain

class TimedTestCase(unittest.TestCase):
    def setUp(self):
        self.start_time = time.time()
        
    def tearDown(self):
        end_time = time.time()
        elapsed = end_time - self.start_time
        print(f"{self.id()}: {elapsed:.6f} seconds")

class TestUrlValidator(TimedTestCase):
    """Test suite for the url_validator module."""
    
    @classmethod
    def setUpClass(cls):
        cls.start_time = time.time()
        print(f"\nStarting tests at: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        
    @classmethod
    def tearDownClass(cls):
        end_time = time.time()
        total_elapsed = end_time - cls.start_time
        print(f"\nTotal test time: {total_elapsed:.6f} seconds")
        print(f"Finished tests at: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")

    def test_validate_url_with_valid_urls(self):
        """Test validate_url with valid URLs."""
        valid_urls = [
            # Standard URLs
            'http://example.com',
            'https://example.com',
            'http://www.example.com',
            'https://www.example.com',
            
            # URLs without scheme
            'example.com',
            'www.example.com',
            
            # Subdomains
            'blog.example.com',
            'sub.domain.example.com',
            
            # With paths
            'example.com/path',
            'example.com/path/to/resource',
            'example.com/path/to/resource.html',
            
            # With query parameters
            'example.com?param=value',
            'example.com/?param=value',
            'example.com/path?param=value&another=123',
            
            # With ports
            'example.com:8080',
            'http://example.com:8080',
            'https://example.com:443',
            
            # IP addresses
            '192.168.1.1',
            'http://192.168.1.1',
            '127.0.0.1',
            'http://127.0.0.1:8080',
            
            # localhost
            'localhost',
            'http://localhost',
            'localhost:8080',
        ]
        
        # Time individual function calls
        for url in valid_urls:
            start = time.time()
            result = validate_url(url)
            end = time.time()
            self.assertTrue(result, f"URL should be valid: {url}")
            print(f"  validate_url({url!r}): {(end-start):.6f} seconds")

    def test_validate_url_with_invalid_urls(self):
        """Test validate_url with invalid URLs."""
        invalid_urls = [
            # Empty string
            '',
            
            # Malformed URLs
            'http:/example.com',  # Missing slash
            'http://example..com',  # Double dot
            'http://.example.com',  # Starts with dot
            'http://example-.com',  # Hyphen at end of segment
            'http://example.com-',  # Hyphen at end of domain
            
            # Invalid IP addresses
            '999.999.999.999',
            '256.256.256.256',
            
            # Malformed with special characters
            'http://exam ple.com',  # Space in domain
            'http://exa_mple.com',  # Underscore in domain (not allowed)
        ]
        
        # Time individual function calls
        for url in invalid_urls:
            start = time.time()
            result = validate_url(url)
            end = time.time()
            self.assertFalse(result, f"URL should be invalid: {url}")
            print(f"  validate_url({url!r}): {(end-start):.6f} seconds")

    def test_normalize_url(self):
        """Test normalize_url function."""
        test_cases = [
            # Adding scheme
            ('example.com', 'http://example.com'),
            ('www.example.com', 'http://www.example.com'),
            
            # Preserving existing scheme
            ('http://example.com', 'http://example.com'),
            ('https://example.com', 'https://example.com'),
            
            # Handling paths
            ('example.com/path', 'http://example.com/path'),
            ('http://example.com/path/', 'http://example.com/path/'),
            
            # Handling query params
            ('example.com?q=test', 'http://example.com?q=test'),
            ('http://example.com/?q=test', 'http://example.com/?q=test'),
            
            # Handling ports
            ('example.com:8080', 'http://example.com:8080'),
            ('http://example.com:80', 'http://example.com:80'),
            
            # Handling fragments (should be removed)
            ('example.com#section', 'http://example.com'),
            ('http://example.com/#section', 'http://example.com/'),
        ]
        
        # Time individual function calls
        for input_url, expected_url in test_cases:
            start = time.time()
            result = normalize_url(input_url)
            end = time.time()
            self.assertEqual(result, expected_url)
            print(f"  normalize_url({input_url!r}): {(end-start):.6f} seconds")

    def test_get_domain(self):
        """Test get_domain function."""
        test_cases = [
            # Simple domains
            ('http://example.com', 'example.com'),
            ('https://example.com', 'example.com'),
            ('example.com', 'example.com'),
            
            # With www
            ('http://www.example.com', 'www.example.com'),
            ('https://www.example.com', 'www.example.com'),
            ('www.example.com', 'www.example.com'),
            
            # Subdomains
            ('http://blog.example.com', 'blog.example.com'),
            ('https://sub.domain.example.com', 'sub.domain.example.com'),
            
            # With paths (should be ignored)
            ('http://example.com/path', 'example.com'),
            ('https://example.com/path/to/resource.html', 'example.com'),
            
            # With query parameters (should be ignored)
            ('http://example.com?param=value', 'example.com'),
            
            # With ports (should be included)
            ('http://example.com:8080', 'example.com:8080'),
            ('https://example.com:443', 'example.com:443'),
            
            # IP addresses
            ('http://192.168.1.1', '192.168.1.1'),
            ('https://127.0.0.1:8080', '127.0.0.1:8080'),
        ]
        
        # Time individual function calls
        for input_url, expected_domain in test_cases:
            start = time.time()
            result = get_domain(input_url)
            end = time.time()
            self.assertEqual(result, expected_domain)
            print(f"  get_domain({input_url!r}): {(end-start):.6f} seconds")

    @patch('requests.head')
    def test_check_site_availability_success(self, mock_head):
        """Test site availability check with successful responses."""
        # Mock successful responses
        for status_code in [200, 201, 301, 302, 307, 308]:
            mock_response = Mock()
            mock_response.status_code = status_code
            mock_head.return_value = mock_response
            
            start = time.time()
            result = check_site_availability('http://example.com')
            end = time.time()
            
            self.assertTrue(result)
            print(f"  check_site_availability(status={status_code}): {(end-start):.6f} seconds")

    @patch('requests.head')
    def test_check_site_availability_failure(self, mock_head):
        """Test site availability check with error responses."""
        # Mock error responses
        for status_code in [400, 403, 404, 500, 503]:
            mock_response = Mock()
            mock_response.status_code = status_code
            mock_head.return_value = mock_response
            
            start = time.time()
            result = check_site_availability('http://example.com')
            end = time.time()
            
            self.assertFalse(result)
            print(f"  check_site_availability(status={status_code}): {(end-start):.6f} seconds")

    @patch('requests.head')
    def test_check_site_availability_exceptions(self, mock_head):
        """Test site availability check with various exceptions."""
        from requests.exceptions import ConnectionError, Timeout, RequestException
        
        exceptions = [ConnectionError, Timeout, RequestException]
        
        for exception in exceptions:
            mock_head.side_effect = exception()
            
            start = time.time()
            result = check_site_availability('http://example.com')
            end = time.time()
            
            self.assertFalse(result)
            print(f"  check_site_availability(exception={exception.__name__}): {(end-start):.6f} seconds")


def generate_timing_report():
    """Run the tests and generate a timing report."""
    print("\n" + "="*80)
    print("VALNARA URL VALIDATOR TIMING REPORT")
    print("="*80)
    print(f"Report generated at: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print("-"*80)
    
    # Run tests
    loader = unittest.TestLoader()
    suite = loader.loadTestsFromTestCase(TestUrlValidator)
    unittest.TextTestRunner(verbosity=2).run(suite)
    
    print("\n" + "="*80)
    print("END OF TIMING REPORT")
    print("="*80)


if __name__ == '__main__':
    generate_timing_report()