import re
import ipaddress
import requests
from urllib.parse import urlparse
from requests.exceptions import RequestException, ConnectionError, Timeout

def validate_url(url):
    """
    Validate if the input string is a properly formated URL.
    
    Args:
        url (str): The URL to validate
        
    Returns:
        bool: True if URL is valed  False otherwise
        
    """
    if not url or not isinstance(url, str):
        return False
        
    if not url.startswith(('http://', 'https://')):
        url = 'http://' + url
    
    try:
        parsed = urlparse(url)
        if not parsed.netloc:
            return False
    except:
        return False
    
    if re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', parsed.netloc):
        ip_part = parsed.netloc.split(':')[0]
        try:
            ipaddress.IPv4Address(ip_part)
        except ValueError:
            return False
    else:
        domain_pattern = re.compile(
            r'^(([a-zA-Z0-9]|[a-zA-Z0-9][a-zA-Z0-9\-]*[a-zA-Z0-9])\.)*'
            r'([a-zA-Z0-9]|[a-zA-Z0-9][a-zA-Z0-9\-]*[a-zA-Z0-9])'
            r'(\.[a-zA-Z]{2,})?'
            r'(:\d+)?$'
        )
        
        if parsed.netloc == 'localhost' or parsed.netloc.startswith('localhost:'):
            pass
        elif not domain_pattern.match(parsed.netloc):
            return False
    
    path_query_pattern = re.compile(
        r'^(/[-a-zA-Z0-9%_.~]*)*'
        r'(\?[-a-zA-Z0-9%_.~=&]*)?$'
    )
    
    path_query = parsed.path
    if parsed.query:
        path_query += '?' + parsed.query
        
    if not path_query_pattern.match(path_query):
        return False
        
    return True

def check_site_availability(url):
    """
    Check if the site is available by sending a request.
    
    Args:
        url (str): The URL to check
        
    Returns:
        bool: True if site is available, False otherwise
    """
    if not url or not isinstance(url, str):
        return False
        
    if not url.startswith(('http://', 'https://')):
        url = 'http://' + url
    
    try:
        response = requests.head(url, timeout=10, allow_redirects=True)
        return response.status_code < 400
    except (ConnectionError, Timeout, RequestException):
        return False

def normalize_url(url):
    """
    Normalize the URL by adding scheme if missing and ensuring consistent format.
    
    Args:
        url (str): The URL to normalize
        
    Returns:
        str: Normalized URL
    """
    if not url or not isinstance(url, str):
        raise TypeError("URL must be a non-empty string")
        
    if not url.startswith(('http://', 'https://')):
        url = 'http://' + url
    
    parsed = urlparse(url)
    normalized_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
    if parsed.query:
        normalized_url += f"?{parsed.query}"
    
    return normalized_url

def get_domain(url):
    """
    Extract the domain from a URL.
    
    Args:
        url (str): The URL to extract domain from
        
    Returns:
        str: Domain name
    """
    if not url or not isinstance(url, str):
        raise TypeError("URL must be a non-empty string")
        
    if not url.startswith(('http://', 'https://')):
        url = 'http://' + url
    
    parsed = urlparse(url)
    return parsed.netloc
