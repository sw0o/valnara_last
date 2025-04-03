import requests
import re

def is_wordpress(url):
    url = url if url.startswith(('http://', 'https://')) else 'http://' + url
    
    try:
        response = requests.get(url, timeout=3, headers={
            'User-Agent': 'Mozilla/5.0',
            'Accept': 'text/html'
        })
        
        # Fastest possible checks
        quick_checks = [
            '/wp-content/' in response.text.lower(),
            '/wp-includes/' in response.text.lower(),
            'wordpress' in response.text.lower(),
            response.text.count('wp-') > 3
        ]
        
        return any(quick_checks)
    
    except:
        return False