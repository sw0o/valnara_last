import requests

def is_wordpress(url):
    if not url.startswith(('http://', 'https://')):
        url = 'http://' + url

    try:
        headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64)'
        }
        response = requests.get(url, headers=headers, timeout=10)
        
        content = response.text.lower()
        
        wordpress_indicators = [
            '/wp-content/',
            '/wp-includes/',
            'generator" content="wordpress',
            'wordpress.org'
        ]
        
        for indicator in wordpress_indicators:
            if indicator in content:
                return True
        
        return False
    
    except Exception as e:
        print(f"WordPress detection error: {e}")
        return False