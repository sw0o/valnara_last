import requests
import re

def is_wordpress(url):
    url = url if url.startswith(('http://', 'https://')) else 'http://' + url
    
    try:
        response = requests.get(url, timeout=3, headers={
            'User-Agent': 'Mozilla/5.0',
            'Accept': 'text/html'
        })
        
        html = response.text.lower()
        
   
        quick_checks = [
            '/wp-content/' in html,
            '/wp-includes/' in html,
            'wordpress' in html,
            html.count('wp-') > 3,
            'wp-admin' in html,
            'wp-login' in html
        ]
        
        if any(quick_checks):
            return True
            
        medium_checks = [
            'wpemoji' in html,
            'woocommerce' in html,
            'wp.customize' in html,
            'class="wp-' in html,
            'id="wp-' in html,
            '/wp-json/' in html,
            'plugins/elementor/' in html,
            'plugins/woocommerce/' in html,
            'plugins/contact-form-7/' in html
        ]
        
        if any(medium_checks):
            return True
            
        
        patterns = [
            r'_wpnonce=[a-zA-Z0-9]{10}',
            r'admin-ajax\.php',
            r'post-\d+',
            r'page-id-\d+',
            r'comment-\d+',
            r'themes/[^/]+/assets'
        ]
        
        for pattern in patterns:
            if re.search(pattern, html):
                return True
        
        return False
        
    except:
        return False