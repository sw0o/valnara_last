import requests

def is_wordpress(url):

    api_key = "w43u2hdtv0t1mbb60321aakv8zbvqj0k2f682afp1y3r7b6rlrq0262bd250ibho20zsa6"
    api_url = "https://whatcms.org/API/Tech"
    
    try:
        response = requests.get(api_url, params={"key": api_key, "url": url})
        data = response.json()
        
        if data.get("result", {}).get("code") == 200:
            for tech in data.get("results", []):
                if tech.get("name", "").lower() == "wordpress":
                    return True
        return False
    except:
        return False
    
    """
    
    Output cases:
    - Returns True: wp detected 
    - Returns False: In the following cases:
      - WordPress is not detected but API call succeeded
      - errors
    """