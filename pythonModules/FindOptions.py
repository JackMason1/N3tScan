import requests
from concurrent.futures import ThreadPoolExecutor

timeout_value = 5
# Define the HTTP methods to check
http_methods = ['OPTIONS', 'PROPFIND', 'TRACK', 'TRACE', 'DEBUG']

# Function to check if an HTTP method is allowed by making a request and observing the response
def check_method(method, url):
    try:
        response = requests.request(method, url, verify=False, timeout=timeout_value)
        if response.status_code // 100 == 2:
            return method.lower(), True
        else:
            return method.lower(), False
    except requests.RequestException as e:
        return method.lower(), False



def findOptions(IP_addresses, timeout, threads_value):
    global timeout_value
    timeout_value = timeout
    for address in IP_addresses:
        for host in address['host']:
            for port in address['ports']:

                url = f"{port['service']}://{host}:{port['port']}"
                print (f"Checking: {url}") # Construct the URL, assuming HTTP protocol and port from your data structure
                with ThreadPoolExecutor(max_workers=5) as executor:
                    results = {method: status for method, status in executor.map(lambda method: check_method(method, url), http_methods)}
                port["Options"] = results
    return (IP_addresses)



#print (FindOptions([{"host": ["www.jackmason.com"], "ports": [{"port": 443, "service": "https", "headers": {"X-Frame-Options": {"value": "Missing!", "color": "orange"}, "X-Content-Type-Options": {"value": "nosniff", "color": "plain"}, "Content-Security-Policy": {"value": "*", "color": "yellow"}, "Strict-Transport-Security": {"value": "max-age=31536000; includeSubDomains; preload;", "color": "plain"}}, "headers_to_remove": {"server": {"data": "Apache", "vulnerability": "None", "colour": "plain"}, "X-Xss-Protection": {"data": "1; mode=block", "vulnerability": "X-XSS-Protection Deprectaed", "colour": "yellow"}}, "direct_ip_access": "False", "content_length": "True", "screenshot": "static/screenshots/jackmason.com:443.png", "intresting_links": {"robots_status": "False", "sitemap_status": "False", "admin_page_status": "False"}, "cookies": [{"name": "PHPSESSID", "value": "pesh1g0389g0q8n5j48c3norl5", "path": "/", "domain": "www.jackmason.com", "secure": "false", "httpOnly": "false", "sameSite": "None"}], "software": [{"library": "jQuery", "version": "1.12.4", "latest_version": "3.7.1", "discover": "jQuery().jquery", "outdated": "true", "officialName": "jquery", "cve": [{"cve": "CVE-2020-11022", "score": "6.5", "level": "medium"}, {"cve": "CVE-2020-11023", "score": "6.3", "level": "medium"}]}]}]}]))