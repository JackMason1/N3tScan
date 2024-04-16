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