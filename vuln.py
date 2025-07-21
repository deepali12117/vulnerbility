import requests
import re

# Define regex patterns for sensitive data (expand patterns as needed)
patterns = {
    "API Key": r'(?i)api[_-]?key\s*[:=]\s*["\']?[A-Za-z0-9_\-]{16,}',
    "JWT Token": r'eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+',  # Basic JWT pattern
    "Email": r'[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+',
    "IP Address": r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b',
    "Authorization Header": r'Authorization\s*:\s*Bearer\s+[A-Za-z0-9\-\._~\+/]+=*',
    "Password": r'(?i)password\s*[:=]\s*["\']?[^"\'\s]+["\']?',
    "Private Key": r'-----BEGIN PRIVATE KEY-----.*?-----END PRIVATE KEY-----',
    "AWS Secret Key": r'(?i)aws_secret_access_key\s*[:=]\s*["\']?[A-Za-z0-9/+=]{40}["\']?',
}

def scan_response_content(response_text):
    leaks_found = {}

    for name, pattern in patterns.items():
        matches = re.findall(pattern, response_text, re.DOTALL)
        if matches:
            leaks_found[name] = matches

    return leaks_found

def test_api_responses(api_endpoints):
    for endpoint in api_endpoints:
        print(f'\nTesting endpoint: {endpoint}')
        try:
            resp = requests.get(endpoint)
            leaks = scan_response_content(resp.text)
            if leaks:
                print(f'Potential sensitive data leaks found:')
                for leak_type, items in leaks.items():
                    print(f' - {leak_type}: {items}')
            else:
                print('No sensitive data leaks detected.')
        except Exception as e:
            print(f'Error accessing {endpoint}: {e}')

if __name__ == '__main__':
    # List your API endpoints here
    api_urls = [
        'https://api.ganna.com/user/profile',
        'https://api.ganna.com/user/profile',
        # Add more endpoints as needed
    ]

    test_api_responses(api_urls)

    