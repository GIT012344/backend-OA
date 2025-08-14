#!/usr/bin/env python3
"""
Test HTTPS connection to backend server
"""
import requests
import urllib3
import ssl
import socket
from datetime import datetime

# Disable SSL warnings for self-signed certificates
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

def test_ssl_certificate():
    """Test SSL certificate details"""
    print("=== SSL Certificate Test ===")
    try:
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        
        with socket.create_connection(('10.10.1.53', 5004), timeout=10) as sock:
            with context.wrap_socket(sock, server_hostname='10.10.1.53') as ssock:
                cert = ssock.getpeercert()
                print(f"SSL connection successful")
                print(f"Certificate Subject: {cert.get('subject', 'N/A')}")
                print(f"Certificate Issuer: {cert.get('issuer', 'N/A')}")
                print(f"Valid from: {cert.get('notBefore', 'N/A')}")
                print(f"Valid until: {cert.get('notAfter', 'N/A')}")
                
                # Check Subject Alternative Names
                san = cert.get('subjectAltName', [])
                if san:
                    print(f"Subject Alternative Names:")
                    for name_type, name_value in san:
                        print(f"   - {name_type}: {name_value}")
                
    except Exception as e:
        print(f"SSL connection failed: {str(e)}")

def test_https_endpoints():
    """Test HTTPS API endpoints"""
    print("\n=== HTTPS Endpoints Test ===")
    
    base_urls = [
        "https://10.10.1.53:5004",
        "https://ticket-backoffice.git.or.th:5004",
        "https://localhost:5004"
    ]
    
    endpoints = [
        "/api/health",
        "/api/tickets",
        "/api/login"
    ]
    
    for base_url in base_urls:
        print(f"\nTesting: {base_url}")
        
        for endpoint in endpoints:
            url = f"{base_url}{endpoint}"
            try:
                # Test with SSL verification disabled
                response = requests.get(url, verify=False, timeout=10)
                status = "OK" if response.status_code < 400 else "WARN"
                print(f"   {status} {endpoint}: HTTP {response.status_code}")
                
            except requests.exceptions.SSLError as e:
                print(f"   SSL {endpoint}: SSL Error - {str(e)}")
            except requests.exceptions.ConnectionError as e:
                print(f"   ERR {endpoint}: Connection Error - {str(e)}")
            except requests.exceptions.Timeout as e:
                print(f"   TIME {endpoint}: Timeout - {str(e)}")
            except Exception as e:
                print(f"   ERR {endpoint}: Error - {str(e)}")

def test_browser_compatibility():
    """Test browser compatibility"""
    print("\n=== Browser Compatibility Test ===")
    
    try:
        # Test with requests (similar to browser behavior)
        response = requests.get("https://10.10.1.53:5004/api/health", verify=True, timeout=10)
        print("OK Browser-like request with SSL verification: SUCCESS")
    except requests.exceptions.SSLError as ssl_error:
        print(f"SSL Browser-like request with SSL verification: SSL Error")
        print(f"   Error details: {str(ssl_error)}")
        print("   This is why browsers show 'Not Secure' warning")
        
        # Test without SSL verification
        try:
            response = requests.get("https://10.10.1.53:5004/api/health", verify=False, timeout=10)
            print(f"OK Same request without SSL verification: HTTP {response.status_code}")
            print("   Backend is working, only SSL trust issue")
        except Exception as e:
            print(f"ERR Backend connection failed: {str(e)}")
    
    except Exception as e:
        print(f"ERR Connection failed: {str(e)}")

if __name__ == "__main__":
    print(f"HTTPS Connection Test - {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print("=" * 60)
    
    test_ssl_certificate()
    test_https_endpoints()
    test_browser_compatibility()
    
    print("\n" + "=" * 60)
    print("Solutions:")
    print("1. For testing: Use browser 'Advanced' -> 'Proceed to site (unsafe)'")
    print("2. For permanent fix: Run import_certificate.bat as Administrator")
    print("3. For production: Get a trusted SSL certificate from a CA")
