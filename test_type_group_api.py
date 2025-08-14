#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Test script for Type/Group/Subgroup API endpoints
Tests both GET and POST endpoints with proper authentication
"""

import requests
import json
import sys
import urllib3
from datetime import datetime

# Disable SSL warnings for self-signed certificates
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Configuration
BASE_URL = "https://ticket-backoffice.git.or.th"  # IIS reverse proxy URL
# Alternative: BASE_URL = "http://10.10.1.53:5004"  # Direct backend URL

# Test JWT token (you'll need to get a real one from login)
TEST_JWT_TOKEN = None  # Will be set after login test

def print_separator(title):
    """Print a nice separator for test sections"""
    print("\n" + "="*60)
    print(f" {title}")
    print("="*60)

def test_login():
    """Test login to get JWT token"""
    global TEST_JWT_TOKEN
    
    print_separator("Testing Login to Get JWT Token")
    
    login_url = f"{BASE_URL}/api/login"
    
    # Test credentials (adjust as needed)
    login_data = {
        "username": "admin",  # Replace with actual admin username
        "password": "admin123"  # Replace with actual admin password
    }
    
    try:
        print(f"POST {login_url}")
        print(f"Data: {json.dumps(login_data, indent=2, ensure_ascii=False)}")
        
        response = requests.post(
            login_url, 
            json=login_data,
            verify=False,  # Skip SSL verification for self-signed certs
            timeout=10
        )
        
        print(f"Status Code: {response.status_code}")
        print(f"Response Headers: {dict(response.headers)}")
        
        if response.status_code == 200:
            result = response.json()
            print(f"Response: {json.dumps(result, indent=2, ensure_ascii=True)}")
            
            if 'access_token' in result:
                TEST_JWT_TOKEN = result['access_token']
                print(f"[OK] Login successful! JWT Token obtained.")
                return True
            else:
                print("[ERROR] Login response missing access_token")
                return False
        else:
            print(f"[ERROR] Login failed with status {response.status_code}")
            try:
                error_data = response.json()
                print(f"Error: {json.dumps(error_data, indent=2, ensure_ascii=True)}")
            except:
                print(f"Error text: {response.text}")
            return False
            
    except Exception as e:
        print(f"[ERROR] Login request failed: {str(e)}")
        return False

def test_get_type_group_subgroup():
    """Test GET /api/type-group-subgroup endpoint"""
    print_separator("Testing GET /api/type-group-subgroup")
    
    url = f"{BASE_URL}/api/type-group-subgroup"
    
    headers = {}
    if TEST_JWT_TOKEN:
        headers['Authorization'] = f'Bearer {TEST_JWT_TOKEN}'
    
    try:
        print(f"GET {url}")
        print(f"Headers: {json.dumps(headers, indent=2)}")
        
        response = requests.get(
            url,
            headers=headers,
            verify=False,  # Skip SSL verification
            timeout=10
        )
        
        print(f"Status Code: {response.status_code}")
        print(f"Response Headers: {dict(response.headers)}")
        
        if response.status_code == 200:
            result = response.json()
            print(f"[OK] GET request successful!")
            print(f"Response: {json.dumps(result, indent=2, ensure_ascii=False)}")
            
            # Validate response structure
            if 'success' in result and result['success']:
                if 'data' in result:
                    data = result['data']
                    print(f"\n[DATA] Data Structure Analysis:")
                    print(f"   - Types found: {list(data.keys()) if isinstance(data, dict) else 'Invalid'}")
                    
                    for type_name, groups in data.items():
                        if isinstance(groups, dict):
                            print(f"   - {type_name}: {list(groups.keys())}")
                            for group_name, subgroups in groups.items():
                                if isinstance(subgroups, list):
                                    print(f"     - {group_name}: {len(subgroups)} subgroups")
                    
                    return True
                else:
                    print("[ERROR] Response missing 'data' field")
                    return False
            else:
                print("[ERROR] Response indicates failure")
                return False
        else:
            print(f"[ERROR] GET request failed with status {response.status_code}")
            try:
                error_data = response.json()
                print(f"Error: {json.dumps(error_data, indent=2, ensure_ascii=False)}")
            except:
                print(f"Error text: {response.text}")
            return False
            
    except Exception as e:
        print(f"[ERROR] GET request failed: {str(e)}")
        return False

def test_post_type_group_subgroup():
    """Test POST /api/type-group-subgroup endpoint"""
    print_separator("Testing POST /api/type-group-subgroup")
    
    if not TEST_JWT_TOKEN:
        print("[ERROR] No JWT token available. Skipping POST test.")
        return False
    
    url = f"{BASE_URL}/api/type-group-subgroup"
    
    # Test data - updated configuration
    test_data = {
        "Service": {
            "Hardware": [
                "ลงทะเบียน USB",
                "ติดตั้งอุปกรณ์",
                "ทดสอบอุปกรณ์",
                "ตรวจสอบอุปกรณ์",
                "ซ่อมแซมอุปกรณ์"  # Added new item
            ],
            "Meeting": [
                "ติดตั้งอุปกรณ์ประชุม",
                "ขอ Link ประชุม / Zoom",
                "เชื่อมต่อ TV",
                "ขอยืมอุปกรณ์",
                "จองห้องประชุม"  # Added new item
            ],
            "Software": [
                "ติดตั้งโปรแกรม",
                "ตั้งค่าโปรแกรม",
                "ตรวจสอบโปรแกรม",
                "เปิดสิทธิ์การใช้งาน",
                "อัพเดทโปรแกรม"  # Added new item
            ]
        },
        "Helpdesk": {
            "Network": [
                "ปัญหาเครือข่าย",
                "ตั้งค่า WiFi",
                "ปัญหาอินเทอร์เน็ต",
                "ตรวจสอบความเร็วเน็ต"  # Added new item
            ],
            "System": [
                "ปัญหาระบบ",
                "อัพเดทระบบ",
                "ติดตั้งระบบ",
                "สำรองข้อมูล"  # Added new item
            ]
        },
        "Emergency": {  # Added new type
            "Critical": [
                "ระบบล่ม",
                "ข้อมูลสูญหาย",
                "ถูกแฮก"
            ]
        }
    }
    
    headers = {
        'Authorization': f'Bearer {TEST_JWT_TOKEN}',
        'Content-Type': 'application/json'
    }
    
    try:
        print(f"POST {url}")
        print(f"Headers: {json.dumps(headers, indent=2)}")
        print(f"Data: {json.dumps(test_data, indent=2, ensure_ascii=False)}")
        
        response = requests.post(
            url,
            json=test_data,
            headers=headers,
            verify=False,  # Skip SSL verification
            timeout=10
        )
        
        print(f"Status Code: {response.status_code}")
        print(f"Response Headers: {dict(response.headers)}")
        
        if response.status_code == 200:
            result = response.json()
            print(f"[OK] POST request successful!")
            print(f"Response: {json.dumps(result, indent=2, ensure_ascii=False)}")
            return True
        else:
            print(f"[ERROR] POST request failed with status {response.status_code}")
            try:
                error_data = response.json()
                print(f"Error: {json.dumps(error_data, indent=2, ensure_ascii=False)}")
            except:
                print(f"Error text: {response.text}")
            return False
            
    except Exception as e:
        print(f"[ERROR] POST request failed: {str(e)}")
        return False

def test_get_after_post():
    """Test GET after POST to verify data was updated"""
    print_separator("Testing GET After POST (Verify Update)")
    
    return test_get_type_group_subgroup()

def main():
    """Run all tests"""
    print("[TEST] Type/Group/Subgroup API Endpoint Tests")
    print(f"[TIME] Test started at: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"[URL] Base URL: {BASE_URL}")
    
    results = []
    
    # Test 1: Login (optional, for POST test)
    print("\n[AUTH] Note: Login test uses placeholder credentials.")
    print("       Update login_data in test_login() function with real credentials.")
    login_success = test_login()
    results.append(("Login", login_success))
    
    # Test 2: GET endpoint (works without auth)
    get_success = test_get_type_group_subgroup()
    results.append(("GET Type/Group/Subgroup", get_success))
    
    # Test 3: POST endpoint (requires auth)
    if login_success:
        post_success = test_post_type_group_subgroup()
        results.append(("POST Type/Group/Subgroup", post_success))
        
        # Test 4: GET after POST
        if post_success:
            get_after_post_success = test_get_after_post()
            results.append(("GET After POST", get_after_post_success))
    else:
        print("\n[WARN] Skipping POST tests due to login failure")
        print("       To test POST endpoint:")
        print("       1. Update login credentials in test_login() function")
        print("       2. Or manually set TEST_JWT_TOKEN variable")
    
    # Summary
    print_separator("Test Results Summary")
    for test_name, success in results:
        status = "[PASS]" if success else "[FAIL]"
        print(f"{status} - {test_name}")
    
    total_tests = len(results)
    passed_tests = sum(1 for _, success in results if success)
    
    print(f"\n[SUMMARY] Overall: {passed_tests}/{total_tests} tests passed")
    
    if passed_tests == total_tests:
        print("[SUCCESS] All tests passed! API endpoints are working correctly.")
    else:
        print("[WARNING] Some tests failed. Check the output above for details.")
    
    return passed_tests == total_tests

if __name__ == "__main__":
    try:
        success = main()
        sys.exit(0 if success else 1)
    except KeyboardInterrupt:
        print("\n\n[STOP] Tests interrupted by user")
        sys.exit(1)
    except Exception as e:
        print(f"\n\n[CRASH] Unexpected error: {str(e)}")
        sys.exit(1)
