from src.auth_scanner.scanner import *
from src.auth_scanner.util import *

import os
from dotenv import load_dotenv

load_dotenv()

host = os.getenv("HOST")


def missing_authentication_test(urls):
    print("---------- TEST 1: Starting scan for missing authentication... ----------")
    admin_payload = json.dumps({"email": "admin@juice-sh.op", "password": "admin123"})
    try:
        admin_session, _ = login(os.getenv("HOST"), admin_payload)
    except RuntimeError as e:
        print(f"Failed to login as admin: {e}")
        return

    user_payload = json.dumps({"email": "test-12345@example.com", "password": "12345"})
    try:
        user_session, _ = login(os.getenv("HOST"), user_payload)
    except RuntimeError as e:
        print(f"Failed to login as user: {e}")
        return

    endpoints = [
        "/rest/user/whoami",  # Requires authentication: Ensures only logged-in users can access user identity info.
        "/api/Users",  # Admin-only access: Prevents non-admin users from listing user accounts.
        "/api/PrivacyRequests",  # Privacy requests handling: Should be secured to process data privacy requests.
        "/#/administration",  # Admin panel: Strictly protected to allow only administrators.
    ]

    print("\n- Testing admin privileges... -")
    for endpoint in endpoints:
        test_endpoint_with_session(os.getenv("HOST"), endpoint, admin_session)

    print("\n- Testing user privileges... -")
    for endpoint in endpoints:
        test_endpoint_with_session(os.getenv("HOST"), endpoint, user_session)

    print("\n- Testing non-authorized session privileges... -")
    for endpoint in endpoints:
        test_endpoint_without_auth(os.getenv("HOST"), endpoint)
    print("\n---------- TEST 1 COMPLETE ----------\n")


def weak_authentication_test():
    print("---------- TEST 2: Starting scan for weak authentication... ----------\n")
    test_rate_limiting(
        os.getenv("HOST"), "admin@juice-sh.op", "12345"
    )  # Login with incorrect credentials
    test_weak_password_support(os.getenv("HOST"))
    print("\n---------- TEST 2 COMPLETE ----------\n")


def weak_encryption_test():
    print("---------- TEST 3: Starting scan for weak encryption... ----------\n")
    check_https(host)
    print("---------- TEST 3 COMPLETE ----------\n")


def missing_authorization_test():
    print("---------- TEST 4: Starting scan for missing authorization... ----------\n")
    admin_payload = json.dumps({"email": "admin@juice-sh.op", "password": "admin123"})
    try:
        admin_session, _ = login(os.getenv("HOST"), admin_payload)
    except RuntimeError as e:
        print(f"Failed to login as admin: {e}")
        return

    user_payload = json.dumps({"email": "test-12345@example.com", "password": "12345"})
    try:
        user_session, _ = login(host, user_payload)
    except RuntimeError as e:
        print(f"Failed to login as user: {e}")
        return

    access_another_user_basket(os.getenv("HOST"), user_session)
    access_another_user_basket(os.getenv("HOST"), admin_session)

    print("\n---------- TEST 4 COMPLETE ----------\n")


def weak_authorization_test():
    print("---------- TEST 5: Starting scan for weak authorization... ----------\n")

    print("---------- TEST 5 COMPLETE ----------\n")


def sensitive_data_test(urls):
    test6_results = []
    print("---------- TEST 6: Starting scan for sensitive data... ----------\n")
    for url, _ in urls:
        test6_result = check_for_data_leakage(url)
        test6_results.append(test6_result)

    for result in test6_results:
        if isinstance(result["message"], list):
            message_formatted = "\n".join(f"- {item}" for item in result["message"])
        else:
            message_formatted = f"- {result['message']}"

        print(f'{result["status"]}: {result["url"]}\n{message_formatted}\n')
    save_results("test6_results", test6_results)
    print("---------- TEST 6 COMPLETE ----------\n")


def uncontrolled_resources_tests(urls):
    test7_results = []
    print("---------- TEST 7: Starting uncontrolled resources check... ----------\n")
    test_file_path = "data/trash.txt"
    for url, _ in urls:
        test7_result = test_file_upload(url, test_file_path)
        test7_results.append(test7_result)
        print(
            f'Status {test7_result["status_code"]}: {test7_result["url"]}\n{test7_result["message"]}\n'
        )
    save_results("test7_results", test7_results)
    print("---------- TEST 7 COMPLETE ----------\n")


def insufficient_audit_test():
    test8_results = []
    print("---------- TEST 8: Starting scan for insufficient auditing... ----------")
    log_file = "data/mock_log_file.log"
    search_categories = {
        "Authentication": ["login", "logout"],
        "Authorization": ["access", "unauthorized", "authorized"],
        "Data Access": ["data", "file", "upload", "insert", "delete"],
    }

    for category, terms in search_categories.items():
        test8_results = analyze_logs(log_file, terms)

        if test8_results:
            print(f"\nFound the following entries related to {category}:")
            for result in test8_results:
                print(result, end="")
        else:
            print("WARNING: No relevant log entries found for this category.")
    save_results("test8_results", test8_results)
    print("---------- TEST 8 COMPLETE ----------\n")


def insufficient_session_management_test():
    print(
        "---------- TEST 9: Starting scan for insufficient session management... ----------"
    )
    # save_results("test9_results", test9_results)
    check_session_management("https://mv-juice-shop-4e9a0f3a9844.herokuapp.com/")
    print("---------- TEST 9 COMPLETE ----------\n")
