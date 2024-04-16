from src.auth_scanner.scanner import *
from src.auth_scanner.util import *

import os
from dotenv import load_dotenv

load_dotenv()


def missing_authentication_test(urls):
    test1_results = []
    print("---------- TEST 1: Starting scan for missing authentication... ----------\n")
    for url, access in urls:
        test1_result = check_authentication(url, access)
        test1_results.append(test1_result)
        print(
            f'{test1_result["status"]} (Status: {test1_result["status_code"]}): {test1_result["url"]}\n{test1_result["message"]}\n'
        )
    save_results("test1_results", test1_results)
    print("---------- TEST 1 COMPLETE ----------\n")


def weak_authentication_test():
    print("---------- TEST 2: Starting scan for weak authentication... ----------\n")
    test_rate_limiting(
        os.getenv("HOST"), "admin@juice-sh.op", "12345"
    )  # Login with incorrect credentials
    test_weak_password_support(os.getenv("HOST"))
    print("\n---------- TEST 2 COMPLETE ----------\n")


def weak_encryption_test(urls):
    test3_results = []
    print("---------- TEST 3: Starting scan for weak encryption... ----------\n")
    for url, _ in urls:
        test3_result = check_https(url)
        test3_results.append(test3_result)
        print(
            f'{test3_result["status"]} (Protocol: {test3_result["protocol"]}): {test3_result["url"]}\n{test3_result["message"]}\n'
        )
    save_results("test3_results", test3_results)
    print("---------- TEST 3 COMPLETE ----------\n")


def missing_authorization_test(base_url):
    print("---------- TEST 4: Starting scan for missing authorization... ----------\n")
    user_credentials = {
        "email": "user@example.com",  # Normal user
        "password": "password123",
    }

    # admin_credentials = {
    #     "email": "admin@juice-sh.op",  # Admin user
    #     "password": "admin123",
    # }

    # Login as normal user
    proxies = {
        "http": "http://127.0.0.1:8080",
        "https": "http://127.0.0.1:8080",
    }
    user_session = requests.Session()
    user_login_response = user_session.post(
        f"{base_url}/rest/user/login", data=user_credentials, proxies=proxies
    )
    print(user_login_response)

    # Login as admin
    # admin_session = requests.Session()
    # admin_login_response = admin_session.post(
    #     f"{base_url}/rest/user/login", data=admin_credentials
    # )

    admin_only_url = f"{base_url}/administration"
    attempt_unauthorized_access(base_url, user_session, admin_only_url)
    # attempt_unauthorized_access(base_url, admin_session, admin_only_url)
    print("---------- TEST 4 COMPLETE ----------\n")


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
