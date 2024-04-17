from src.auth_scanner.scanner import *
from src.auth_scanner.util import *

import os
from dotenv import load_dotenv

load_dotenv()

host = os.getenv("HOST")
admin_email = os.getenv("ADMIN_EMAIL")
admin_password = os.getenv("ADMIN_PASSWORD")
user_email = os.getenv("USER_EMAIL")
user_password = os.getenv("USER_PASSWORD")


def missing_authentication_test():
    print("---------- TEST 1: Starting scan for missing authentication... ----------")
    admin_payload = json.dumps({"email": admin_email, "password": admin_password})
    try:
        admin_session, _ = login(os.getenv("HOST"), admin_payload)
    except RuntimeError as e:
        print(f"Failed to login as admin: {e}")
        return

    user_payload = json.dumps({"email": user_email, "password": user_password})
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
        os.getenv("HOST"), admin_email, "12345"
    )  # Login with incorrect credentials
    test_weak_password_support(os.getenv("HOST"))
    print("\n---------- TEST 2 COMPLETE ----------\n")


def weak_encryption_test():
    print("---------- TEST 3: Starting scan for weak encryption... ----------\n")
    check_https(host)
    print("---------- TEST 3 COMPLETE ----------\n")


def missing_authorization_test():
    print("---------- TEST 4: Starting scan for missing authorization... ----------\n")
    admin_payload = json.dumps({"email": admin_email, "password": admin_password})
    try:
        admin_session, _ = login(os.getenv("HOST"), admin_payload)
    except RuntimeError as e:
        print(f"Failed to login as admin: {e}")
        return

    user_payload = json.dumps({"email": user_email, "password": user_password})
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
    admin_payload = json.dumps({"email": admin_email, "password": admin_password})
    try:
        admin_session, _ = login(os.getenv("HOST"), admin_payload)
    except RuntimeError as e:
        print(f"Failed to login as admin: {e}")
        return

    user_payload = json.dumps({"email": user_email, "password": user_password})
    try:
        user_session, _ = login(host, user_payload)
    except RuntimeError as e:
        print(f"Failed to login as user: {e}")
        return

    normal_user_id = 2
    submit_feedback_as_another_user(host, admin_session, normal_user_id)

    admin_user_id = 1
    submit_feedback_as_another_user(host, user_session, admin_user_id)
    print("---------- TEST 5 COMPLETE ----------\n")


def sensitive_data_test(urls):
    test6_results = []
    print("---------- TEST 6: Starting scan for sensitive data... ----------\n")
    for url in urls:
        test6_result = check_for_data_leakage(url)
        test6_results.append(test6_result)

    for result in test6_results:
        if isinstance(result["message"], list):
            message_formatted = "\n".join(f"- {item}" for item in result["message"])
        else:
            message_formatted = f"- {result['message']}"

        print(f'{result["status"]}: {result["url"]}\n{message_formatted}\n')
    print("---------- TEST 6 COMPLETE ----------\n")


def uncontrolled_resources_tests():
    print("---------- TEST 7: Starting uncontrolled resources check... ----------\n")
    user_payload = json.dumps({"email": user_email, "password": user_password})
    try:
        user_session, _ = login(host, user_payload)
    except RuntimeError as e:
        print(f"Failed to login as user: {e}")
        return

    test_file_path = "data/trash.txt"
    test_file_upload(host, user_session, test_file_path)
    print("---------- TEST 7 COMPLETE ----------\n")


def insufficient_audit_test():
    test8_results = []
    print("---------- TEST 8: Starting scan for insufficient auditing... ----------\n")
    user_payload = json.dumps({"email": user_email, "password": user_password})
    try:
        user_session, _ = login(host, user_payload)
    except RuntimeError as e:
        print(f"Failed to login as user: {e}")
        return
    print("- Attempting to access support logs as normal user... -")
    test_endpoint_with_session(os.getenv("HOST"), "/support/logs", user_session)

    print("\n- Analyzing log file... -")
    log_file = os.getenv("LOG_FILE")
    search_categories = {
        "Authentication": ["login", "logout"],
        "Authorization": ["access", "unauthorized", "authorized"],
        "Data Access": ["data", "file", "upload", "insert", "delete"],
    }

    for category, terms in search_categories.items():
        test8_results = analyze_logs(log_file, terms)

        if test8_results:
            print(f"Found the following entries related to {category}:")
            for result in test8_results:
                print(result, end="")
        else:
            print(f"\nWARNING: No relevant log entries found for category: {category}.")
    print("\n---------- TEST 8 COMPLETE ----------\n")


def insufficient_session_management_test():
    print(
        "---------- TEST 9: Starting scan for insufficient session management... ----------\n"
    )
    admin_payload = json.dumps({"email": admin_email, "password": admin_password})
    try:
        user_session, _ = login(host, admin_payload)
    except RuntimeError as e:
        print(f"Failed to login as user: {e}")
        return
    check_session_management(user_session)
    print("\n---------- TEST 9 COMPLETE ----------\n")
