from src.auth_scanner.scanner import *
from src.auth_scanner.util import *
from tests.test_scanner import *
from src.util.authentication import create_user

import os
from dotenv import load_dotenv

load_dotenv()


def main():
    urls_file = "data/urls.txt"
    urls = load_urls_from_file(urls_file)

    create_user(os.getenv("HOST"), os.getenv("USER_EMAIL"), os.getenv("USER_PASSWORD"))

    missing_authentication_test()
    weak_authentication_test()
    weak_encryption_test()
    missing_authorization_test()
    weak_authorization_test()
    sensitive_data_test(urls)
    uncontrolled_resources_tests()
    insufficient_audit_test()
    insufficient_session_management_test()


if __name__ == "__main__":
    main()
