from src.auth_scanner.scanner import *
from src.auth_scanner.util import *
from tests.test_scanner import *
from src.auth_scanner.authentication import *


def main():
    urls_file = "data/urls.txt"
    urls = load_urls_from_file(urls_file)

    process_urls(urls)

    missing_authentication_test(urls)
    # weak_authentication_test()
    # weak_encryption_test(urls)
    # missing_authorization_test("http://localhost:3000/#")
    # weak_authorization_test()
    # sensitive_data_test(urls)
    # uncontrolled_resources_tests(urls)
    # insufficient_audit_test()
    # insufficient_session_management_test()


if __name__ == "__main__":
    main()
