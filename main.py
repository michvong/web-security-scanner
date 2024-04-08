from src.auth_scanner.scanner import *
from src.auth_scanner.util import *


def main():
    urls_file = "data/urls.txt"
    urls = load_urls_from_file(urls_file)

    process_urls(urls)

    test1_results = []
    print("---------- TEST 1: Starting scan for missing authentication... ----------\n")
    for url, access in urls:
        test1_result = check_authentication(url, access)
        test1_results.append(test1_result)
        print(f"{test1_result['status']} (Status: {test1_result['status_code']}): {test1_result['url']}\n{test1_result["message"]}\n")
        save_results("test1_results", test1_results)

    print("---------- TEST 1 COMPLETE ----------\n")


if __name__ == "__main__":
    main()
