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
        print(f"{test1_result["status"]} (Status: {test1_result["status_code"]}): {test1_result['url']}\n{test1_result["message"]}\n")
    save_results("test1_results", test1_results)
    print("---------- TEST 1 COMPLETE ----------\n")


    test3_results = []
    print("---------- TEST 3: Starting scan for weak encryption... ----------\n")
    for url, _ in urls:
        test3_result = check_https(url)
        test3_results.append(test3_result)
        print(f'{test3_result["status"]} (Protocol: {test3_result["protocol"]}): {test3_result["url"]}\n{test3_result["message"]}\n')
    save_results("test3_results", test3_results)
    print("---------- TEST 3 COMPLETE ----------\n")

    test6_results = []
    print("---------- TEST 6: Starting scan for sensitive data... ----------\n")
    for url, _ in urls:
        test6_result = check_for_data_leakage(url)
        test6_results.append(test6_result)
        message_formatted = "\n".join(f'- {item}' for item in test6_result["message"])
        print(f'{test6_result["status"]}: {test6_result["url"]}\n{message_formatted}\n')
    save_results("test6_results", test6_results)
    print("---------- TEST 6 COMPLETE ----------\n")


if __name__ == "__main__":
    main()
