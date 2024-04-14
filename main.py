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
        print(
            f'{test1_result["status"]} (Status: {test1_result["status_code"]}): {test1_result["url"]}\n{test1_result["message"]}\n'
        )
    save_results("test1_results", test1_results)
    print("---------- TEST 1 COMPLETE ----------\n")

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

    # test7_results = []
    # print("---------- TEST 7: Starting uncontrolled resources check... ----------\n")
    # test_file_path = "data/test.sh"
    # for url, _ in urls:
    #     test7_result = test_file_upload(url, test_file_path)
    #     test7_results.append(test7_result)
    #     print(f'Status {test7_result["status_code"]}: {test7_result["url"]}\n{test7_result["message"]}\n')
    # save_results("test7_results", test7_results)
    # print("---------- TEST 7 COMPLETE ----------\n")

    # test8_results = []
    # print("---------- TEST 8: Starting scan for insufficient auditing... ----------")
    # log_file = 'data/mock_log_file.log'
    # search_categories = {
    #     'Authentication': ['login', 'logout'],
    #     'Authorization': ['access', 'unauthorized', 'authorized'],
    #     'Data Access': ['data', 'file', 'upload', 'insert', 'delete']
    # }

    # for category, terms in search_categories.items():
    #     test8_results = analyze_logs(log_file, terms)

    #     if test8_results:
    #         print(f"\nFound the following entries related to {category}:")
    #         for result in test8_results:
    #             print(result, end='')
    #     else:
    #         print("WARNING: No relevant log entries found for this category.")
    # save_results("test8_results", test8_results)
    # print("---------- TEST 8 COMPLETE ----------\n")

    # print(
    #     "---------- TEST 9: Starting scan for insufficient session management... ----------"
    # )
    # save_results("test9_results", test9_results)
    # check_session_management("https://mv-juice-shop-4e9a0f3a9844.herokuapp.com/")
    # print("---------- TEST 9 COMPLETE ----------\n")


if __name__ == "__main__":
    main()
