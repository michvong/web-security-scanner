from urllib.parse import urlparse

from src.auth_scanner.scanner import *
from src.auth_scanner.util import *


def main():
    urls_file = "data/urls.txt"
    urls = load_urls_from_file(urls_file)

    print("---------- TEST 1: Starting scan for missing authentication... ----------\n")
    for url, access in urls:
        parsed_url = urlparse(url)
        if not parsed_url.scheme:
            print(f"Invalid URL format: {url}")
            continue

        check_authentication(url, access)

    print("\nScan completed.")


if __name__ == "__main__":
    main()
