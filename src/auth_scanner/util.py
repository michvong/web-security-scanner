from urllib.parse import urlparse
import json


def process_urls(urls):
    for url, access in urls:
        parsed_url = urlparse(url)
        if not parsed_url.scheme:
            print(f"Invalid URL format: {url}\n")
            continue

        if access not in (True, False):
            print(f"Invalid access format: {access}\n")
            continue


def load_urls_from_file(file_path):
    """
    Load URLs and their protection status from a file, returning a list of tuples.
    """
    with open(file_path, "r") as file:
        return [
            (line.strip().split(",")[0], line.strip().split(",")[1] == "True")
            for line in file
            if line.strip()
        ]


def save_results(test_type, results):
    with open(f"reports/{test_type}.json", "w") as file:
        json.dump(results, file, indent=4)
