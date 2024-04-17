from urllib.parse import urlparse
import json


def load_urls_from_file(file_path):
    """
    Load URLs from a file, returning a list of URLs.
    Each line in the file should contain one URL.
    """
    with open(file_path, "r") as file:
        return [line.strip() for line in file if line.strip()]
