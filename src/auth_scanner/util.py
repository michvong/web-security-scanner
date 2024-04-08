def load_urls_from_file(file_path):
    """
    Load URLs and their expected access control from a file.
    """
    with open(file_path, "r") as file:
        urls = [
            (line.strip().split(",")[0], line.strip().split(",")[1])
            for line in file
            if line.strip()
        ]
    return urls
