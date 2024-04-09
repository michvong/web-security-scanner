import requests
from urllib.parse import urlparse


def check_authentication(url, access):
    """
    Check if the given URL requires authentication.
    """
    try:
        response = requests.get(url, allow_redirects=True)
        if response.status_code == 200:
            if access == "protected":
                return {
                    "url": url,
                    "access": access,
                    "status": "ERROR",
                    "status_code": response.status_code,
                    "message": "Protected but was accessed without authentication.",
                }
            elif access == "public":
                return {
                    "url": url,
                    "access": access,
                    "status": "SUCCESS",
                    "status_code": response.status_code,
                    "message": "Public and accessible as expected.",
                }
        else:
            return {
                "url": url,
                "access": access,
                "status": "ERROR",
                "status_code": response.status_code,
                "message": f"Authentication required or error.",
            }

    except requests.RequestException as e:
        return {
            "url": url,
            "access": access,
            "status": "ERROR",
            "message": f"Error accessing {url}: {e}",
        }


def check_https(url):
    parsed_url = urlparse(url)
    if parsed_url.scheme == "https":
        return {
            "url": url,
            "protocol": parsed_url.scheme,
            "status": "SUCCESS",
            "message": "Data is safely encrypted in transmissions.",
        }
    else:
        return {
            "url": url,
            "protocol": parsed_url.scheme,
            "status": "ERROR",
            "message": "Data is NOT safe.",
        }


def check_for_data_leakage(url):
    """
    Sends a request to the URL and checks the response for potential data leakage.
    """
    try:
        response = requests.get(url)
        leaks_detected = []

        # Check for sensitive data in headers
        for header in ["Server", "X-Powered-By", "Set-Cookie"]:
            if header in response.headers:
                leaks_detected.append(
                    f"Sensitive header information found: {header} - {response.headers[header]}"
                )

        # Basic check for common sensitive error messages
        common_errors = ["database", "SQL", "username", "password"]
        for error in common_errors:
            if error in response.text:
                leaks_detected.append(
                    f"Possible sensitive error message found containing: '{error}'"
                )

        if leaks_detected:
            return {"url": url, "status": "WARNING", "message": leaks_detected}
        else:
            return {
                "url": url,
                "status": "OK",
                "message": "No obvious data leakage detected.",
            }
    except requests.RequestException as e:
        return {
            "url": url,
            "status": "ERROR",
            "message": str(e),
        }


def test_file_upload(url, filepath, form_field_name="file"):
    """
    Attempts to upload a file to the given URL.

    :param url: The URL where the file should be uploaded.
    :param filepath: The path to the file to be uploaded.
    :param form_field_name: The name of the form field used for the file upload.
    """
    files = {form_field_name: open(filepath, "rb")}
    try:
        response = requests.post(url, files=files)
        if response.status_code == 200:
            return {
                "url": url,
                "status_code": response.status_code,
                "message": f"'{filepath}' was successfully uploaded.",
            }
        else:
            return {
                "url": url,
                "status_code": response.status_code,
                "message": f"'{filepath}' could not be uploaded.",
            }
    except Exception as e:
        print(f"Error during file upload: {e}")
    finally:
        files[form_field_name].close()


def analyze_logs(log_file_path, search_terms):
    """
    Analyze log files for specified search terms and return matches.

    :param log_file_path: Path to the log file.
    :param search_terms: A list of terms to search for in the log entries.
    :return: List of matching log entries.
    """
    matches = []
    with open(log_file_path, "r") as file:
        for line in file:
            if any(term in line.lower() for term in search_terms):
                matches.append(line)

    return matches
