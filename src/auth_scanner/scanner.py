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
