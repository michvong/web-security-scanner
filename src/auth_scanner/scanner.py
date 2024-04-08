import requests


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
