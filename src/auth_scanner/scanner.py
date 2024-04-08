import requests


def check_authentication(url, access):
    """
    Check if the given URL requires authentication.
    Returns True if authentication is likely missing, False otherwise.
    """
    try:
        response = requests.get(url, allow_redirects=True)
        if response.status_code == 200:
            if access == "protected":
                print(
                    f"ERROR, Security Issue: {url} is protected but was accessed without authentication."
                )
                return True
            elif access == "public":
                print(f"SUCCESS: {url} is public and accessible as expected.")
                return False
        else:
            print(
                f"ERROR, Authentication required or error: {url} (Status: {response.status_code})"
            )
            return True

    except requests.RequestException as e:
        print(f"Error accessing {url}: {e}")
        return False
