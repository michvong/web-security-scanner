from src.util.authentication import *
from src.util.products import *

import requests
import json
from urllib.parse import urlparse
from dotenv import load_dotenv

load_dotenv()

proxies = {
    "http": os.getenv("HTTP_PROXY"),
    "https": os.getenv("HTTPS_PROXY"),
}


def test_endpoint_with_session(server, endpoint, session):
    """
    Test the specified endpoint with a given session.
    """
    response = session.get(
        f"{server}{endpoint}",
    )
    if response.status_code == 200:
        print(
            f"Access to {endpoint} successful with session: Status code {response.status_code}"
        )
    else:
        print(
            f"Access to {endpoint} failed with session: Status code {response.status_code}"
        )


def test_endpoint_without_auth(server, endpoint):
    """
    Test endpoint without any authentication.
    """
    response = requests.get(f"{server}{endpoint}")
    if response.status_code == 200:
        print(f"Security Issue: {endpoint} is accessible without authentication.")
    else:
        print(
            f"No access without authentication to {endpoint}: Status Code {response.status_code}"
        )


def test_rate_limiting(base_url, email, password):
    """
    Test for rate limiting by trying to login multiple times.
    """
    login_credentials = {"email": email, "password": password}
    login_payload = json.dumps(login_credentials)
    for i in range(10):
        try:
            authenticated_session, response = login(base_url, login_payload)
            print(f"Attempt {i+1}, Status: {response.status_code}")
        except RuntimeError as e:
            print(f"Attempt {i+1}, Login failed: {e}")
            if "429" in str(e):
                print("Rate limiting detected.")
                return
    print("Rate limiting not detected.\n")


def test_weak_password_support(base_url):
    """
    Test password strength enforcement by attempting to register users with various password complexities.
    """
    # Test cases for various password strengths
    passwords = [
        "123",  # Too short, no digit, symbol, uppercase, or lowercase
        "12345",  # Minimum length, no digit, symbol, uppercase, or lowercase
        "abcdefgh",  # No digit, symbol, or uppercase
        "ABCD1234",  # No lowercase or symbol
        "abcd1234",  # No uppercase or symbol
        "abcdABCD",  # No digit or symbol
        "!abcdAB1",  # Strong: has digit, symbol, uppercase, and lowercase
    ]

    results = {}
    for password in passwords:
        email = f"test-{password}@example.com"  # Unique email for each test case
        try:
            create_user(base_url, email, password)
            results[password] = "Weak password accepted, weak authentication detected."
        except RuntimeError as e:
            results[password] = (
                f"Weak password rejected, strong authentication measures in place. {str(e)}"
            )

    for password, result in results.items():
        print(f"Password: {password} -> {result}")


def check_https(url):
    parsed_url = urlparse(url)
    if parsed_url.scheme == "https":
        print(
            url
            + ": HTTP protocol is used, data is safely encrypted in transmissions.\n"
        )
    else:
        print(url + ": HTTPS protocol is not used, data is NOT safe.\n")


def access_another_user_basket(server, session):
    """
    If we're admin(ID 1), open basket 2. Anybody else, open the ID below us.
    :param server: juice shop URL
    :param session: Session
    """
    current_user_id = get_current_user_id(server, session)
    current_user_email = get_current_user_email(server, session)

    if current_user_id == 1:
        targetid = current_user_id + 1
    else:
        targetid = current_user_id - 1
    basket = session.get("{}/{}".format(get_basket_url(server), targetid))
    if not basket.ok:
        print(f"Error accessing basket {targetid} as {current_user_email}")
    else:
        print(
            f"Successfully accessed another user's basket {targetid} as {current_user_email}"
        )


def submit_feedback_as_another_user(server, session, user_id):
    current_user_id = get_current_user_id(server, session)
    payload = {
        "comment": "I'm submitting evil feedback!",
        "UserId": user_id,
    }
    print(
        f"Submitting feedback from user ID {current_user_id} as user ID {user_id}..."
    ),
    send_feedback(server, session, payload)


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
    Attempts to upload a file to the given URL using an authenticated session.

    :param url: The base URL where the file should be uploaded.
    :param filepath: The path to the file to be uploaded.
    :param form_field_name: The name of the form field used for the file upload.
    """
    session = requests.Session()
    jsurl = f"{url}/rest/user/login"
    file_upload_url = f"{url}/file-upload"

    auth_payload = json.dumps({"email": "admin@juice-sh.op", "password": "whocares"})

    login_response = session.post(
        jsurl, headers={"Content-Type": "application/json"}, data=auth_payload
    )
    if not login_response.ok:
        return {
            "url": url,
            "status_code": login_response.status_code,
            "message": "Failed to log in. Check credentials and URL.",
        }

    try:
        with open(filepath, "rb") as infile:
            files = {
                form_field_name: ("filename.ext", infile, "application/octet-stream")
            }
            upload_response = session.post(file_upload_url, files=files)
            if upload_response.ok:
                return {
                    "url": file_upload_url,
                    "status_code": upload_response.status_code,
                    "message": f"File '{filepath}' was successfully uploaded.",
                }
            else:
                return {
                    "url": file_upload_url,
                    "status_code": upload_response.status_code,
                    "message": f"Failed to upload '{filepath}'. Server responded with status code: {upload_response.status_code}",
                }
    except Exception as e:
        return {"url": file_upload_url, "message": f"Error during file upload: {e}"}


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


def check_session_management(url):
    login_url = f"{url}/rest/user/login"
    logout_url = f"{url}/rest/user/logout"

    user_details = {"email": "admin@juice-sh.op", "password": "admin123"}

    with requests.Session() as session:
        response = session.post(login_url, json=user_details)

        if response.status_code == 200:
            print("Login successful.")
            cookies = session.cookies
            for cookie in cookies:
                print(f"Cookie {cookie.name} attributes:")
                attributes = []
                if "Secure" in cookie._rest:
                    attributes.append("Secure")
                if "HttpOnly" in cookie._rest:
                    attributes.append("HttpOnly")
                print(", ".join(attributes) or "No Secure/HttpOnly attributes set")

        else:
            print("Failed to login.")

        response = session.get(logout_url)
        if response.status_code == 200:
            print("Logout successful.")

        # Try to access a protected resource after logging out
        response = session.get(f"{url}/api/ProtectedResource")
        if response.status_code == 401:
            print("Session properly invalidated after logout.")
        else:
            print("Session may not be properly invalidated after logout.")
