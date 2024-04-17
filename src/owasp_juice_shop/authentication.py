import requests
import json
import os
from dotenv import load_dotenv

load_dotenv()

proxies = {
    "http": os.getenv("HTTP_PROXY"),
    "https": os.getenv("HTTPS_PROXY"),
}


def login_as_admin(server):
    """
    Log in legitimately as an admin.
    :param server: juice shop URL
    :return: Session
    """
    payload = json.dumps({"email": "admin@juice-sh.op", "password": "admin123"})
    return login(server, payload)


def login(server, payload, headers=None):
    """
    Login through the REST API and return a Session with auth header and token in cookie.
    :param server: Juice shop URL.
    :param payload: JSON payload required for auth, should be a dict.
    :param headers: Optional headers to use for the request. Sets content-type to JSON if omitted.
    :return: Session
    """
    session = requests.Session()

    # Ensure headers are set to handle JSON content
    if headers is None:
        headers = {"Content-Type": "application/json"}

    # Ensure payload is properly formatted as JSON
    if isinstance(payload, dict):
        payload = json.dumps(payload)

    response = session.post(f"{server}/rest/user/login", headers=headers, data=payload)

    # Check if the login was successful
    if response.ok:
        try:
            # Attempt to parse the JSON token
            token_data = response.json().get("authentication", {})
            token = token_data.get("token")
            if token:
                session.cookies.set(
                    "token", token, path="/"
                )  # Ensure the path is correctly set
                session.headers.update({"Authorization": f"Bearer {token}"})
        except ValueError:
            # Handle JSON decode error
            print(f"Failed to decode JSON from response: {response.text}")
            raise RuntimeError("Invalid JSON response received.")
    else:
        # Handle unsuccessful login attempts
        print(
            f"Error logging in. Status: {response.status_code}, Content: {response.text}\n"
        )
        raise RuntimeError("Login failed with status: {}".format(response.status_code))

    return session, response


def create_user(server, email, password):
    """
    Create new user account through the API.
    :param server: juice shop URL.
    :param email: email address(unvalidated by server!)
    :param password: password
    """
    payload = json.dumps(
        {
            "email": email,
            "password": password,
            "passwordRepeat": password,
            "securityQuestion": {"id": 1, "answer": "test"},
        }
    )
    session = requests.Session()
    response = session.post(
        f"{server}/api/Users",
        headers={"Content-Type": "application/json"},
        data=payload,
        proxies=proxies,
    )
    if not response.ok:
        print(f"Error creating user {email}")


def whoami(server, session):
    """
    Check current user details
    :param server: juice shop URL
    :param session: Session
    :return: response body as dict
    """
    who = session.get(
        f"{server}/rest/user/whoami",
        headers={"Accept": "application/json"},
    )
    if not who.ok:
        print("Error retrieving current user details")
    return who.json()


def get_current_user_id(server, session):
    """
    Retrieve current user's ID #
    :param server: juice shop URL
    :param session: Session
    :return: ID as int
    """
    return whoami(server, session).get("user", {}).get("id")


def get_current_user_email(server, session):
    """
    Retrieve current user's email
    :param server: juice shop URL
    :param session: Session
    :return: email as string
    """
    return whoami(server, session).get("user", {}).get("email")
