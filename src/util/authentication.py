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
    Login through the REST API and return a Session with auth header and token in cookie
    :param server: juice shop URL
    :param payload: JSON payload required for auth
    :param headers: optional headers to use for the request. Sets content-type to JSON if omitted.
    :return: Session
    """
    session = requests.Session()

    if headers is None:
        headers = {"Content-Type": "application/json"}
    response = session.post(f"{server}/rest/user/login", headers=headers, data=payload)
    if not response.ok:
        raise RuntimeError(
            f"Error logging in. Status: {response.status_code}, Content: {response.text}"
        )

    token = response.json().get("authentication", {}).get("token")
    if token:
        session.cookies.set("token", token)
        session.headers.update({"Authorization": f"Bearer {token}"})

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
        "{}/api/Users".format(server),
        headers={"Content-Type": "application/json"},
        data=payload,
        proxies=proxies,
    )
    if not response.ok:
        raise RuntimeError("Error creating user {}".format(email))


def whoami(server, session):
    """
    Check current user details
    :param server: juice shop URL
    :param session: Session
    :return: response body as dict
    """
    who = session.get(
        "{}/rest/user/whoami".format(server),
        headers={"Accept": "application/json"},
    )
    if not who.ok:
        raise RuntimeError("Error retrieving current user details")
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
