import requests
import json

proxies = {
    "http": "http://127.0.0.1:8080",
    "https": "http://127.0.0.1:8080",
}


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
    response = session.post(
        "{}/rest/user/login".format(server),
        headers=headers,
        data=payload,
        proxies=proxies,
    )
    if not response.ok:
        raise RuntimeError("Error logging in. Content: {}".format(response.content))
    token = response.json().get("token")
    session.cookies.set("token", token, proxies=proxies)
    session.headers.update(
        {"Authorization": "Bearer {}".format(token)}, proxies=proxies
    )
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
