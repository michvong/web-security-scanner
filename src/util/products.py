from src.util.authentication import *


def get_basket_url(server):
    return "{}/rest/basket".format(server)


def send_feedback(server, session, payload):
    """
    Submit feedback directly to the API.
    :param server: juice shop URL.
    :param session: Session
    :param payload: feedback content
    """
    submit = session.post(
        "{}/api/Feedbacks".format(server),
        headers={"Content-type": "application/json"},
        data=json.dumps(payload),
    )
    if not submit.ok:
        print("Error submitting feedback.\n")
    else:
        print("Sucessfully submitted evil feedback.")
