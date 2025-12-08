from .base import BaseHandler
from cms import config
from cms.db import Contest, Participation, User
from cms.grading.scoring import task_score
from cms.server.contest.authentication import get_password
from cms.service.ProxyService import ProxyExecutor
from cmscommon.crypto import hash_password
from cmscommon.datetime import make_timestamp

try:
    import tornado4.web as tornado_web
except ImportError:
    import tornado.web as tornado_web

from sqlalchemy.orm import contains_eager
from sqlalchemy.orm import joinedload
import json
import jwt
import logging
import requests
import secrets
from urllib.parse import urljoin, urlsplit
logger = logging.getLogger(__name__)

def get_jwt_payload(token):
    try:
        return jwt.decode(
            jwt=token,
            key=config.ddd_jwt_key,
            algorithms=[config.ddd_jwt_alg]
        )
    except jwt.exceptions.InvalidTokenError as e:
        return None

class DDDHandler(BaseHandler):
    def check_xsrf_cookie(self):
        """
        We are going to communicate with an external server. In this case, the xsrf cookie
        serves no purpose and is a hinderance.
        """
        pass

    def reset_ranking(self, old_name=None):
        reset_type = ProxyExecutor.USER_TYPE
        if old_name is not None:
            for ranking in config.rankings:
                try:
                    name = ProxyExecutor.RESOURCE_PATHS[reset_type]
                    url = urljoin(ranking,f"{name}/{old_name}")
                    auth = urlsplit(url)
                    res = requests.delete(url,
                        auth=(auth.username,auth.password),
                        headers={'content-type': 'application/json'},
                        verify=config.https_certfile)
                    if 400 <= res.status_code < 600:
                        logger.warning(f"{res.status_code} while resetting ranking")
                except requests.exceptions.RequestException as error:
                    # Likely because ranking server is not running
                    logger.warning(f"While resetting ranking got {error}")


        self.service.proxy_service.reinitialize()

class DDDNewUserHandler(DDDHandler):
    """DDD New User Handler
    """
    def post(self):
        token = self.get_argument("token")

        payload = get_jwt_payload(token)
        if payload is None:
            raise tornado_web.HTTPError(400)

        attrs = dict(
            first_name = payload["first_name"],
            last_name = payload["last_name"],
            username = payload["username"],
            email = payload["email"],
            # We give the user a completely random password.
            # This is not going to be saved anywhere, it is
            # only so that no one is going to be able to
            # actually log in without going throuh the DDD
            # system.
            password = hash_password(secrets.token_urlsafe(16)),
        )

        user = User(**attrs)
        self.sql_session.add(user)
        self.sql_session.flush()
        response = {"user_id": user.id}
        self.sql_session.commit()
        self.write(response)

class DDDAddUserToContestHandler(DDDHandler):
    def post(self):
        token = self.get_argument("token")
        payload = get_jwt_payload(token)
        if payload is None:
            raise tornado_web.HTTPError(400)

        contest_id = int(payload["contest_id"])
        user_id = int(payload["user_id"])
        contest = Contest.get_from_id(contest_id,self.sql_session)
        user = User.get_from_id(user_id,self.sql_session)

        existing_participation = self.sql_session.query(Participation) \
        .filter(Participation.contest == contest)\
        .filter(Participation.user == user)\
        .first()

        if existing_participation is None:
            participation = Participation(contest=contest, user=user)
            self.sql_session.add(participation)
            self.sql_session.commit()
            self.reset_ranking()
            self.write("Added")
        else:
            self.write("Not Added")

class DDDLoginHandler(DDDHandler):
    """DDD Login Handler
    We recieve a request from the DDD main site for logging in a particular user.
    """
    def get(self):
        token = self.get_argument("token",None)
        payload = get_jwt_payload(token)

        if payload is None:
            raise tornado_web.HTTPError(400)


        user_id = int(payload["user_id"])
        contest_id = int(payload["contest_id"])

        # We now believe that this request truely came from the DDD website. So we will log them in
        # without requireing any password. Since the rest of the system doesn't directly permit this,
        # we have to get around the other systems, as we do not have access to the password the
        # accounts were created with. It is however enough to make it seem like they were logged in
        # regularly

        # In addition to this, we are going to bypass most of the validation, that normally would run,
        # since we trust DDD to do the right thing.

        participation = self.sql_session.query(Participation) \
            .join(Participation.user) \
            .options(contains_eager(Participation.user)) \
            .filter(User.id == user_id)\
            .join(Participation.contest)\
            .options(contains_eager(Participation.contest))\
            .filter(Contest.id == contest_id)\
            .first()

        if participation is None:
            self.redirect(config.ddd_url)
            return

        correct_password = get_password(participation)

        cookie = json.dumps([participation.user.username, correct_password, make_timestamp(self.timestamp)]).encode("utf-8")

        cookie_name = participation.contest.name + "_login"
        self.set_secure_cookie(cookie_name, cookie, expires_days=None)

        contest = Contest.get_from_id(contest_id,self.sql_session)

        if self.is_multi_contest():
            next_page = self.url[contest.name]()
        else:
            next_page = self.url()

        self.redirect(next_page)

class DDDUpdateUserHandler(DDDHandler):
    """DDD Update user
    """
    def post(self):
        token = self.get_argument("token")

        payload = get_jwt_payload(token)
        if payload is None:
            raise tornado_web.HTTPError(400)

        user_id = int(payload["user_id"])
        user = User.get_from_id(user_id,self.sql_session)

        old_username = user.username

        user.first_name = payload["first_name"]
        user.last_name = payload["last_name"]
        user.username = payload["username"]
        user.email = payload["email"]
        self.sql_session.commit()

        if old_username != user.username:
            self.reset_ranking(old_username)
        # We don't right now need to create a response, but we will as a placeholder
        response = {}
        self.write(response)

class DDDGetRanking(DDDHandler):
    """
    DDD Get user score
    """
    def post(self):
        token = self.get_argument("token")

        payload = get_jwt_payload(token)
        if payload is None:
            raise tornado_web.HTTPError(400)

        contest_id = payload["contest_id"]

        # This massive joined load gets all the information which we will need
        # to generating the rankings.
        self.contest = self.sql_session.query(Contest)\
            .filter(Contest.id == contest_id)\
            .options(joinedload('participations'))\
            .options(joinedload('participations.submissions'))\
            .options(joinedload('participations.submissions.token'))\
            .options(joinedload('participations.submissions.results'))\
            .first()

        scores = {}

        for p in self.contest.participations:
            total_score = 0.0
            for task in self.contest.tasks:
                t_score, t_partial = task_score(p, task, rounded=True)
                total_score += t_score
            total_score = round(total_score, self.contest.score_precision)
            scores[p.user_id] = total_score
        self.write({"scores": scores})
