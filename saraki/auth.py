"""
    saraki.auth
    ~~~~~~~~~~~
"""

import jwt
from functools import wraps
from datetime import datetime

from cerberus import Validator
from flask import request, current_app, jsonify, abort, _request_ctx_stack
from werkzeug.routing import BaseConverter
from werkzeug.local import LocalProxy

from .utility import generate_schema, get_key_path
from .model import (
    User,
    Org,
    Membership,
    _persist_actions,
    _persist_resources,
    _persist_abilities,
    get_member_privileges,
)
from .exc import (
    NotFoundCredentialError,
    InvalidUserError,
    InvalidOrgError,
    InvalidMemberError,
    InvalidPasswordError,
    JWTError,
    TokenNotFoundError,
    AuthorizationError,
    ProgrammingError,
)


AUTH_SCHEMA = generate_schema(User, include=["username", "password"])


HTTP_VERBS_CRUD = {
    "get": "read",
    "post": "write",
    "patch": "write",
    "put": "write",
    "delete": "delete",
}


#: A local proxy object that points to the user accessing an endpoint in the
#: current request. The value of this object is an instance of the model class
#: :class:`~saraki.model.User` or None if there is not a user.
current_user = LocalProxy(lambda: getattr(_request_ctx_stack.top, "current_user", None))


#: A local proxy object that points to the organization being accessed in the
#: current request. The value of this object is an instance of the model class
#: :class:`~saraki.model.Org` or None if the endpoint is not a tenant endpoint.
current_org = LocalProxy(lambda: getattr(_request_ctx_stack.top, "current_org", None))


class Claim(str):
    def __new__(cls, value, type):
        return str.__new__(cls, value)

    def __init__(self, value, type):
        self._claim_type = type

    @property
    def type(self):
        return self._claim_type

    def __repr__(self):
        return f'Claim(value="{self[:]}", type="{self.type}")'


class SubClaimConverter(BaseConverter):
    def to_python(self, value):
        return Claim(value=value, type="sub")

    def to_url(self, value):
        return value


class AudClaimConverter(BaseConverter):
    def to_python(self, value):
        return Claim(value=value, type="aud")

    def to_url(self, value):
        return value


def _verify_username(username):

    filters = {"canonical_username": username.lower()}
    identity = User.query.filter_by(**filters).one_or_none()

    if identity is None:
        raise InvalidUserError(f'Username "{username}" is not registered')

    return identity


def _verify_orgname(orgname):

    org = Org.query.filter_by(orgname=orgname).one_or_none()

    if org is None:
        raise InvalidOrgError(f'Orgname "{orgname}" is not registered')

    return org


def _verify_member(user, org):
    member = Membership.query.filter_by(user_id=user.id, org_id=org.id).one_or_none()

    if member is None:
        raise InvalidMemberError(f"{user.username} is not a member of {org.orgname}")

    return member


def _get_request_jwt():
    """Return ``Authorization`` header token if present, otherwise None.

    If the Authorization header is present, raises a JWTError if the token
    is malformed.
    """

    token_string = request.headers.get("Authorization", None)
    token_prefix = current_app.config["JWT_AUTH_HEADER_PREFIX"]

    if token_string is None:
        return None

    parts = token_string.split()

    error = (
        "Missing or malformed token"
        if len(parts) < 2
        else "The token contains spaces"
        if len(parts) > 2
        else "Unsupported authorization type"
        if parts[0] != token_prefix
        else None
    )

    if error:
        raise JWTError(error)

    return parts[1]


def _generate_jwt_payload(user, org=None):
    required_claim_list = current_app.config["JWT_REQUIRED_CLAIMS"]
    iat = datetime.utcnow()
    exp = iat + current_app.config["JWT_EXPIRATION_DELTA"]
    iss = current_app.config["JWT_ISSUER"] or current_app.config["SERVER_NAME"]
    payload = {}

    if "iss" in required_claim_list:
        if not iss:
            raise RuntimeError(
                "The token payload could not be generated. The claim iss is "
                "required, but neither JWT_ISSUER nor SERVER_NAME are provided"
            )

        payload["iss"] = iss

    if org:
        payload["aud"] = org.orgname
        payload.update({"scp": get_member_privileges(org, user)})

    payload.update({"iat": iat, "exp": exp, "sub": user.username})

    return payload


def _encode_jwt(payload):
    secret = current_app.config["SECRET_KEY"]

    if secret is None:
        raise RuntimeError("SECRET_KEY is not set. Can not generate Token")

    algorithm = current_app.config["JWT_ALGORITHM"]
    required_claim_list = current_app.config["JWT_REQUIRED_CLAIMS"]

    missing_claims = list(set(required_claim_list) - set(payload.keys()))

    if missing_claims:
        raise ValueError(
            f'Payload is missing required claims: {", ".join(missing_claims)}'
        )

    return jwt.encode(payload, secret, algorithm=algorithm)


def _decode_jwt(token):

    if not isinstance(token, (str, bytes)):
        raise ValueError(f"{type(token)} is not a valid JWT string")

    required_claim_list = current_app.config["JWT_REQUIRED_CLAIMS"]

    options = {"require_" + claim: True for claim in required_claim_list}
    options.update({"verify_" + claim: True for claim in required_claim_list})
    options["verify_aud"] = False

    parameters = {
        "jwt": token,
        "key": current_app.config["SECRET_KEY"],
        "leeway": current_app.config["JWT_LEEWAY"],
        "options": options,
        "algorithms": [current_app.config["JWT_ALGORITHM"]],
    }

    if "iss" in required_claim_list:
        parameters["issuer"] = current_app.config["JWT_ISSUER"]

    try:
        payload = jwt.decode(**parameters)
    except jwt.exceptions.MissingRequiredClaimError as e:
        raise JWTError(str(e))
    except jwt.exceptions.ExpiredSignatureError as e:
        raise JWTError("Token has expired")
    except jwt.exceptions.InvalidIssuerError as e:
        raise JWTError(str(e))
    except jwt.exceptions.DecodeError as e:
        raise JWTError("Invalid or malformed token")

    return payload


def _get_parent_resource(required_resource, scopes):

    resource_map = current_app.auth.resources
    path = get_key_path(required_resource, resource_map) or []

    for resource in scopes:
        if resource in path:
            return resource

    return None


def _is_authorized(payload, resource=None, action=None):

    criteria = []

    for c in request.view_args.values():
        if isinstance(c, Claim):
            criteria.append(c.type in payload and c == payload[c.type])

    if not all(criteria):
        return False

    if not resource:
        return True

    scopes = payload.get("scp")

    if not scopes:
        return False

    if action is None:
        method = request.method.lower()

        if method not in HTTP_VERBS_CRUD:
            return False

        action = HTTP_VERBS_CRUD[method]

    scope_resource = scopes.get(resource)

    if not scope_resource:
        parent_resource = _get_parent_resource(resource, scopes)

        if not parent_resource:
            return False

        scope_resource = scopes[parent_resource]

    return action in scope_resource or "manage" in scope_resource


def _validate_request(resource=None, action=None):

    token = _get_request_jwt()

    if token is None:
        raise TokenNotFoundError

    payload = _decode_jwt(token)

    if _is_authorized(payload, resource, action) is False:
        raise AuthorizationError

    org = None

    try:
        user = _verify_username(payload["sub"])
        org = _verify_orgname(payload["aud"]) if "aud" in payload else None

    except (InvalidUserError, InvalidOrgError) as e:
        raise AuthorizationError

    _request_ctx_stack.top.current_user = user
    _request_ctx_stack.top.current_org = org


# ~~~~~~~~~~~~~~~~~~~~~
#
# AUTHENTICATION
#
# ~~~~~~~~~~~~~~~~~~~~~


def _authenticate_with_token(token):
    """Given a valid access token, authenticate a user and return a new access
    token.
    """

    payload = _decode_jwt(token)
    username = payload["sub"]

    return _verify_username(username)


def _authenticate_with_password(username, password):

    user = _verify_username(username)

    if user.verify_password(password) is False:
        raise InvalidPasswordError("Invalid password")

    return user


def _authenticate(orgname=None):
    """Handles an authentication request and returns an access token."""

    org = None

    if orgname:
        try:
            org = _verify_orgname(orgname)
        except InvalidOrgError:
            raise abort(404)

    token = _get_request_jwt()

    if token:
        user = _authenticate_with_token(token)
    else:
        username_password = request.get_json()

        if username_password is None:
            raise NotFoundCredentialError("Missing token and username/password")

        v = Validator(AUTH_SCHEMA)

        if v.validate(username_password) is False:
            abort(400, v.errors)

        user = _authenticate_with_password(**username_password)

    if org:
        _verify_member(user, org)

    payload = _generate_jwt_payload(user, org)
    access_token = _encode_jwt(payload)

    return jsonify({"access_token": access_token.decode("utf-8")})


def require_auth(resource=None, action=None, parent_resource=None):

    if action and not resource:
        raise ProgrammingError(f"You passed an action '{action}' without a resource")

    def decorator(func):

        func._auth_metadata = dict(
            resource=resource, action=action, parent_resource=parent_resource
        )

        @wraps(func)
        def wrapper(*arg, **karg):

            _validate_request(resource, action)

            return func(*arg, **karg)

        return wrapper

    return decorator


class Auth:
    def __init__(self, app=None):

        self._resources = {}
        self._actions = ["manage"]
        self._persist_actions_func = _persist_actions
        self._persist_resources_func = _persist_resources
        self._persist_abilities_func = _persist_abilities

        if app:
            self.init_app(app)

    def init_app(self, app):

        self.app = app

        app.url_map.converters["sub"] = SubClaimConverter
        app.url_map.converters["aud"] = AudClaimConverter

        methods = ["POST"]

        app.add_url_rule(
            rule="/auth",
            view_func=_authenticate,
            methods=methods,
            defaults={"orgname": None},
        )

        app.add_url_rule(
            rule="/auth/<orgname>", view_func=_authenticate, methods=methods
        )

    @property
    def resources(self):
        return self._resources

    @property
    def actions(self):
        return self._actions

    def _add_resource(self, resource, parent=None):

        if type(resource) != str:
            raise TypeError(
                f"resource argument must be an string, got {type(resource)}"
            )

        resources = self.resources
        path = get_key_path(resource, resources)

        if not path:

            parent_path = get_key_path(parent, resources) if parent else []

            if parent_path is None:
                self._resources[parent] = None
                parent_path = [parent]

            parent_resource = self._resources

            for branch in parent_path:
                if parent_resource[branch] is None:
                    parent_resource[branch] = {}
                parent_resource = parent_resource[branch]

            parent_resource[resource] = None

    def _add_action(self, action):

        if type(action) != str:
            raise TypeError(f"action argument must be an string, got {type(action)}")
        if action is not None and action not in self.actions:
            self._actions.append(action)

    def _collect_metadata(self):

        for view_func in self.app.view_functions.values():

            if hasattr(view_func, "_auth_metadata"):

                _auth = view_func._auth_metadata

                resource = _auth["resource"]
                parent_resource = _auth["parent_resource"]
                action = _auth["action"]

                if resource:
                    self._add_resource(resource, parent_resource)

                if action:
                    self._add_action(action)

    def persist_actions(self, f):
        """Registers a function called to persist actions in a database."""

        self._persist_actions_func = f
        return f

    def persist_resources(self, f):
        """Registers a function called to persist resources in a database."""

        self._persist_resources_func = f
        return f

    def persist_abilities(self, f):
        """Registers a function called to persist abilities in a database."""

        self._persist_resources_func = f
        return f

    def persist_data(self):
        self._collect_metadata()
        self._persist_actions_func(self.actions)
        self._persist_resources_func(self.resources)
        self._persist_abilities_func()
