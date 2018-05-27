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

from .model import AppUser
from .utility import generate_schema
from .exc import NotFoundCredentialError, InvalidUserError, \
    InvalidPasswordError, JWTError, TokenNotFoundError, AuthorizationError


AUTH_SCHEMA = generate_schema(AppUser, include=['username', 'password'])


current_identity = LocalProxy(
    lambda: getattr(_request_ctx_stack.top, 'current_identity', None))


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
        return Claim(value=value, type='sub')

    def to_url(self, value):
        return value


def _verify_username(username):

    identity = AppUser.query \
        .filter_by(canonical_username=username.lower()).one_or_none()

    if identity is None:
        raise InvalidUserError(f'Username "{username}" is not registered')

    return identity


def _get_incoming_request_token():
    """Return ``Authorization`` header token if present, otherwise None.

    If the Authorization header is present, raises a JWTError if the token
    is malformed.
    """

    token_string = request.headers.get('Authorization', None)
    token_prefix = current_app.config['JWT_AUTH_HEADER_PREFIX']

    if token_string is None:
        return None

    parts = token_string.split()

    error = 'Missing or malformed token' if len(parts) < 2 \
        else 'The token contains spaces' if len(parts) > 2 \
        else 'Unsupported authorization type' if parts[0] != token_prefix \
        else None

    if error:
        raise JWTError(error)

    return parts[1]


def _jwt_payload_generator(identity):
    required_claim_list = current_app.config['JWT_REQUIRED_CLAIMS']
    iat = datetime.utcnow()
    exp = iat + current_app.config['JWT_EXPIRATION_DELTA']
    iss = current_app.config['JWT_ISSUER'] or current_app.config['SERVER_NAME']
    payload = {}

    if 'iss' in required_claim_list:
        if not iss:
            raise RuntimeError(
                'The token payload could not be generated. The claim iss is '
                'required, but neither JWT_ISSUER nor SERVER_NAME are provided'
            )

        payload['iss'] = iss

    payload.update({'iat': iat, 'exp': exp, 'sub': identity.username})

    return payload


def _jwt_encode_handler(payload):
    secret = current_app.config['SECRET_KEY']

    if secret is None:
        raise RuntimeError('SECRET_KEY is not set. Can not generate Token')

    algorithm = current_app.config['JWT_ALGORITHM']
    required_claim_list = current_app.config['JWT_REQUIRED_CLAIMS']

    missing_claims = list(set(required_claim_list) - set(payload.keys()))

    if missing_claims:
        raise ValueError(
            f'Payload is missing required claims: {", ".join(missing_claims)}'
        )

    return jwt.encode(payload, secret, algorithm=algorithm)


def _jwt_decode_handler(token):

    if not isinstance(token, (str, bytes)):
        raise ValueError(f'{type(token)} is not a valid JWT string')

    required_claim_list = current_app.config['JWT_REQUIRED_CLAIMS']

    options = {'require_' + claim: True for claim in required_claim_list}
    options.update({'verify_' + claim: True for claim in required_claim_list})

    parameters = {
        'jwt': token,
        'key': current_app.config['SECRET_KEY'],
        'leeway': current_app.config['JWT_LEEWAY'],
        'options': options,
        'algorithms': [current_app.config['JWT_ALGORITHM']],
    }

    if 'iss' in required_claim_list:
        parameters['issuer'] = current_app.config['JWT_ISSUER']

    try:
        payload = jwt.decode(**parameters)
    except jwt.exceptions.MissingRequiredClaimError as e:
        raise JWTError(str(e))
    except jwt.exceptions.ExpiredSignatureError as e:
        raise JWTError('Token has expired')
    except jwt.exceptions.InvalidIssuerError as e:
        raise JWTError(str(e))
    except jwt.exceptions.DecodeError as e:
        raise JWTError('Invalid or malformed token')

    return payload


def _is_authorized(payload):

    criteria = []

    for c in request.view_args.values():
        criteria.append(c.type in payload and c == payload[c.type])

    if not all(criteria):
        return False

    return True


def _validate_request():

    token = _get_incoming_request_token()

    if token is None:
        raise TokenNotFoundError(
            'The request does not contain an access token')

    payload = _jwt_decode_handler(token)

    if _is_authorized(payload) is False:
        raise AuthorizationError('Invalid access token for this resource')

    try:
        _verify_username(payload['sub'])
    except InvalidUserError as e:
        raise AuthorizationError('Invalid access token for this resource')


# ~~~~~~~~~~~~~~~~~~~~~
#
# AUTHENTICATION
#
# ~~~~~~~~~~~~~~~~~~~~~


def _authenticate_with_token(token):
    """Given a valid access token, authenticate a user and return a new access
    token.
    """

    payload = _jwt_decode_handler(token)
    username = payload['sub']

    return _verify_username(username)


def _authenticate_with_password(username, password):

    user = _verify_username(username)

    if user.verify_password(password) is False:
        raise InvalidPasswordError('Invalid password')

    return user


def _authentication_endpoint():
    """Handles an authentication request and returns an access token."""

    identity = None
    token = _get_incoming_request_token()

    if token:
        identity = _authenticate_with_token(token)
    else:
        username_password = request.get_json()

        if username_password is None:
            raise NotFoundCredentialError('Missing token and '
                                          'username/password')

        v = Validator(AUTH_SCHEMA)

        if v.validate(username_password) is False:
            abort(400, v.errors)

        identity = _authenticate_with_password(**username_password)

    payload = _jwt_payload_generator(identity)
    access_token = _jwt_encode_handler(payload)

    return jsonify({'access_token': access_token.decode('utf-8')})


def require_auth():

    def decorator(func):

        @wraps(func)
        def wrapper(*arg, **karg):

            _validate_request()

            return func(*arg, **karg)
        return wrapper
    return decorator


class Auth(object):

    def __init__(self, app=None):

        if app:
            self.init_app(app)

    def init_app(self, app):

        self.app = app

        app.url_map.converters['sub'] = SubClaimConverter

        app.add_url_rule(rule='/auth',
                         view_func=_authentication_endpoint,
                         methods=['POST'])
