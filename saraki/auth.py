"""
    saraki.auth
    ~~~~~~~~~~~
"""

import jwt
from datetime import datetime

from cerberus import Validator
from flask import request, current_app, jsonify, abort
from .model import AppUser
from .utility import generate_schema
from .exc import NotFoundCredentialError, InvalidUserError, \
    InvalidPasswordError, \
    JWTError


AUTH_SCHEMA = generate_schema(AppUser, include=['username', 'password'])


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


class Auth(object):

    def __init__(self, app=None):

        if app:
            self.init_app(app)

    def init_app(self, app):

        self.app = app

        app.add_url_rule(rule='/auth',
                         view_func=_authentication_endpoint,
                         methods=['POST'])
