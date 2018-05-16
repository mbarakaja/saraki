import jwt
import pytest
from json import dumps, loads
from werkzeug.exceptions import BadRequest
from flask import Flask
from calendar import timegm
from datetime import datetime, timedelta
from unittest.mock import patch
from saraki import Saraki
from saraki.exc import NotFoundCredentialError, InvalidPasswordError, \
    InvalidUserError, JWTError
from saraki.auth import Auth, _verify_username, _authenticate_with_password, \
    _get_incoming_request_token, _jwt_payload_generator, _jwt_encode_handler, \
    _jwt_decode_handler, _authenticate_with_token, _authentication_endpoint


@pytest.fixture
def _app():
    app = Saraki(__name__)
    app.config['SECRET_KEY'] = 'secret'
    app.config['JWT_ALGORITHM'] = 'HS256'
    app.config['JWT_ISSUER'] = 'acme.local'
    return app


@pytest.fixture
def _ctx(_app):
    ctx = _app.app_context()
    ctx.push()

    yield ctx

    ctx.pop()


@pytest.fixture
def _request_ctx(_app):
    return _app.test_request_context


@pytest.fixture
def _payload():
    iat = datetime.utcnow()
    exp = iat + timedelta(seconds=6000)
    return {'iss': 'acme.local', 'sub': 'Coy0te', 'iat': iat, 'exp': exp}


class AppUser(object):
    username = 'Coy0te'


@pytest.mark.usefixtures("data")
class Test_verify_username(object):

    def test_different_case_variations(self, ctx):
        assert _verify_username('Coy0te').username == 'Coy0te'
        assert _verify_username('coy0te').username == 'Coy0te'
        assert _verify_username('COY0TE').username == 'Coy0te'

    def test_unregistered_username(self, ctx):
        error_msg = 'Username "unknown" is not registered'

        with pytest.raises(InvalidUserError, match=error_msg):
            _verify_username('unknown')


class Test_get_incoming_request_token(object):

    def test_with_more_than_one_space(self, _request_ctx):
        headers = {'Authorization': 'Bearer this is a token with spaces'}

        with _request_ctx('/', headers=headers):
            with pytest.raises(JWTError, match='The token contains spaces'):
                _get_incoming_request_token()

    def test_with_wrong_prefix(self, _request_ctx):
        headers = {'Authorization': 'WRONG a.nice.token'}

        with _request_ctx('/', headers=headers):
            with pytest.raises(JWTError,
                               match='Unsupported authorization type'):
                _get_incoming_request_token()

    def test_without_space_after_prefix(self, _request_ctx):
        headers = {'Authorization': 'Bearera.nice.token'}

        with _request_ctx('/', headers=headers):
            with pytest.raises(JWTError, match='Missing or malformed token'):
                _get_incoming_request_token()

    def test_with_empty_authorization_http_header(self, _request_ctx):
        with _request_ctx('/', headers={'Authorization': ''}):
            with pytest.raises(JWTError, match='Missing or malformed token'):
                _get_incoming_request_token()

    def test_without_authorization_http_header(self, _request_ctx):
        with _request_ctx('/'):
            token = _get_incoming_request_token()

        assert token is None

    def test_with_valid_token(self, _app):
        prefix = _app.config["JWT_AUTH_HEADER_PREFIX"]
        token = 'a.nice.token'
        headers = {'Authorization': f'{prefix} {token}'}

        with _app.test_request_context('/', headers=headers):
            _token = _get_incoming_request_token()

        assert token == _token


class Test_jwt_payload_generator(object):

    def test_included_claims(self, _ctx):

        payload = _jwt_payload_generator(AppUser())

        assert 'iss' in payload
        assert 'iat' in payload
        assert 'exp' in payload
        assert 'sub' in payload

    def test_iss_claim_when_no_JWT_ISSUER_or_SERVER_NAME_is_set(self, _app):
        _app.config['SERVER_NAME'] = None
        _app.config['JWT_ISSUER'] = None

        error = 'Neither JWT_ISSUER nor SERVER_NAME is set'

        with pytest.raises(RuntimeError, match=error):
            with _app.app_context():
                _jwt_payload_generator(AppUser())

    def test_iss_claim(self, _app):
        _app.config['SERVER_NAME'] = 'server.name'
        _app.config['JWT_ISSUER'] = 'acme.issuer'

        with _app.app_context():
            payload = _jwt_payload_generator(AppUser())

        assert payload['iss'] == 'acme.issuer'

    def test_iss_claim_fallback_to_server_name(self, _app):
        _app.config['SERVER_NAME'] = 'server.name'
        _app.config['JWT_ISSUER'] = None

        with _app.app_context():
            payload = _jwt_payload_generator(AppUser())

        assert payload['iss'] == 'server.name'

    def test_sub_claim(self, _ctx):
        payload = _jwt_payload_generator(AppUser())

        assert payload['sub'] == 'Coy0te'

    @patch('saraki.auth.datetime')
    def test_iat_claim(self, mock_datetime, _ctx):
        _datetime = datetime(2018, 5, 13, 17, 52, 44, 524300)
        mock_datetime.utcnow.return_value = _datetime

        payload = _jwt_payload_generator(AppUser())

        assert payload['iat'] == _datetime
        mock_datetime.utcnow.assert_called_once()

    @patch('saraki.auth.datetime')
    def test_exp_claim(self, mock_datetime, _app):
        _datetime = datetime(2018, 5, 13, 17, 52, 44, 524300)
        _app.config['JWT_EXPIRATION_DELTA'] = timedelta(seconds=400)
        mock_datetime.utcnow.return_value = _datetime

        with _app.app_context():
            payload = _jwt_payload_generator(AppUser())

        assert payload['exp'] == _datetime + timedelta(seconds=400)


class Test_jwt_encode_handler(object):

    def test_with_valid_payload(self, _ctx):
        iat = datetime.utcnow()
        exp = iat + timedelta(seconds=300)

        token = _jwt_encode_handler({
            'iss': 'acme.local',
            'sub': 'Coy0te',
            'iat': iat,
            'exp': exp
        })

        _payload = jwt.decode(token, verify=False)

        assert _payload['iss'] == 'acme.local'
        assert _payload['sub'] == 'Coy0te'
        assert _payload['iat'] == timegm(iat.utctimetuple())
        assert _payload['exp'] == timegm(exp.utctimetuple())

    def test_with_missing_iss_claim(self, _ctx):
        iat = datetime.utcnow()
        exp = iat + timedelta(seconds=300)

        error = 'Payload is missing required claims: iss'

        with pytest.raises(ValueError, match=error):
            _jwt_encode_handler({'sub': 'Coy0te', 'iat': iat, 'exp': exp})

    def test_with_various_missing_required_claims(self, _ctx):
        with pytest.raises(ValueError) as error:
            _jwt_encode_handler({})

        e = str(error)

        assert 'Payload is missing required claims:' in e
        assert 'iss' in e
        assert 'sub' in e
        assert 'iat' in e
        assert 'exp' in e

    def test_when_a_secret_is_not_provided(self, _app):

        _app.config['SECRET_KEY'] = None

        error = 'SECRET_KEY is not set. Can not generate Token'

        with pytest.raises(RuntimeError, match=error):
            with _app.app_context():
                _jwt_encode_handler({})


class Test_jwt_decode_handler(object):

    def test_passing_invalid_data_types(self):

        with pytest.raises(ValueError, match='is not a valid JWT string'):
            _jwt_decode_handler(None)

        with pytest.raises(ValueError, match='is not a valid JWT string'):
            _jwt_decode_handler(1)

        with pytest.raises(ValueError, match='is not a valid JWT string'):
            _jwt_decode_handler(True)

    def test_token_with_wrong_iss_claim(self, _app, _payload):
        _app.config['SERVER_NAME'] = 'acme.local'
        _app.config['JWT_LEEWAY'] = timedelta(seconds=10)

        _payload['iss'] = 'malicious.issuer'

        token = jwt.encode(_payload, _app.config['SECRET_KEY'])

        with pytest.raises(JWTError, match='Invalid issuer'):
            with _app.app_context():
                _jwt_decode_handler(token)

    def test_token_without_iss_claim(self, _app, _payload):
        _app.config['SERVER_NAME'] = 'acme.local'
        _app.config['JWT_LEEWAY'] = timedelta(seconds=10)
        del _payload['iss']

        token = jwt.encode(_payload, _app.config['SECRET_KEY'])

        with pytest.raises(JWTError, match='Token is missing the "iss" claim'):
            with _app.app_context():
                _jwt_decode_handler(token)

    def test_token_without_iat_claim(self, _app, _payload):

        _app.config['JWT_LEEWAY'] = timedelta(seconds=10)
        del _payload['iat']

        token = jwt.encode(_payload, _app.config['SECRET_KEY'])

        with pytest.raises(JWTError, match='Token is missing the "iat" claim'):
            with _app.app_context():
                _jwt_decode_handler(token)

    def test_token_without_exp_claim(self, _app, _payload):

        _app.config['JWT_LEEWAY'] = timedelta(seconds=10)
        del _payload['exp']

        token = jwt.encode(_payload, _app.config['SECRET_KEY'])

        with pytest.raises(JWTError, match='Token is missing the "exp" claim'):
            with _app.app_context():
                _jwt_decode_handler(token)

    def test_with_expired_token(self, _app):
        _app.config['JWT_LEEWAY'] = timedelta(seconds=10)

        iat = datetime(1900, 5, 13, 17, 52, 44, 524300)
        exp = iat + timedelta(seconds=400)
        payload = {'iat': iat, 'exp': exp}

        token = jwt.encode(payload, _app.config['SECRET_KEY'])

        with pytest.raises(JWTError, match='Token has expired'):
            with _app.app_context():
                _jwt_decode_handler(token)

    def test_with_malformed_token(self, _app, _payload):

        token = jwt.encode(_payload, _app.config['SECRET_KEY']) + b"'"

        with pytest.raises(JWTError, match='Invalid or malformed token'):
            with _app.app_context():
                _jwt_decode_handler(token)

    def test_with_valid_token(self, _app, _payload):
        _app.config['SERVER_NAME'] = 'acme.local'
        _app.config['JWT_LEEWAY'] = timedelta(seconds=10)

        token = jwt.encode(_payload, _app.config['SECRET_KEY'])

        with _app.app_context():
            decoded_payload = _jwt_decode_handler(token)

        assert decoded_payload['iss'] == 'acme.local'
        assert decoded_payload['sub'] == 'Coy0te'


class Test_authenticate_with_password(object):

    def test_with_unknown_username(self, ctx):
        error = 'Username "extraneous" is not registered'

        with pytest.raises(InvalidUserError, match=error):
            _authenticate_with_password('extraneous', '12345')

    def test_with_wrong_password(self, ctx):
        with pytest.raises(InvalidPasswordError, match='Invalid password'):
            _authenticate_with_password('Coy0te', 'wrongpassword')

    def test_with_valid_username_and_password(self, ctx):
        identity = _authenticate_with_password('Coy0te', '12345')

        assert identity.username == 'Coy0te'


class Test_authenticate_with_token(object):

    def test_token_with_unregistered_username(self, app, _payload):

        _payload['sub'] = 'unknown'

        token = jwt.encode(_payload, app.config['SECRET_KEY'],
                           algorithm=app.config['JWT_ALGORITHM'])

        error = 'Username "unknown" is not registered'

        with pytest.raises(InvalidUserError, match=error):
            with app.app_context():
                _authenticate_with_token(token)

    def test_token_with_registered_username(self, app, _payload):

        token = jwt.encode(_payload, app.config['SECRET_KEY'],
                           algorithm=app.config['JWT_ALGORITHM'])

        with app.app_context():
            user = _authenticate_with_token(token)

        assert user.username == 'Coy0te'


class Test_authentication_endpoint(object):

    def test_request_without_credentials_or_token(self, _request_ctx):

        with pytest.raises(NotFoundCredentialError):
            with _request_ctx('/'):
                _authentication_endpoint()

    def test_request_without_username(self, _request_ctx):

        body = {'password': '12345'}

        with pytest.raises(BadRequest):
            with _request_ctx('/', data=dumps(body),
                              content_type='application/json'):
                _authentication_endpoint()

    def test_request_without_password(self, _request_ctx):

        body = {'username': 'Coy0te'}

        with pytest.raises(BadRequest):
            with _request_ctx('/', data=dumps(body),
                              content_type='application/json'):
                _authentication_endpoint()


class TestRequestAccessToken(object):
    """Integration test. Requests to ``/auth`` endpoint"""

    def test_request_without_credentials_nor_token(self, app):

        rv = app.test_client().post('/auth')

        assert rv.status_code == 400

    def test_request_without_username(self, client):

        body = {'password': '12345'}

        rv = client \
            .post('/auth', data=dumps(body), content_type='application/json')

        assert rv.status_code == 400, str(rv.data)

    def test_request_without_password(self, client):

        body = {'username': 'Coy0te'}

        rv = client \
            .post('/auth', data=dumps(body), content_type='application/json')

        assert rv.status_code == 400

    def test_request_with_invalid_username(self, client):

        body = {'username': 'Coyote', 'password': '123456'}

        rv = client \
            .post('/auth', data=dumps(body), content_type='application/json')

        assert rv.status_code == 400

    def test_request_with_invalid_password(self, client):

        body = {'username': 'Coy0te', 'password': 'wrongpassword'}

        rv = client \
            .post('/auth', data=dumps(body), content_type='application/json')

        assert rv.status_code == 400

    def test_request_with_valid_credentials(self, client):

        body = {'username': 'Coy0te', 'password': '12345'}

        rv = client \
            .post('/auth', data=dumps(body), content_type='application/json')

        assert rv.status_code == 200
        token = loads(rv.data)['access_token']
        payload = jwt.decode(token, verify=False)

        assert payload['sub'] == 'Coy0te'

    def test_request_with_valid_token(self, app, _payload):
        token = jwt.encode(_payload, app.config['SECRET_KEY'],
                           algorithm=app.config['JWT_ALGORITHM']).decode()

        rv = app.test_client().post(
            '/auth',
            headers={'Authorization': f'JWT {token}'},
            content_type='application/json',
        )

        assert rv.status_code == 200
        token = loads(rv.data)['access_token']
        payload = jwt.decode(token, verify=False)

        assert payload['sub'] == 'Coy0te'


class TestAuth(object):

    def test_authentication_endpoint_registration(self):
        app = Flask(__name__)

        auth = Auth()
        auth.init_app(app)

        adapter = app.url_map.bind('')
        adapter.match('/auth', method='POST')
