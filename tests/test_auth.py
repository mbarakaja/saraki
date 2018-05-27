import jwt
import pytest
from json import dumps, loads
from werkzeug.exceptions import BadRequest
from calendar import timegm
from datetime import datetime, timedelta
from unittest.mock import patch
from saraki import Saraki
from saraki.exc import NotFoundCredentialError, InvalidPasswordError, \
    InvalidUserError, JWTError, AuthorizationError, TokenNotFoundError
from saraki.auth import _verify_username, _authenticate_with_password, \
    _get_incoming_request_token, _jwt_payload_generator, _jwt_encode_handler, \
    _jwt_decode_handler, _authenticate_with_token, _authentication_endpoint, \
    _is_authorized, _validate_request, require_auth


parametrize = pytest.mark.parametrize


def getpayload(scp=None, sub=None):
    iat = datetime.utcnow()
    exp = iat + timedelta(seconds=6000)
    payload = {
        'iss': 'acme.local',
        'sub': sub or 'Coy0te',
        'iat': iat,
        'exp': exp,
    }

    if scp:
        payload['scp'] = scp

    return payload


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
    return getpayload()


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

    def test_default_included_claims(self, _ctx):

        payload = _jwt_payload_generator(AppUser())

        assert len(payload) is 3
        assert 'iat' in payload
        assert 'exp' in payload
        assert 'sub' in payload

    def test_iss_claim_when_no_JWT_ISSUER_or_SERVER_NAME_are_set(self, _app):
        _app.config['SERVER_NAME'] = None
        _app.config['JWT_ISSUER'] = None
        _app.config['JWT_REQUIRED_CLAIMS'] = ['iss']

        error_msg = (
            'The token payload could not be generated. The claim iss is '
            'required, but neither JWT_ISSUER nor SERVER_NAME are provided'
        )

        with pytest.raises(RuntimeError, match=error_msg):
            with _app.app_context():
                _jwt_payload_generator(AppUser())

    def test_iss_claim_inclusion_only_when_required(self, _app):
        _app.config['JWT_REQUIRED_CLAIMS'] = []
        _app.config['SERVER_NAME'] = 'server.name'
        _app.config['JWT_ISSUER'] = 'acme.issuer'

        with _app.app_context():
            payload = _jwt_payload_generator(AppUser())

        assert 'iss' not in payload

    def test_iss_claim(self, _app):
        _app.config['JWT_REQUIRED_CLAIMS'] = ['iss']
        _app.config['SERVER_NAME'] = 'server.name'
        _app.config['JWT_ISSUER'] = 'acme.issuer'

        with _app.app_context():
            payload = _jwt_payload_generator(AppUser())

        assert payload['iss'] == 'acme.issuer'

    def test_iss_claim_fallback_to_server_name(self, _app):
        _app.config['JWT_REQUIRED_CLAIMS'] = ['iss']
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
            'exp': exp,
            'custom': 'custom claim value',
        })

        _payload = jwt.decode(token, verify=False)

        assert _payload['iss'] == 'acme.local'
        assert _payload['sub'] == 'Coy0te'
        assert _payload['iat'] == timegm(iat.utctimetuple())
        assert _payload['exp'] == timegm(exp.utctimetuple())
        assert _payload['custom'] == 'custom claim value'

    def test_with_missing_iss_claim(self, _app, _ctx):
        _app.config['JWT_REQUIRED_CLAIMS'] = ['iss']
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
        _app.config['JWT_REQUIRED_CLAIMS'] = ['iss']

        _payload['iss'] = 'malicious.issuer'

        token = jwt.encode(_payload, _app.config['SECRET_KEY'])

        with pytest.raises(JWTError, match='Invalid issuer'):
            with _app.app_context():
                _jwt_decode_handler(token)

    def test_token_without_iss_claim_when_is_required(self, _app, _payload):
        _app.config['JWT_REQUIRED_CLAIMS'] = ['iss']
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

    def test_with_valid_token_without_iss(self, _app, _payload):
        _app.config['JWT_LEEWAY'] = timedelta(seconds=10)

        token = jwt.encode(_payload, _app.config['SECRET_KEY'])

        with _app.app_context():
            decoded_payload = _jwt_decode_handler(token)

        assert decoded_payload['sub'] == 'Coy0te'

    def test_with_valid_token(self, _app, _payload):
        _app.config['SERVER_NAME'] = 'acme.local'
        _app.config['JWT_LEEWAY'] = timedelta(seconds=10)

        token = jwt.encode(_payload, _app.config['SECRET_KEY'])

        with _app.app_context():
            decoded_payload = _jwt_decode_handler(token)

        assert decoded_payload['iss'] == 'acme.local'
        assert decoded_payload['sub'] == 'Coy0te'


class Test_is_authorized(object):

    def test_aud_claim_verification(self, _app, _request_ctx, _payload):

        @_app.route('/<sub:username>/private-info')
        def private_info(username):
            return 'Private information'

        _payload['sub'] = 'Coy0te'

        with _request_ctx('/elmer/private-info'):
            assert _is_authorized(_payload) is False

        _payload['sub'] = 'elmer'

        with _request_ctx('/elmer/private-info'):
            assert _is_authorized(_payload) is True

    def test_route_without_required_claim(self, _app, _request_ctx, _payload):

        @_app.route('/private-info')
        def private_info():
            return 'Private information'

        with _request_ctx('/private-info'):
            assert _is_authorized(_payload) is True


class Test_validate_request(object):

    def test_request_without_access_token(self, _request_ctx):
        excmsg = 'he request does not contain an access token'

        with _request_ctx('/'):
            with pytest.raises(TokenNotFoundError, match=excmsg):
                _validate_request()

    @patch('saraki.auth._verify_username')
    @patch('saraki.auth._is_authorized')
    @patch('saraki.auth._jwt_decode_handler')
    @patch('saraki.auth._get_incoming_request_token')
    def test_request_with_access_token(
        self,
        mocked_get_incoming_request_token,
        mocked_jwt_decode_handler,
        mocked_is_authorized,
        mocked_verify_username,
        _request_ctx
    ):

        mocked_get_incoming_request_token.return_value = 'a.nice.token'
        mocked_jwt_decode_handler.return_value = {'sub': 'Coy0te'}

        with _request_ctx('/'):
            _validate_request()

        mocked_get_incoming_request_token.assert_called_once()
        mocked_jwt_decode_handler.assert_called_once_with('a.nice.token')
        mocked_is_authorized.assert_called_once_with({'sub': 'Coy0te'})
        mocked_verify_username.assert_called_once_with('Coy0te')

    @patch('saraki.auth._is_authorized')
    def test_with_unauthorized_token(self, mocked_is_authorized, _app):

        token = jwt.encode(getpayload(), _app.config['SECRET_KEY']).decode()
        headers = {'Authorization': f'JWT {token}'}

        mocked_is_authorized.return_value = False

        with _app.test_request_context('/', headers=headers):
            with pytest.raises(AuthorizationError):
                _validate_request()

    @pytest.mark.usefixtures("data")
    def test_with_unknown_username_in_sub_claim(self, app, _payload):

        _payload['sub'] = 'unknown'

        token = jwt.encode(_payload, app.config['SECRET_KEY']).decode()
        headers = {'Authorization': f'JWT {token}'}

        with app.test_request_context('/', headers=headers):
            with pytest.raises(AuthorizationError):
                _validate_request()


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


class TestRequireAuth(object):

    @patch('saraki.auth._validate_request')
    def test_call_to_validate_request(self, mocked_validate_request):

        @require_auth()
        def private():
            return 'private content'

        private()

        mocked_validate_request.assert_called_once()

    def test_required_aud_claim(self):
        pass


@pytest.mark.usefixtures("data")
class TestEndpoint(object):

    @parametrize(
        "payload, expected",
        [
            (None, 404),
            (getpayload(sub='unknown'), 404),
            (getpayload(sub='Coy0te'), 200)
        ]
    )
    def test_route_without_sub_variable_rule(self, _app, payload, expected):

        client = _app.test_client()

        @_app.route('/movies')
        @require_auth()
        def movies():
            return 'movies'

        headers = {}

        if payload:
            token = jwt.encode(
                payload,
                _app.config['SECRET_KEY'],
                algorithm=_app.config['JWT_ALGORITHM']
            )
            headers['Authorization'] = f'JWT {token.decode()}'

        assert client.get('/movies', headers=headers).status_code == expected

    @parametrize(
        "payload, expected",
        [
            (None, 404),
            (getpayload(sub='unknown'), 404),
            (getpayload(sub='R0adRunner'), 404),
            (getpayload(sub='Coy0te'), 200)
        ]
    )
    def test_route_with_sub_variable_rule(self, _app, payload, expected):

        client = _app.test_client()

        @_app.route('/<sub:username>/my-movies')
        @require_auth()
        def my_movies(username):
            return 'Those are your movies'

        headers = {}

        if payload:
            token = jwt.encode(
                payload,
                _app.config['SECRET_KEY'],
                algorithm=_app.config['JWT_ALGORITHM']
            )

            headers['Authorization'] = f'JWT {token.decode()}'

        rv = client.get('/Coy0te/my-movies', headers=headers)
        assert rv.status_code == expected
