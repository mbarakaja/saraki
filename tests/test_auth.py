import jwt
import pytest
from random import randint
from typing import NamedTuple
from json import dumps, loads
from werkzeug.exceptions import BadRequest, NotFound
from flask import Flask
from calendar import timegm
from datetime import datetime, timedelta
from unittest.mock import patch, call, Mock
from saraki.exc import (
    NotFoundCredentialError,
    InvalidPasswordError,
    InvalidUserError,
    JWTError,
    AuthorizationError,
    TokenNotFoundError,
    InvalidMemberError,
    InvalidOrgError,
    ProgrammingError,
)
from saraki.auth import (
    _verify_username,
    _verify_orgname,
    _verify_member,
    _authenticate_with_password,
    _authenticate_with_token,
    _get_request_jwt,
    _generate_jwt_payload,
    _encode_jwt,
    _decode_jwt,
    _authenticate,
    _is_authorized,
    _validate_request,
    require_auth,
    Auth,
    current_user,
    current_org,
)
from saraki.model import User, Org

parametrize = pytest.mark.parametrize


def getpayload(scp=None, sub="coyote", aud=None):
    iat = datetime.utcnow()
    exp = iat + timedelta(seconds=6000)
    payload = {"iss": "acme.local", "sub": sub, "iat": iat, "exp": exp}

    if aud:
        payload["aud"] = aud

    if scp:
        payload["scp"] = scp

    return payload


@pytest.fixture
def _payload():
    return getpayload()


class AppUserMock(NamedTuple):
    username: str


class AppOrgMock(NamedTuple):
    orgname: str


def _get_user(username):
    return AppUserMock(username=username)


def _get_org(orgname):
    return AppOrgMock(orgname=orgname)


@pytest.mark.usefixtures("data")
class Test_verify_username(object):
    def test_different_case_variations(self, ctx):
        assert _verify_username("coyote").username == "coyote"
        assert _verify_username("Coyote").username == "coyote"
        assert _verify_username("COYOTE").username == "coyote"

    def test_unregistered_username(self, ctx):
        error_msg = 'Username "unknown" is not registered'

        with pytest.raises(InvalidUserError, match=error_msg):
            _verify_username("unknown")


@pytest.mark.usefixtures("data", "data_org")
class Test_verify_orgname:
    def test_registered_organization(self, ctx):
        assert _verify_orgname("acme").orgname == "acme"

    def test_unregistered_organization(self, ctx):

        error_msg = 'Orgname "unknown" is not registered'

        with pytest.raises(InvalidOrgError, match=error_msg):
            _verify_orgname("unknown")


@pytest.mark.usefixtures("data", "data_org")
class Test_verify_member:
    def test_valid_member(self, ctx):

        user = _verify_username("coyote")
        org = _verify_orgname("acme")

        member = _verify_member(user, org)
        assert member.user is user
        assert member.org is org

    def test_invali_member(self, ctx):

        user = _verify_username("coyote")
        org = _verify_orgname("rrinc")

        error_msg = "coyote is not a member of rrinc"

        with pytest.raises(InvalidMemberError, match=error_msg):
            _verify_member(user, org)


class Test_get_request_jwt(object):
    def test_with_more_than_one_space(self, request_ctx):
        headers = {"Authorization": "Bearer this is a token with spaces"}

        with request_ctx("/", headers=headers):
            with pytest.raises(JWTError, match="The token contains spaces"):
                _get_request_jwt()

    def test_with_wrong_prefix(self, request_ctx):
        headers = {"Authorization": "WRONG a.nice.token"}

        with request_ctx("/", headers=headers):
            with pytest.raises(JWTError, match="Unsupported authorization type"):
                _get_request_jwt()

    def test_without_space_after_prefix(self, request_ctx):
        headers = {"Authorization": "Bearera.nice.token"}

        with request_ctx("/", headers=headers):
            with pytest.raises(JWTError, match="Missing or malformed token"):
                _get_request_jwt()

    def test_with_empty_authorization_http_header(self, request_ctx):
        with request_ctx("/", headers={"Authorization": ""}):
            with pytest.raises(JWTError, match="Missing or malformed token"):
                _get_request_jwt()

    def test_without_authorization_http_header(self, request_ctx):
        with request_ctx("/"):
            token = _get_request_jwt()

        assert token is None

    def test_with_valid_token(self, app):
        prefix = app.config["JWT_AUTH_HEADER_PREFIX"]
        token = "a.nice.token"
        headers = {"Authorization": f"{prefix} {token}"}

        with app.test_request_context("/", headers=headers):
            _token = _get_request_jwt()

        assert token == _token


class Test_generate_jwt_payload(object):
    @pytest.mark.usefixtures("ctx")
    def test_default_included_claims(self):
        user = _get_user(username="somebody")

        payload = _generate_jwt_payload(user)

        assert len(payload) is 3
        assert "iat" in payload
        assert "exp" in payload
        assert "sub" in payload

    def test_iss_claim_when_no_JWT_ISSUER_or_SERVER_NAME_are_set(self, app):
        app.config["SERVER_NAME"] = None
        app.config["JWT_ISSUER"] = None
        app.config["JWT_REQUIRED_CLAIMS"] = ["iss"]

        error_msg = (
            "The token payload could not be generated. The claim iss is "
            "required, but neither JWT_ISSUER nor SERVER_NAME are provided"
        )

        user = _get_user(username="somebody")

        with app.app_context():
            with pytest.raises(RuntimeError, match=error_msg):
                _generate_jwt_payload(user)

    def test_iss_claim_inclusion_only_when_required(self, app):
        app.config["JWT_REQUIRED_CLAIMS"] = []
        app.config["SERVER_NAME"] = "server.name"
        app.config["JWT_ISSUER"] = "acme.issuer"

        user = _get_user(username="somebody")

        with app.app_context():
            payload = _generate_jwt_payload(user)

        assert "iss" not in payload

    def test_iss_claim(self, app):
        app.config["JWT_REQUIRED_CLAIMS"] = ["iss"]
        app.config["SERVER_NAME"] = "server.name"
        app.config["JWT_ISSUER"] = "acme.issuer"

        user = _get_user(username="somebody")

        with app.app_context():
            payload = _generate_jwt_payload(user)

        assert payload["iss"] == "acme.issuer"

    def test_iss_claim_fallback_to_server_name(self, app):
        app.config["JWT_REQUIRED_CLAIMS"] = ["iss"]
        app.config["SERVER_NAME"] = "server.name"
        app.config["JWT_ISSUER"] = None

        user = _get_user(username="somebody")

        with app.app_context():
            payload = _generate_jwt_payload(user)

        assert payload["iss"] == "server.name"

    @pytest.mark.usefixtures("ctx")
    def test_sub_claim(self):
        user = _get_user(username="coyote")
        payload = _generate_jwt_payload(user)

        assert payload["sub"] == "coyote"

    @pytest.mark.usefixtures("data", "data_org")
    def test_aud_claim(self, app):
        user = User.query.filter_by(username="coyote").one()
        org = Org.query.filter_by(orgname="acme").one()

        with app.app_context():
            payload = _generate_jwt_payload(user, org)

        assert payload["aud"] == "acme"

    @pytest.mark.usefixtures("ctx")
    @patch("saraki.auth.datetime")
    def test_iat_claim(self, mock_datetime):
        _datetime = datetime(2018, 5, 13, 17, 52, 44, 524300)
        mock_datetime.utcnow.return_value = _datetime

        user = _get_user(username="somebody")
        payload = _generate_jwt_payload(user)

        assert payload["iat"] == _datetime
        mock_datetime.utcnow.assert_called_once()

    @patch("saraki.auth.datetime")
    def test_exp_claim(self, mock_datetime, app):
        _datetime = datetime(2018, 5, 13, 17, 52, 44, 524300)
        app.config["JWT_EXPIRATION_DELTA"] = timedelta(seconds=400)
        mock_datetime.utcnow.return_value = _datetime

        user = _get_user(username="somebody")

        with app.app_context():
            payload = _generate_jwt_payload(user)

        assert payload["exp"] == _datetime + timedelta(seconds=400)

    @pytest.mark.usefixtures("data", "data_org")
    def test_scp_claim_for_organization_owners(self):

        user = User.query.filter_by(username="coyote").one()
        org = Org.query.filter_by(orgname="acme").one()

        payload = _generate_jwt_payload(user, org)

        assert "org" in payload["scp"]
        assert payload["scp"]["org"] == ["manage"]


class Test_encode_jwt(object):
    @pytest.mark.usefixtures("ctx")
    def test_with_valid_payload(self):
        iat = datetime.utcnow()
        exp = iat + timedelta(seconds=300)

        token = _encode_jwt(
            {
                "iss": "acme.local",
                "sub": "coyote",
                "iat": iat,
                "exp": exp,
                "custom": "custom claim value",
            }
        )

        _payload = jwt.decode(token, verify=False)

        assert _payload["iss"] == "acme.local"
        assert _payload["sub"] == "coyote"
        assert _payload["iat"] == timegm(iat.utctimetuple())
        assert _payload["exp"] == timegm(exp.utctimetuple())
        assert _payload["custom"] == "custom claim value"

    def test_with_missing_iss_claim(self, app):
        app.config["JWT_REQUIRED_CLAIMS"] = ["iss"]
        iat = datetime.utcnow()
        exp = iat + timedelta(seconds=300)

        error = "Payload is missing required claims: iss"

        with app.app_context():
            with pytest.raises(ValueError, match=error):
                _encode_jwt({"sub": "coyote", "iat": iat, "exp": exp})

    @pytest.mark.usefixtures("ctx")
    def test_with_various_missing_required_claims(self):
        with pytest.raises(ValueError) as error:
            _encode_jwt({})

        e = str(error)

        assert "Payload is missing required claims:" in e
        assert "iss" in e
        assert "sub" in e
        assert "iat" in e
        assert "exp" in e

    def test_when_a_secret_is_not_provided(self, app):

        app.config["SECRET_KEY"] = None

        error = "SECRET_KEY is not set. Can not generate Token"

        with app.app_context():
            with pytest.raises(RuntimeError, match=error):
                _encode_jwt({})


class Test_decode_jwt(object):
    def test_passing_invalid_data_types(self):

        with pytest.raises(ValueError, match="is not a valid JWT string"):
            _decode_jwt(None)

        with pytest.raises(ValueError, match="is not a valid JWT string"):
            _decode_jwt(1)

        with pytest.raises(ValueError, match="is not a valid JWT string"):
            _decode_jwt(True)

    def test_token_with_wrong_iss_claim(self, app, _payload):
        app.config["JWT_ISSUER"] = "acme.local"
        app.config["JWT_LEEWAY"] = timedelta(seconds=10)
        app.config["JWT_REQUIRED_CLAIMS"] = ["iss"]

        _payload["iss"] = "malicious.issuer"

        token = jwt.encode(_payload, app.config["SECRET_KEY"])

        with app.app_context():
            with pytest.raises(JWTError, match="Invalid issuer"):
                _decode_jwt(token)

    def test_token_without_iss_claim_when_is_required(self, app, _payload):
        app.config["JWT_REQUIRED_CLAIMS"] = ["iss"]
        app.config["JWT_ISSUER"] = "acme.local"
        app.config["JWT_LEEWAY"] = timedelta(seconds=10)
        del _payload["iss"]

        token = jwt.encode(_payload, app.config["SECRET_KEY"])
        error_msg = 'Token is missing the "iss" claim'

        with app.app_context():
            with pytest.raises(JWTError, match=error_msg):
                _decode_jwt(token)

    def test_token_without_iat_claim(self, app, _payload):

        app.config["JWT_LEEWAY"] = timedelta(seconds=10)
        del _payload["iat"]

        token = jwt.encode(_payload, app.config["SECRET_KEY"])
        error_msg = 'Token is missing the "iat" claim'

        with app.app_context():
            with pytest.raises(JWTError, match=error_msg):
                _decode_jwt(token)

    def test_token_without_exp_claim(self, app, _payload):

        app.config["JWT_LEEWAY"] = timedelta(seconds=10)
        del _payload["exp"]

        token = jwt.encode(_payload, app.config["SECRET_KEY"])
        error_msg = 'Token is missing the "exp" claim'

        with app.app_context():
            with pytest.raises(JWTError, match=error_msg):
                _decode_jwt(token)

    def test_with_expired_token(self, app):
        app.config["JWT_LEEWAY"] = timedelta(seconds=10)

        iat = datetime(1900, 5, 13, 17, 52, 44, 524300)
        exp = iat + timedelta(seconds=400)
        payload = {"iat": iat, "exp": exp}

        token = jwt.encode(payload, app.config["SECRET_KEY"])

        with app.app_context():
            with pytest.raises(JWTError, match="Token has expired"):
                _decode_jwt(token)

    def test_with_malformed_token(self, app, _payload):

        token = jwt.encode(_payload, app.config["SECRET_KEY"]) + b"'"

        with app.app_context():
            with pytest.raises(JWTError, match="Invalid or malformed token"):
                _decode_jwt(token)

    def test_with_valid_token_without_iss(self, app, _payload):
        app.config["JWT_LEEWAY"] = timedelta(seconds=10)

        token = jwt.encode(_payload, app.config["SECRET_KEY"])

        with app.app_context():
            decoded_payload = _decode_jwt(token)

        assert decoded_payload["sub"] == "coyote"

    def test_with_valid_token(self, app, _payload):
        app.config["SERVER_NAME"] = "acme.local"
        app.config["JWT_LEEWAY"] = timedelta(seconds=10)

        token = jwt.encode(_payload, app.config["SECRET_KEY"])

        with app.app_context():
            decoded_payload = _decode_jwt(token)

        assert decoded_payload["iss"] == "acme.local"
        assert decoded_payload["sub"] == "coyote"

    def test_with_valid_token_with_aud_claim(self, app):
        app.config["SERVER_NAME"] = "acme.local"
        app.config["JWT_LEEWAY"] = timedelta(seconds=10)

        payload = getpayload(aud="acme")
        token = jwt.encode(payload, app.config["SECRET_KEY"])

        with app.app_context():
            decoded_payload = _decode_jwt(token)

        assert decoded_payload["iss"] == "acme.local"
        assert decoded_payload["sub"] == "coyote"
        assert decoded_payload["aud"] == "acme"


class Test_is_authorized(object):
    def test_sub_claim_verification(self, app, _payload):
        @app.route("/<sub:username>/private-info")
        def private_info(username):
            return "Private information"

        _payload["sub"] = "coyote"

        with app.test_request_context("/elmer/private-info"):
            assert _is_authorized(_payload) is False

        _payload["sub"] = "elmer"

        with app.test_request_context("/elmer/private-info"):
            assert _is_authorized(_payload) is True

    @parametrize(
        "payload, expected",
        [
            (getpayload(), False),
            (getpayload(aud="unknown"), False),
            (getpayload(aud="acme"), True),
        ],
        ids=["Missing aud claim", "aud value mismatch", "aud value matches"],
    )
    def test_aud_claim_verification(self, app, payload, expected):
        @app.route("/<aud:orgname>/private-info")
        def private_info(orgname):
            return "Private information"

        with app.test_request_context("/acme/private-info"):
            assert _is_authorized(payload) is expected

    def test_routes_without_required_claim(self, app, _payload):

        # route without any view_args
        @app.route("/private-info")
        def list_private():
            return "Private information"

        # route with view_args
        @app.route("/private-info/<int:id>")
        def get_private(id):
            return "Private information"

        with app.test_request_context("/private-info"):
            assert _is_authorized(_payload) is True

        with app.test_request_context("/private-info/1"):
            assert _is_authorized(_payload) is True

    @parametrize(
        "scope, required, expected",
        [
            (None, (None, None), True),
            (None, ("movie", "delete"), False),
            ({"film": ["read"]}, (None, None), True),
            ({"film": ["read"]}, ("movie", "delete"), False),
            ({"film": ["manage"]}, ("movie", "delete"), False),
            ({"movie": ["read"]}, ("movie", "delete"), False),
            ({"movie": ["delete"]}, ("movie", "delete"), True),
            ({"movie": ["manage"]}, ("movie", "delete"), True),
        ],
        ids=[
            "without scope | resource not required",
            "without scope | resource is required",
            "with scope | resource not required",
            "missing required resource",
            "manage action but missing required resource",
            "resource match but action does not",
            "resource and action match",
            "resource match and action is manage",
        ],
    )
    def test_scope_validation(self, app, scope, required, expected):
        @app.route("/")
        def private_info():
            return ""

        payload = getpayload(scp=scope)

        resource = required[0]
        action = required[1]

        with app.test_request_context("/"):
            assert _is_authorized(payload, resource, action) is expected

    @parametrize(
        "scope, required, expected",
        [
            (None, ("catalog", "read"), False),
            ({"catalog": ["read"]}, ("catalog", "read"), True),
            ({"product": ["read"]}, ("catalog", "read"), True),
            ({"catalog": ["read"]}, ("catalog", "write"), False),
            ({"product": ["read"]}, ("catalog", "write"), False),
            ({"product": ["write"]}, ("product", "write"), True),
        ],
        ids=[
            "without scope | resource is required",
            "resource and action match",
            "resource is parent",
            "resource match but action does not",
            "resource is parent but action does not match",
            "scope and required resource are parents",
        ],
    )
    def test_scope_validation_with_nested_resource(
        self, app, scope, required, expected
    ):

        app.auth._resources = {"puchase": None, "product": {"catalog": None}}

        @app.route("/")
        def private_info():
            return ""

        payload = getpayload(scp=scope)

        resource = required[0]
        action = required[1]

        with app.test_request_context("/"):
            assert _is_authorized(payload, resource, action) is expected

    @parametrize(
        "action, method, expect",
        [
            ("custom", "CUSTOM", False),
            ("manage", "CUSTOM", False),
            ("follow", "GET", False),
            ("read", "DELETE", False),
            ("write", "GET", False),
            ("read", "GET", True),
            ("write", "POST", True),
            ("write", "PUT", True),
            ("write", "PATCH", True),
            ("delete", "DELETE", True),
            ("manage", "GET", True),
            ("manage", "POST", True),
            ("manage", "PUT", True),
            ("manage", "PATCH", True),
            ("manage", "DELETE", True),
        ],
    )
    def test_http_method_to_action_mapping(self, app, action, method, expect):
        @app.route("/", methods=[method])
        def private_info():
            return ""

        payload = getpayload(scp={"cartoon": [action]})

        with app.test_request_context("/", method=method):
            assert _is_authorized(payload, "cartoon") is expect


class Test_validate_request(object):
    def test_request_without_access_token(self, request_ctx):
        with request_ctx("/"):
            with pytest.raises(TokenNotFoundError):
                _validate_request()

    @patch("saraki.auth._verify_username")
    @patch("saraki.auth._is_authorized")
    @patch("saraki.auth._decode_jwt")
    @patch("saraki.auth._get_request_jwt")
    def test_request_with_access_token(
        self,
        mocked_get_request_jwt,
        mocked_jwt_decode_handler,
        mocked_is_authorized,
        mocked_verify_username,
        request_ctx,
    ):

        mocked_get_request_jwt.return_value = "a.nice.token"
        mocked_jwt_decode_handler.return_value = {"sub": "coyote"}

        with request_ctx("/"):
            _validate_request("stock", "read")

        mocked_get_request_jwt.assert_called_once()
        mocked_jwt_decode_handler.assert_called_once_with("a.nice.token")
        mocked_is_authorized.assert_called_once_with({"sub": "coyote"}, "stock", "read")
        mocked_verify_username.assert_called_once_with("coyote")

    @patch("saraki.auth._is_authorized")
    def test_with_unauthorized_token(self, mocked_is_authorized, app):

        token = jwt.encode(getpayload(), app.config["SECRET_KEY"]).decode()
        headers = {"Authorization": f"JWT {token}"}

        mocked_is_authorized.return_value = False

        with app.test_request_context("/", headers=headers):
            with pytest.raises(AuthorizationError):
                _validate_request()

    @pytest.mark.usefixtures("data")
    def test_with_unknown_username_in_sub_claim(self, app, _payload):

        path = f"/{randint(100, 10000)}"

        @app.route(path)
        def index():
            pass

        _payload["sub"] = "unknown"

        token = jwt.encode(_payload, app.config["SECRET_KEY"]).decode()
        headers = {"Authorization": f"JWT {token}"}

        with app.test_request_context(path, headers=headers):
            with pytest.raises(AuthorizationError):
                _validate_request()

    @pytest.mark.usefixtures("data")
    def test_with_unknown_orgname_in_aud_claim(self, app):
        path = f"/{randint(100, 10000)}"

        @app.route(path)
        def index():
            pass

        payload = getpayload(aud="unknown")

        token = jwt.encode(payload, app.config["SECRET_KEY"]).decode()
        headers = {"Authorization": f"JWT {token}"}

        with app.test_request_context(path, headers=headers):
            with pytest.raises(AuthorizationError):
                _validate_request()

    @pytest.mark.usefixtures("data")
    def test_current_user(self, app):
        @app.route("/")
        def index():
            pass

        payload = getpayload(sub="coyote")

        token = jwt.encode(payload, app.config["SECRET_KEY"]).decode()
        headers = {"Authorization": f"JWT {token}"}

        with app.test_request_context("/", headers=headers):
            _validate_request()
            assert current_user.username == "coyote"

        assert current_user._get_current_object() is None

    @pytest.mark.usefixtures("data", "data_org")
    def test_current_org(self, app):
        @app.route("/")
        def index():
            pass

        payload = getpayload(sub="coyote", aud="acme")

        token = jwt.encode(payload, app.config["SECRET_KEY"]).decode()
        headers = {"Authorization": f"JWT {token}"}

        with app.test_request_context("/", headers=headers):
            _validate_request()
            assert current_org.orgname == "acme"

        assert current_org._get_current_object() is None


@pytest.mark.usefixtures("data")
class Test_authenticate_with_password(object):
    @pytest.mark.usefixtures("ctx")
    def test_with_unknown_username(self):
        error = 'Username "extraneous" is not registered'

        with pytest.raises(InvalidUserError, match=error):
            _authenticate_with_password("extraneous", "12345")

    @pytest.mark.usefixtures("ctx")
    def test_with_wrong_password(self, ctx):

        with pytest.raises(InvalidPasswordError, match="Invalid password"):
            _authenticate_with_password("coyote", "wrongpassword")

    @pytest.mark.usefixtures("ctx")
    def test_with_valid_username_and_password(self):
        identity = _authenticate_with_password("coyote", "12345")

        assert identity.username == "coyote"


@pytest.mark.usefixtures("data")
class Test_authenticate_with_token(object):
    def test_token_with_unregistered_username(self, app, _payload):

        _payload["sub"] = "unknown"

        token = jwt.encode(
            _payload, app.config["SECRET_KEY"], algorithm=app.config["JWT_ALGORITHM"]
        )

        error = 'Username "unknown" is not registered'

        with app.app_context():
            with pytest.raises(InvalidUserError, match=error):
                _authenticate_with_token(token)

    def test_token_with_registered_username(self, app, _payload):

        token = jwt.encode(
            _payload, app.config["SECRET_KEY"], algorithm=app.config["JWT_ALGORITHM"]
        )

        with app.app_context():
            user = _authenticate_with_token(token)

        assert user.username == "coyote"


class Test_authenticate(object):
    def test_request_without_credentials_or_token(self, request_ctx):

        with request_ctx("/"):
            with pytest.raises(NotFoundCredentialError):
                _authenticate()

    def test_request_without_username(self, request_ctx):

        body = dumps({"password": "12345"})

        with request_ctx("/", data=body, content_type="application/json"):
            with pytest.raises(BadRequest):
                _authenticate()

    def test_request_without_password(self, request_ctx):

        body = dumps({"username": "coyote"})

        with request_ctx("/", data=body, content_type="application/json"):
            with pytest.raises(BadRequest):
                _authenticate()

    @pytest.mark.usefixtures("data")
    def test_request_passing_unregistered_orgname(self, request_ctx):

        body = dumps({"username": "Y0seSam", "password": "secret"})

        with request_ctx("/", data=body, content_type="application/json"):
            with pytest.raises(NotFound):
                _authenticate("unknown")

    @pytest.mark.usefixtures("data", "data_org")
    def test_request_passing_registered_orgname(self, request_ctx):

        body = dumps({"username": "coyote", "password": "12345"})

        with request_ctx("/", data=body, content_type="application/json"):
            rv = _authenticate("acme")

        assert rv.status_code == 200
        assert "access_token" in loads(rv.data)


@pytest.mark.usefixtures("data")
class TestAuthenticationRequest(object):
    """Integration test of ``/auth`` and ``/auth/<orgname>`` endpoints."""

    @parametrize(
        "req_payload",
        [
            (None),
            ({}),
            ({"password": "12345"}),
            ({"username": "coyote"}),
            ({"username": "coyote", "password": "wrongpassword"}),
            ({"username": "unknown", "password": "123456"}),
        ],
        ids=[
            "Empty request payload",
            "Empty dictionary",
            "Missing username",
            "Missing password",
            "Wrong password",
            "Unregistered username",
        ],
    )
    def test_invalid_authentication_request(self, client, req_payload):

        rv = client.post(
            "/auth", data=dumps(req_payload), content_type="application/json"
        )

        assert rv.status_code == 400

    def test_request_with_valid_credentials(self, client):

        body = {"username": "coyote", "password": "12345"}

        rv = client.post("/auth", data=dumps(body), content_type="application/json")

        assert rv.status_code == 200
        token = loads(rv.data)["access_token"]
        payload = jwt.decode(token, verify=False)

        assert payload["sub"] == "coyote"

    def test_request_with_valid_token(self, app, _payload):
        token = jwt.encode(
            _payload, app.config["SECRET_KEY"], algorithm=app.config["JWT_ALGORITHM"]
        ).decode()

        rv = app.test_client().post(
            "/auth",
            headers={"Authorization": f"JWT {token}"},
            content_type="application/json",
        )

        assert rv.status_code == 200
        token = loads(rv.data)["access_token"]
        payload = jwt.decode(token, verify=False)

        assert payload["sub"] == "coyote"

    @pytest.mark.usefixtures("data", "data_org")
    @parametrize(
        "req_payload",
        [
            (None),
            ({}),
            ({"password": "12345"}),
            ({"username": "coyote"}),
            ({"username": "coyote", "password": "wrongpassword"}),
            ({"username": "unknown", "password": "123456"}),
            ({"username": "R0adRunner", "password": "password"}),
        ],
        ids=[
            "Empty request payload",
            "Empty dictionary",
            "Missing username",
            "Missing password",
            "Wrong password",
            "Unregistered username",
            "Not a member",
        ],
    )
    def test_invalid_org_authentication_request(self, client, req_payload):

        rv = client.post(
            "/auth/acme", data=dumps(req_payload), content_type="application/json"
        )

        assert rv.status_code == 400

    def test_unregistered_org_authentication_request(self, client):

        orgname = "unknown"
        request_payload = {"username": "Coyote", "password": "123456"}

        rv = client.post(
            f"/auth/{orgname}",
            data=dumps(request_payload),
            content_type="application/json",
        )

        assert rv.status_code == 404

    @pytest.mark.usefixtures("data", "data_org")
    @parametrize(
        "payload, expected",
        [(getpayload(sub="R0adRunner"), 400), (getpayload(sub="coyote"), 200)],
        ids=["Not a member", "Owner"],
    )
    def test_org_auth_request_using_valid_tokens(self, app, payload, expected):

        token = jwt.encode(
            payload, app.config["SECRET_KEY"], algorithm=app.config["JWT_ALGORITHM"]
        ).decode()

        rv = app.test_client().post(
            "/auth/acme",
            headers={"Authorization": f"JWT {token}"},
            content_type="application/json",
        )

        assert rv.status_code == expected

        if rv.status_code == 200:
            token = loads(rv.data)["access_token"]
            payload = jwt.decode(token, verify=False)

            assert payload["sub"] == "coyote"
            assert payload["aud"] == "acme"


class TestRequireAuth(object):
    def test_pass_action_without_resource(self):
        error_msg = "You passed an action 'read' without a resource"

        with pytest.raises(ProgrammingError, match=error_msg):
            require_auth(action="read")

    @parametrize(
        "resource, action, parent_resource",
        [("stock", None, None), ("stock", "read", None), ("stock", "read", "market")],
    )
    def test_auth_metadata(self, resource, action, parent_resource):
        @require_auth(resource, action, parent_resource)
        def endpoint():
            return "private content"

        assert hasattr(endpoint, "_auth_metadata")
        assert endpoint._auth_metadata == {
            "resource": resource,
            "action": action,
            "parent_resource": parent_resource,
        }

    @patch("saraki.auth._validate_request")
    @parametrize("resource, action", [(None, None), ("stock", None), ("stock", "read")])
    def test_call_to_validate_request_internal_function(
        self, mocked_validate_request, resource, action
    ):
        @require_auth(resource, action)
        def private():
            return "private content"

        private()

        mocked_validate_request.assert_called_once_with(resource, action)


class TestAuth(object):
    def test_instantiation(self):
        auth = Auth()
        assert not hasattr(auth, "app")

        with patch.object(Auth, "init_app") as mocked_init_app:
            app = Flask(__name__)
            auth = Auth(app)
            mocked_init_app.assert_called_once_with(app)

    def test_init_app(self):
        app = Flask(__name__)
        auth = Auth()
        auth.init_app(app)

        adapter = app.url_map.bind("")

        assert adapter.match("/auth", method="POST")
        assert auth.app is app

    def test_add_resource(self):
        auth = Auth()
        auth._add_resource("lonely")

        assert "lonely" in auth.resources

        auth = Auth()
        auth._add_resource("purchase", "commerce")

        assert "commerce" in auth.resources
        assert "purchase" in auth.resources["commerce"]

        auth = Auth()
        auth._add_resource("product")
        auth._add_resource("catalog")
        auth._add_resource("product")

        assert len(auth.resources) == 2
        assert "catalog" in auth.resources
        assert "product" in auth.resources

        auth = Auth()
        auth._add_resource("sale", "commerce")
        auth._add_resource("purchase", "commerce")

        assert auth.resources == {"commerce": {"sale": None, "purchase": None}}

    @parametrize("value", (None, 1, True, [], ()))
    def test_add_resouce_with_invalid_value(self, value):
        auth = Auth()

        with pytest.raises(TypeError):
            auth._add_resource(value)

    @parametrize(
        "actions, length",
        [
            (("read", "update", "read", "update", "create"), 4),
            (("read", "create", "update", "delete"), 5),
        ],
    )
    def test_add_action(self, actions, length):
        auth = Auth()

        for action_name in actions:
            auth._add_action(action_name)

        assert len(auth.actions) == length

    @parametrize("value", (None, 1, True, [], ()))
    def test_add_action_with_invalid_value(self, value):
        auth = Auth()

        with pytest.raises(TypeError):
            auth._add_action(value)

    def test_collect_metadata(self):
        app = Flask(__name__)
        auth = Auth(app)

        @app.route("/sales")
        @require_auth("sale", "read", "biz")
        def list_sale():
            pass

        @app.route("/sales", methods=["POST"])
        @require_auth("sale", "create", "biz")
        def add_sale():
            pass

        @app.route("/sales/1")
        @require_auth()
        def get_one_sale():
            pass

        auth._add_resource = Mock()
        auth._add_action = Mock()

        auth._collect_metadata()

        assert auth._add_resource.call_count == 2
        auth._add_resource.assert_has_calls([call("sale", "biz"), call("sale", "biz")])

        assert auth._add_resource.call_count == 2
        auth._add_action.assert_has_calls([call("read"), call("create")])


@pytest.mark.usefixtures("data")
class TestEndpoint(object):
    @parametrize(
        "payload, expected",
        [
            (None, 401),
            (getpayload(sub="unknown"), 401),
            (getpayload(sub="coyote"), 200),
        ],
    )
    def test_route_without_sub_variable_rule(self, app, payload, expected):

        client = app.test_client()

        @app.route("/movies")
        @require_auth()
        def movies():
            return "movies"

        headers = {}

        if payload:
            token = jwt.encode(
                payload, app.config["SECRET_KEY"], algorithm=app.config["JWT_ALGORITHM"]
            )
            headers["Authorization"] = f"JWT {token.decode()}"

        assert client.get("/movies", headers=headers).status_code == expected

    @parametrize(
        "payload, expected",
        [
            (None, 401),
            (getpayload(sub="unknown"), 401),
            (getpayload(sub="R0adRunner"), 401),
            (getpayload(sub="coyote"), 200),
        ],
    )
    def test_route_with_sub_variable_rule(self, app, payload, expected):

        client = app.test_client()

        @app.route("/<sub:username>/my-movies")
        @require_auth()
        def my_movies(username):
            return "Those are your movies"

        headers = {}

        if payload:
            token = jwt.encode(
                payload, app.config["SECRET_KEY"], algorithm=app.config["JWT_ALGORITHM"]
            )

            headers["Authorization"] = f"JWT {token.decode()}"

        rv = client.get("/coyote/my-movies", headers=headers)
        assert rv.status_code == expected

    @pytest.mark.usefixtures("data", "data_org")
    @parametrize(
        "payload, expected",
        [
            (None, 401),
            (getpayload(sub="coyote", aud="unknown"), 401),
            (getpayload(sub="coyote", aud="acme"), 200),
        ],
    )
    def test_route_with_aud_variable_rule(self, app, payload, expected):
        @app.route("/<aud:orgname>/stocks")
        @require_auth()
        def stocks(orgname):
            return "All the stocks"

        headers = {}

        if payload:
            token = jwt.encode(
                payload, app.config["SECRET_KEY"], algorithm=app.config["JWT_ALGORITHM"]
            )

            headers["Authorization"] = f"JWT {token.decode()}"

        client = app.test_client()
        rv = client.get("/acme/stocks", headers=headers)
        assert rv.status_code == expected

    @parametrize(
        "payload, expected",
        [
            (None, 401),
            (getpayload(), 200),
            (getpayload({"film": ["manage"]}), 200),
            (getpayload({"movie": ["write"]}), 200),
        ],
        ids=[
            "without token",
            "token without scope",
            "token with manage action",
            "token with different action",
        ],
    )
    def test_without_required_resource(self, app, payload, expected):

        client = app.test_client()

        @app.route("/movies")
        @require_auth()
        def movies():
            return "movies"

        headers = {}

        if payload:
            token = jwt.encode(
                payload, app.config["SECRET_KEY"], algorithm=app.config["JWT_ALGORITHM"]
            )
            headers["Authorization"] = f"JWT {token.decode()}"

        assert client.get("/movies", headers=headers).status_code == expected

    @parametrize(
        "payload, expected",
        [
            (None, 401),
            (getpayload(), 401),
            (getpayload({"film": ["manage"]}), 401),
            (getpayload({"movie": ["read"]}), 401),
            (getpayload({"movie": ["write"]}), 200),
        ],
        ids=[
            "without token",
            "token: without scope",
            "token: missing required resource",
            "token: action mismatch",
            "token: with required resource/action",
        ],
    )
    def test_with_required_resource(self, app, payload, expected):
        @app.route("/movies", methods=["POST"])
        @require_auth("movie")
        def movies():
            return "movies"

        headers = {}

        if payload:
            token = jwt.encode(
                payload, app.config["SECRET_KEY"], algorithm=app.config["JWT_ALGORITHM"]
            )
            headers["Authorization"] = f"JWT {token.decode()}"

        client = app.test_client()
        assert client.post("/movies", headers=headers).status_code == expected

    @parametrize(
        "payload, expected",
        [
            (None, 401),
            (getpayload(), 401),
            (getpayload({"film": ["manage"]}), 401),
            (getpayload({"film": ["write"]}), 401),
            (getpayload({"movie": ["change"]}), 200),
        ],
    )
    def test_with_explicit_required_action(self, app, payload, expected):

        client = app.test_client()

        @app.route("/movies", methods=["PUT"])
        @require_auth("movie", "change")
        def movies():
            return "movies"

        headers = {}

        if payload:
            token = jwt.encode(
                payload, app.config["SECRET_KEY"], algorithm=app.config["JWT_ALGORITHM"]
            )
            headers["Authorization"] = f"JWT {token.decode()}"

        assert client.put("/movies", headers=headers).status_code == expected


def test_register_persist_actions_handler():
    auth = Auth()

    @auth.persist_actions
    def custom_handler(actions):
        pass

    assert auth._persist_actions_func == custom_handler


def test_register_persist_resources_handler():
    auth = Auth()

    @auth.persist_resources
    def custom_handler(resources):
        pass

    assert auth._persist_resources_func == custom_handler
