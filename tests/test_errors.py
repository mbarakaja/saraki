import pytest
from json import loads
from flask import abort

from saraki.exc import (
    NotFoundCredentialError,
    InvalidUserError,
    InvalidPasswordError,
    InvalidOrgError,
    InvalidMemberError,
    JWTError,
    TokenNotFoundError,
    AuthorizationError,
)

parametrize = pytest.mark.parametrize


def test_not_found_credential_handler(app, client):
    @app.route("/")
    def index():
        raise NotFoundCredentialError()

    rv = client.get("/")
    data = loads(rv.data)

    assert rv.status_code == 400
    assert data["error"] == "Provide an access token or a username/password"


def test_invalid_user_handler(app, client):
    @app.route("/")
    def index():
        raise InvalidUserError()

    client = app.test_client()
    rv = client.get("/")
    data = loads(rv.data)

    assert rv.status_code == 400
    assert data["error"] == "Invalid username or password"


def test_invalid_password_handler(app, client):
    @app.route("/")
    def index():
        raise InvalidPasswordError()

    rv = client.get("/")
    data = loads(rv.data)

    assert rv.status_code == 400
    assert data["error"] == "Invalid username or password"


def test_invalid_org_handler(app, client):
    @app.route("/")
    def index():
        raise InvalidOrgError()

    rv = client.get("/")
    data = loads(rv.data)

    assert rv.status_code == 400
    assert data["error"] == "Invalid organization"


def test_invalid_member_handler(app, client):
    @app.route("/")
    def index():
        raise InvalidMemberError("Invalid member message")

    rv = client.get("/")
    data = loads(rv.data)

    assert rv.status_code == 400
    assert data["error"] == "Invalid member message"


def test_jwt_error_handler(app, client):
    @app.route("/")
    def index():
        raise JWTError("Token related error message")

    rv = client.get("/")
    data = loads(rv.data)

    assert rv.status_code == 400
    assert data["error"] == "Token related error message"


@parametrize("error_value", ("An error message", {"prop": "value"}, 1))
def test_bad_request(app, client, error_value):
    @app.route("/")
    def index():
        abort(400, error_value)

    rv = client.get("/")
    data = loads(rv.data)

    assert rv.status_code == 400
    assert data["error"] == error_value


def test_not_found_token_handler(app, client):
    @app.route("/")
    def index():
        raise TokenNotFoundError()

    rv = client.get("/")
    data = loads(rv.data)

    assert rv.status_code == 401
    assert data["error"] == "The request does not contain an access token"


def test_authorization_error_handler(app, client):
    @app.route("/")
    def index():
        raise AuthorizationError()

    rv = client.get("/")
    data = loads(rv.data)

    assert rv.status_code == 401
    assert data["error"] == "Invalid access token for this resource"
