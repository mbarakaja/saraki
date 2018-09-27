import os
import pytest
from unittest.mock import patch
from datetime import timedelta

from saraki.auth import require_auth
from saraki.model import Resource, Action
from saraki.config import Config


@pytest.mark.usefixtures("ctx", "savepoint")
def test_init(app):
    @app.route("/routes")
    @require_auth("resource1", "action1")
    def route():
        pass

    app.init()

    assert Action.query.filter_by(name="action1").first()
    assert Resource.query.filter_by(name="resource1").first()


class TestConfig:
    def test_server_name(self):
        with patch.dict(os.environ, {}):
            assert Config().SERVER_NAME is None

        with patch.dict(os.environ, {"SRK_SERVER_NAME": "localhost"}):
            assert Config().SERVER_NAME == "localhost"

    def test_secret_key(self):
        with patch.dict(os.environ, {}):
            assert Config().SECRET_KEY is None

        with patch.dict(os.environ, {"SRK_SECRET_KEY": "secret"}):
            assert Config().SECRET_KEY == "secret"

    def test_sqlalchemy_database_uri(self):
        with patch.dict(os.environ, {}):
            assert Config().SQLALCHEMY_DATABASE_URI is None

        with patch.dict(os.environ, {"SRK_DATABASE_URI": "uri"}):
            assert Config().SQLALCHEMY_DATABASE_URI == "uri"

    def test_jwt_prefix(self):
        assert Config().JWT_AUTH_HEADER_PREFIX == "JWT"

    def test_jwt_algorithm(self):
        assert Config().JWT_ALGORITHM == "HS256"

    def test_jwt_leeway(self):
        assert Config().JWT_LEEWAY == timedelta(seconds=10)

    def test_jwt_expiration_delta(self):
        assert Config().JWT_EXPIRATION_DELTA == timedelta(seconds=300)

    def test_jwt_issuer(self):
        with patch.dict(os.environ, {}):
            assert Config().JWT_ISSUER is None

        with patch.dict(os.environ, {"SRK_SERVER_NAME": "localhost"}):
            assert Config().JWT_ISSUER == "localhost"

    def test_jwt_required_claims(self):
        with patch.dict(os.environ, {}):
            assert Config().JWT_REQUIRED_CLAIMS == ["exp", "iat", "sub"]
