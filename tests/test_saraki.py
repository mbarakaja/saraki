from saraki import Saraki
from saraki.auth import Auth
from saraki.model import database
from flask_sqlalchemy import SQLAlchemy


def test_basic():
    app = Saraki(__name__)

    assert isinstance(app.auth, Auth)
    assert app.extensions["sqlalchemy"].db is database
    assert "app" in app.blueprints


def test_without_auth_object():
    app = Saraki(__name__, auth=None)

    assert not hasattr(app, "auth")
    assert "app" not in app.blueprints


def test_passing_custom_auth_object():
    auth = Auth()
    app = Saraki(__name__, auth=auth)

    assert app.auth is auth
    assert "app" in app.blueprints


def test_without_database_object():
    app = Saraki(__name__, db=None)

    assert "sqlalchemy" not in app.extensions


def test_passing_custom_database_object():
    custom_database = SQLAlchemy()
    app = Saraki(__name__, db=custom_database)

    assert app.extensions["sqlalchemy"].db is custom_database
