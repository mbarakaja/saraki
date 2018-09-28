import pytest
from json import dumps
from passlib.hash import bcrypt_sha256
from saraki.testing import assert_allowed_methods
from saraki.model import User


def test_allowed_methods(app):
    assert_allowed_methods("/signup", ["POST"], app)


@pytest.mark.usefixtures("data")
def test_signup_with_duplicate_username(client):
    user = User.query.first()
    data = {"email": "random@email", "username": user.username, "password": "123"}
    rv = client.post("/signup", data=dumps(data), content_type="application/json")

    assert rv.status_code == 400


@pytest.mark.usefixtures("data")
def test_signup_with_duplicate_email(client):
    user = User.query.first()
    data = {"email": user.email, "username": "Elmer", "password": "123"}
    rv = client.post("/signup", data=dumps(data), content_type="application/json")

    assert rv.status_code == 400


def test_signup_user(client):
    data = {"email": "elmer@acme", "username": "Elmer", "password": "123"}
    rv = client.post("/signup", data=dumps(data), content_type="application/json")

    assert rv.status_code == 201

    user = User.query.filter_by(username="Elmer").one()

    assert user.email == "elmer@acme"
    assert user.username == "Elmer"
    assert user.canonical_username == "elmer"
    assert bcrypt_sha256.identify(user.password) is True


def test_password_column():
    user = User()
    user.password = "12345"

    assert user.password != "12345"
    assert bcrypt_sha256.identify(user.password) is True


def test_canonical_username_column():
    user = User()
    user.username = "MoMo"

    assert user.canonical_username == "momo"


def test_verify_password():
    user = User()
    user.password = "12345"

    assert user.password != "12345"
    assert user.verify_password("12345") is True
