from json import dumps
from passlib.hash import bcrypt_sha256
from saraki.model import AppUser

data = {'email': 'elmer@acme', 'username': 'Elmer', 'password': '123'}


def test_signup_user_endpoint(client):

    rv = client.post('/signup', data=dumps(data),
                     content_type='application/json')

    assert rv.status_code == 201

    user = AppUser.query.filter_by(username='Elmer').one()

    assert user.id is not None
    assert user.email == 'elmer@acme'
    assert user.username == 'Elmer'
    assert user.canonical_username == 'elmer'
    assert bcrypt_sha256.identify(user.password) is True


def test_user_password_hash(client):

    client.post('/signup', data=dumps(data),
                content_type='application/json')

    user = AppUser.query.filter_by(username='Elmer').one()

    assert bcrypt_sha256.identify(user.password) is True
