from json import dumps
from passlib.hash import bcrypt_sha256
from saraki.model import User

data = {'email': 'elmer@acme', 'username': 'Elmer', 'password': '123'}


def test_signup_user_endpoint(client):

    rv = client.post('/signup', data=dumps(data),
                     content_type='application/json')

    assert rv.status_code == 201

    user = User.query.filter_by(username='Elmer').one()

    assert user.id is not None
    assert user.email == 'elmer@acme'
    assert user.username == 'Elmer'
    assert user.canonical_username == 'elmer'
    assert bcrypt_sha256.identify(user.password) is True


def test_user_password_hash(client):

    client.post('/signup', data=dumps(data),
                content_type='application/json')

    user = User.query.filter_by(username='Elmer').one()

    assert bcrypt_sha256.identify(user.password) is True
