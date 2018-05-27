import pytest
from json import dumps, loads
from saraki.model import database
from app import app

app.testing = True


@pytest.fixture(scope='module', autouse=True)
def add_user():
    data = {'username': 'elmer', 'password': 'password', 'email': 'elmer@acme'}

    app.test_client().post(
        '/signup', data=dumps(data), content_type='application/json')

    yield

    with app.app_context():
        database.drop_all()


@pytest.fixture
def client():
    return app.test_client()


@pytest.fixture
def access_token(client):
    data = dumps({'username': 'elmer', 'password': 'password'})
    rv = client.post('/auth', data=data, content_type='application/json')
    return f'JWT {loads(rv.data)["access_token"]}'


def test_request_to_home(client):
    rv = client.get('/')
    assert rv.data == b'Home'


def test_request_to_locked_endpoint(client, access_token):
    rv = client.get('/locked')
    assert rv.status_code == 404

    headers = {'Authorization': access_token}
    rv = client.get('/locked', headers=headers)
    assert rv.status_code == 200
    assert rv.data == b'locked'


def test_request_to_user_info_endpoint(client, access_token):
    rv = client.get('/elmer-info')
    assert rv.status_code == 404

    headers = {'Authorization': access_token}

    rv = client.get('/Coy0te-info', headers=headers)
    assert rv.status_code == 404

    rv = client.get('/elmer-info', headers=headers)
    assert rv.status_code == 200
    assert rv.data == b'This information is just for elmer'
