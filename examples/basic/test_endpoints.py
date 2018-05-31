import pytest
from json import dumps, loads


@pytest.fixture
def _access_token(client):
    data = dumps({'username': 'elmer', 'password': 'password'})
    rv = client.post('/auth', data=data, content_type='application/json')
    return f'JWT {loads(rv.data)["access_token"]}'


def test_request_to_home(client):
    rv = client.get('/')
    assert rv.data == b'Home'


def test_request_to_locked_endpoint(client, _access_token):
    rv = client.get('/locked')
    assert rv.status_code == 404

    headers = {'Authorization': _access_token}
    rv = client.get('/locked', headers=headers)
    assert rv.status_code == 200
    assert rv.data == b'locked'


def test_request_to_user_info_endpoint(client, _access_token):
    rv = client.get('/elmer-info')
    assert rv.status_code == 404

    headers = {'Authorization': _access_token}

    rv = client.get('/Coy0te-info', headers=headers)
    assert rv.status_code == 404

    rv = client.get('/elmer-info', headers=headers)
    assert rv.status_code == 200
    assert rv.data == b'This information is just for elmer'
