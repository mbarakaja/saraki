from json import dumps, loads


def login(client, username, password, orgname=None):
    data = dumps(dict(username=username, password=password))
    path = f'/auth/{orgname}' if orgname else '/auth'

    rv = client.post(path, data=data, content_type='application/json')

    return f'JWT {loads(rv.data)["access_token"]}'


def test_request_to_home(client):
    rv = client.get('/')
    assert rv.data == b'Home'


def test_request_to_locked_endpoint(client,):

    access_token = login(client, username='elmer', password='password')

    rv = client.get('/locked')
    assert rv.status_code == 401

    headers = {'Authorization': access_token}
    rv = client.get('/locked', headers=headers)
    assert rv.status_code == 200
    assert rv.data == b'locked'


def test_request_to_user_info_endpoint(client):

    access_token = login(client, username='elmer', password='password')
    headers = {'Authorization': access_token}

    rv = client.get('/Coy0te-info', headers=headers)
    assert rv.status_code == 401

    rv = client.get('/elmer-info', headers=headers)
    assert rv.status_code == 200
    assert rv.data == b'This information is just for elmer'


def test_request_to_org_info_endpoint(client):
    access_token = login(
        client,
        username='elmer',
        password='password',
        orgname='elmerinc',
    )

    headers = {'Authorization': access_token}

    rv = client.get('/orgs/acme-info', headers=headers)
    assert rv.status_code == 401

    rv = client.get('/orgs/elmerinc-info', headers=headers)

    assert rv.status_code == 200
    assert rv.data == b'This information is just for elmerinc'
