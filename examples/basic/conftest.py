import json
import pytest
from dotenv import load_dotenv, find_dotenv
from saraki.model import database
from test_endpoints import login
from app import app

app.testing = True

load_dotenv(find_dotenv())


@pytest.fixture(scope='session')
def setup_database(request):

    with app.app_context():
        database.create_all()

    client = app.test_client()
    data = {'username': 'elmer', 'password': 'password', 'email': 'elmer@acme'}

    client.post(
        '/signup',
        data=json.dumps(data),
        content_type='application/json'
    )

    token = login(client, username='elmer', password='password')

    client.post(
        '/users/elmer/orgs',
        data=json.dumps({'orgname': 'elmerinc', 'name': 'Elmer Inc'}),
        content_type='application/json',
        headers={'Authorization': token}
    )

    def teardown():
        with app.app_context():
            database.drop_all()

    request.addfinalizer(teardown)


@pytest.fixture
def client(setup_database):
    return app.test_client()
