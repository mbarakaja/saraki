import json
import pytest
from saraki.model import database

from app import app

app.testing = True


@pytest.fixture(scope='session')
def setup_database(request):

    with app.app_context():
        database.create_all()

    data = {'username': 'elmer', 'password': 'password', 'email': 'elmer@acme'}

    app.test_client().post(
        '/signup', data=json.dumps(data), content_type='application/json')

    def teardown():
        with app.app_context():
            database.drop_all()

    request.addfinalizer(teardown)


@pytest.fixture
def client(setup_database):
    return app.test_client()
