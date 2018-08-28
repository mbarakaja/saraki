import jwt
import pytest
from datetime import datetime, timedelta
from unittest.mock import patch, MagicMock
from json import loads, dumps
from assertions import list_is
from cerberus import Validator
from sqlalchemy.orm import joinedload
from saraki.model import User, Org, Membership
from saraki.utility import generate_schema
from saraki.handlers import ORG_SCHEMA


@pytest.mark.usefixtures('client')
def login(username, orgname=None, scope=None):
    iat = datetime.utcnow()
    exp = iat + timedelta(seconds=6000)
    payload = {
        'iss': 'acme.local',
        'sub': username,
        'iat': iat,
        'exp': exp,
    }

    if orgname:
        payload.update({
            'aud': orgname,
            'scp': {'org': ['manage']},
        })

    if scope:
        payload.update({
            'scp': scope,
        })

    token = jwt.encode(payload, 'secret').decode()

    return f'JWT {token}'


@pytest.mark.usefixtures('data')
@patch('saraki.handlers.Validator')
def test_add_org_endpoint_data_validation(MockValidator, client):

    v = MagicMock()
    MockValidator.return_value = v
    v.validate.return_value = False
    v.errors = {}
    access_token = login('Coy0te')

    rv = client.post(
        '/users/Coy0te/orgs',
        data=dumps({'prop': 'value'}),
        content_type='application/json',
        headers={'Authorization': access_token},
    )

    assert rv.status_code == 400

    MockValidator.assert_called_once_with(ORG_SCHEMA, Org)
    v.validate.assert_called_once_with({'prop': 'value'})


@pytest.mark.usefixtures('data', 'data_org')
@pytest.mark.parametrize(
    'req_payload, status_code',
    [
        ({}, 400),
        ({'orgname': 'acme', 'name': 'Acme Corporation'}, 400),
        ({'orgname': 'choco', 'name': 'The Chocolate Factory'}, 201)
    ]
)
def test_add_org_endpoint(req_payload, status_code, client):

    rv = client.post(
        '/users/Coy0te/orgs',
        data=dumps(req_payload),
        content_type='application/json',
        headers={'Authorization': login('Coy0te')},
    )

    assert rv.status_code == status_code

    if rv.status_code == 201:
        org = Org.query \
            .options(
                joinedload(Org.created_by)
            ).filter_by(
                orgname=req_payload['orgname']
            ).one()

        member = Membership.query \
            .filter_by(
                app_org_id=org.id,
                app_user_id=org.created_by.id,
            ).one()

        assert org.orgname == 'choco'
        assert org.name == 'The Chocolate Factory'
        assert org.created_by.username == 'Coy0te'
        assert member.is_owner is True


@pytest.mark.usefixtures('data', 'data_org')
@pytest.mark.parametrize(
    "username, expected_lst",
    [
        ('Coy0te', [{'orgname': 'acme'}]),
        ('Y0seSam', []),
    ]
)
def test_list_user_orgs_endpoint(client, username, expected_lst):

    token = login(username)
    url = f'/users/{username}/orgs'
    rv = client.get(url, headers={'Authorization': token})

    assert rv.status_code == 200

    returned_lst = loads(rv.data)

    assert len(expected_lst) == len(returned_lst)
    assert list_is(expected_lst) <= returned_lst


user_response_schema = generate_schema(
    User, exclude=['id', 'password', 'canonical_username'])


member_response_schema = {
   'user': {'type': 'dict', 'required': True, 'schema': user_response_schema},
   'is_owner': {'type': 'boolean', 'required': True},
   'enabled': {'type': 'boolean', 'required': True},
}


@pytest.mark.usefixtures('data', 'data_member')
def test_list_members(client):
    token = login('Coy0te', 'acme', scope={'org': ['read']})

    rv = client.get(
        '/orgs/acme/members',
        headers={'Authorization': token},
    )

    assert rv.status_code == 200

    data = loads(rv.data)
    assert len(data) is 3

    v = Validator(member_response_schema)

    assert v.validate(data[0]), v.errors


@pytest.mark.usefixtures('data', 'data_org')
@pytest.mark.parametrize(
    "username, status, error",
    [
        ('unknown', 400, 'User unknown does not exist'),
        ('Coy0te', 400, 'Coy0te is already a member of acme'),
    ]
)
def test_add_member_with_invalid_user(client, username, status, error):
    data = {'username': username}
    token = login('Coy0te', 'acme')

    rv = client.post(
        '/orgs/acme/members',
        data=dumps(data),
        content_type='application/json',
        headers={'Authorization': token},
    )

    body = loads(rv.data)

    assert rv.status_code == status
    assert error in body['error']['username']


@pytest.mark.usefixtures('data', 'data_org')
def test_add_member(client):
    data = {'username': 'R0adRunner'}
    token = login('Coy0te', 'acme')

    rv = client.post(
        '/orgs/acme/members',
        data=dumps(data),
        content_type='application/json',
        headers={'Authorization': token},
    )

    assert rv.status_code == 201

    v = Validator(member_response_schema)
    data = loads(rv.data)
    assert v.validate(data), v.errors


@pytest.mark.usefixtures('data')
def test_list_plans(client):

    rv = client.get('/plans')
    rv.status_code == 200

    data = loads(rv.data)
    assert len(data) == 3


@pytest.mark.usefixtures('data')
def test_get_plan(client):

    rv = client.get('/plans/1')
    rv.status_code == 200

    data = loads(rv.data)
    assert data['id'] == 1


@pytest.mark.usefixtures('data')
def test_add_plan(client):
    token = login('Coy0te', scope={"app": ["write"]})
    data = {'name': 'Enterprise', 'amount_of_members': 500, "price": 1000}

    rv = client.post(
        '/plans',
        data=dumps(data),
        content_type='application/json',
        headers={'Authorization': token},
    )

    assert rv.status_code == 201, rv.data

    data = loads(rv.data)


@pytest.mark.usefixtures('data')
def test_delete_plan(client):
    token = login('Coy0te', scope={"app": ["delete"]})
    url = '/plans/1'

    rv = client.delete(url, headers={'Authorization': token})

    assert rv.status_code == 200
    assert client.get(url).status_code == 404
