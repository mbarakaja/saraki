import jwt
import pytest
from datetime import datetime, timedelta
from unittest.mock import patch, MagicMock
from json import loads, dumps
from assertions import list_is
from sqlalchemy.orm import joinedload
from saraki.model import AppOrg, AppOrgMember
from saraki.handlers import ORG_SCHEMA


def login(username):

    iat = datetime.utcnow()
    exp = iat + timedelta(seconds=6000)
    payload = {
        'iss': 'acme.local',
        'sub': username,
        'iat': iat,
        'exp': exp,
    }

    token = jwt.encode(payload, 'secret').decode()

    return f'JWT {token}'


@pytest.mark.usefixtures('data')
@patch('saraki.handlers.Validator')
def test_add_org_endpoint_data_validation(MockValidator, client):

    v = MagicMock()
    MockValidator.return_value = v
    v.validate.return_value = False

    access_token = login('Coy0te')

    client.post(
        '/users/Coy0te/orgs',
        data=dumps({'prop': 'value'}),
        content_type='application/json',
        headers={'Authorization': access_token},
    )

    MockValidator.assert_called_once_with(ORG_SCHEMA, AppOrg)
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
        org = AppOrg.query \
            .options(
                joinedload(AppOrg.created_by)
            ).filter_by(
                orgname=req_payload['orgname']
            ).one()

        member = AppOrgMember.query \
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
