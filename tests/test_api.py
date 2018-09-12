import pytest
from unittest.mock import patch, MagicMock
from json import loads, dumps
from assertions import list_is
from cerberus import Validator
from sqlalchemy.orm import joinedload
from saraki.model import User, Org, Membership, Resource, Action, Ability
from saraki.utility import generate_schema
from saraki.api import ORG_SCHEMA
from saraki.testing import assert_allowed_methods

from common import login


pytestmark = pytest.mark.usefixtures("data")


@patch("saraki.api.Validator")
def test_add_org_endpoint_data_validation(MockValidator, client):

    v = MagicMock()
    MockValidator.return_value = v
    v.validate.return_value = False
    v.errors = {}
    access_token = login("coyote")

    rv = client.post(
        "/users/coyote/orgs",
        data=dumps({"prop": "value"}),
        content_type="application/json",
        headers={"Authorization": access_token},
    )

    assert rv.status_code == 400

    MockValidator.assert_called_once_with(ORG_SCHEMA, Org)
    v.validate.assert_called_once_with({"prop": "value"})


@pytest.mark.usefixtures("data_org")
@pytest.mark.parametrize(
    "req_payload, status_code",
    [
        ({}, 400),
        ({"orgname": "acme", "name": "Acme Corporation"}, 400),
        ({"orgname": "choco", "name": "The Chocolate Factory"}, 201),
    ],
)
def test_add_org_endpoint(req_payload, status_code, client):

    rv = client.post(
        "/users/coyote/orgs",
        data=dumps(req_payload),
        content_type="application/json",
        headers={"Authorization": login("coyote")},
    )

    assert rv.status_code == status_code

    if rv.status_code == 201:
        org = (
            Org.query.options(joinedload(Org.created_by))
            .filter_by(orgname=req_payload["orgname"])
            .one()
        )

        member = Membership.query.filter_by(
            org_id=org.id, user_id=org.created_by.id
        ).one()

        assert org.orgname == "choco"
        assert org.name == "The Chocolate Factory"
        assert org.created_by.username == "coyote"
        assert member.is_owner is True


@pytest.mark.usefixtures("data_org")
@pytest.mark.parametrize(
    "username, expected_lst", [("coyote", [{"orgname": "acme"}]), ("YoseSam", [])]
)
def test_list_user_orgs_endpoint(client, username, expected_lst):

    token = login(username)
    url = f"/users/{username}/orgs"
    rv = client.get(url, headers={"Authorization": token})

    assert rv.status_code == 200

    returned_lst = loads(rv.data)

    assert len(expected_lst) == len(returned_lst)
    assert list_is(expected_lst) <= returned_lst


user_response_schema = generate_schema(
    User, exclude=["id", "password", "canonical_username"]
)


member_response_schema = {
    "user": {"type": "dict", "required": True, "schema": user_response_schema},
    "is_owner": {"type": "boolean", "required": True},
    "enabled": {"type": "boolean", "required": True},
}


@pytest.mark.usefixtures("data_member")
def test_list_members(client):
    token = login("coyote", "acme", scope={"org": ["read"]})

    rv = client.get("/orgs/acme/members", headers={"Authorization": token})

    assert rv.status_code == 200

    data = loads(rv.data)
    assert len(data) is 3

    v = Validator(member_response_schema)

    assert v.validate(data[0]), v.errors


@pytest.mark.usefixtures("data_org")
@pytest.mark.parametrize(
    "username, status, error",
    [
        ("unknown", 400, "User unknown does not exist"),
        ("coyote", 400, "coyote is already a member of acme"),
    ],
)
def test_add_member_with_invalid_user(client, username, status, error):
    data = {"username": username}
    token = login("coyote", "acme")

    rv = client.post(
        "/orgs/acme/members",
        data=dumps(data),
        content_type="application/json",
        headers={"Authorization": token},
    )

    body = loads(rv.data)

    assert rv.status_code == status
    assert error in body["error"]["username"]


@pytest.mark.usefixtures("data_org")
def test_add_member(client):
    data = {"username": "RoadRunner"}
    token = login("coyote", "acme")

    rv = client.post(
        "/orgs/acme/members",
        data=dumps(data),
        content_type="application/json",
        headers={"Authorization": token},
    )

    assert rv.status_code == 201

    v = Validator(member_response_schema)
    data = loads(rv.data)
    assert v.validate(data), v.errors


def test_list_plans(client):

    rv = client.get("/plans")
    rv.status_code == 200

    data = loads(rv.data)
    assert len(data) == 3


@pytest.mark.usefixtures("data")
def test_get_plan(client):

    rv = client.get("/plans/1")
    rv.status_code == 200

    data = loads(rv.data)
    assert data["id"] == 1


@pytest.mark.usefixtures("data")
def test_add_plan(client):
    token = login("coyote", scope={"app": ["write"]})
    data = {"name": "Enterprise", "amount_of_members": 500, "price": 1000}

    rv = client.post(
        "/plans",
        data=dumps(data),
        content_type="application/json",
        headers={"Authorization": token},
    )

    assert rv.status_code == 201, rv.data

    data = loads(rv.data)


def test_delete_plan(client):
    token = login("coyote", scope={"app": ["delete"]})
    url = "/plans/1"

    rv = client.delete(url, headers={"Authorization": token})

    assert rv.status_code == 200
    assert client.get(url).status_code == 404


class TestResource:
    def test_allowed_methods(self, app):
        assert_allowed_methods("/resources", ["GET"], app)
        assert_allowed_methods("/resources/1", ["GET"], app)

    def test_list_resource(self, client):
        token = login("coyote", scope={"app": "read"})
        rv = client.get("/resources", headers={"Authorization": token})

        assert rv.status_code == 200

        data = rv.get_json()

        assert len(data) > 0

    def test_get_resource(self, client):

        _id = Resource.query.first().id

        token = login("coyote", scope={"app": "read"})
        rv = client.get(f"/resources/{_id}", headers={"Authorization": token})

        assert rv.status_code == 200

        data = rv.get_json()
        assert data["id"] == _id


class TestAction:
    def test_allowed_methods(self, app):
        assert_allowed_methods("/actions", ["GET"], app)
        assert_allowed_methods("/actions/1", ["GET"], app)

    def test_list_resource(self, client):
        token = login("coyote", scope={"app": "read"})
        rv = client.get("/actions", headers={"Authorization": token})

        assert rv.status_code == 200

        data = rv.get_json()
        assert len(data) > 0

    def test_get_resource(self, client):
        _id = Action.query.first().id

        token = login("coyote", scope={"app": "read"})
        rv = client.get(f"/actions/{_id}", headers={"Authorization": token})

        assert rv.status_code == 200

        data = rv.get_json()
        assert data["id"] == _id


class TestAbility:
    def test_allowed_methods(self, app):
        assert_allowed_methods("/abilities", ["GET"], app)
        assert_allowed_methods("/abilities/1,1", ["GET"], app)

    def test_list_abilities(self, client):
        token = login("coyote", scope={"app": ["read"]})
        rv = client.get("/abilities", headers={"Authorization": token})

        assert rv.status_code == 200

        data = rv.get_json()
        assert len(data) > 0

    def test_get_ability(self, client):
        model = Ability.query.first()
        _id = f"{model.action_id},{model.resource_id}"

        token = login("coyote", scope={"app": "read"})
        rv = client.get(f"/abilities/{_id}", headers={"Authorization": token})

        assert rv.status_code == 200

        data = rv.get_json()
        assert data["action_id"] == model.action_id
        assert data["resource_id"] == model.resource_id


@pytest.mark.usefixtures("data_role")
class TestRole:
    def test_allowed_methods(self, app):
        assert_allowed_methods("/orgs/acme/roles", ["GET", "POST"], app)
        assert_allowed_methods("/orgs/acme/roles/1", ["GET", "PATCH", "DELETE"], app)

    @pytest.mark.parametrize("orgname, expected", [("acme", 3), ("rrinc", 4)])
    def test_list_roles(self, client, orgname, expected):
        token = login("coyote", orgname, scope={"org": ["manage"]})
        rv = client.get(f"/orgs/{orgname}/roles", headers={"Authorization": token})
        data = rv.get_json()

        assert rv.status_code == 200
        assert len(data) == expected

    @pytest.mark.parametrize(
        "orgname, id, expected",
        [("acme", 5, 404), ("acme", 1, 200)],
        ids=["from another organization", "own role"],
    )
    def test_get_role(self, client, orgname, id, expected):
        token = login("coyote", orgname, scope={"org": ["manage"]})
        rv = client.get(f"/orgs/{orgname}/roles/{id}", headers={"Authorization": token})

        assert rv.status_code == expected

    def test_add_role_with_invalid_payload(self, client):
        token = login("coyote", "acme", scope={"org": ["manage"]})
        data = dumps({"name": "New Role", "description": "...", "org_id": 4})
        rv = client.post(
            f"/orgs/acme/roles",
            headers={"Authorization": token},
            data=data,
            content_type="application/json",
        )
        data = rv.get_json()

        assert rv.status_code == 400
        assert "unknown field" in data["error"]["org_id"]

    def test_add_role_without_abilities(self, client):
        token = login("coyote", "acme", scope={"org": ["manage"]})
        data = dumps({"name": "New Role", "description": "..."})
        rv = client.post(
            f"/orgs/acme/roles",
            headers={"Authorization": token},
            data=data,
            content_type="application/json",
        )
        data = rv.get_json()

        assert rv.status_code == 201
        assert "org_id" not in data
        assert "id" in data
        assert data["name"] == "New Role"
        assert data["description"] == "..."

    def test_add_role_with_abilities(self, client):
        token = login("coyote", "acme", scope={"org": ["manage"]})
        data = dumps(
            {
                "name": "New Role",
                "description": "...",
                "abilities": [
                    {"action_id": 1, "resource_id": 1},
                    {"action_id": 2, "resource_id": 1},
                ],
            }
        )
        rv = client.post(
            f"/orgs/acme/roles",
            headers={"Authorization": token},
            data=data,
            content_type="application/json",
        )
        data = rv.get_json()

        assert rv.status_code == 201, rv.data
        assert "org_id" not in data
        assert "id" in data
        assert data["name"] == "New Role"
        assert data["description"] == "..."
        assert len(data["abilities"]) == 2

    def test_update_role_from_another_organization(self, client):
        token = login("coyote", "acme", scope={"org": ["manage"]})
        req_payload = {"name": "Updated Role 5", "description": "New description"}
        rv = client.patch(
            f"/orgs/acme/roles/5",
            headers={"Authorization": token},
            data=dumps(req_payload),
            content_type="application/json",
        )

        assert rv.status_code == 404

    def test_update_role_with_invalid_payload(self, client):
        token = login("coyote", "acme", scope={"org": ["manage"]})
        req_payload = {"org_id": 2}
        rv = client.patch(
            f"/orgs/acme/roles/1",
            headers={"Authorization": token},
            data=dumps(req_payload),
            content_type="application/json",
        )
        data = rv.get_json()

        assert rv.status_code == 400
        assert "unknown field" in data["error"]["org_id"]

    def test_update_role_without_abilities(self, client):
        token = login("coyote", "acme", scope={"org": ["manage"]})
        req_payload = {"name": "Updated Role 1", "description": "New description"}
        rv = client.patch(
            f"/orgs/acme/roles/1",
            headers={"Authorization": token},
            data=dumps(req_payload),
            content_type="application/json",
        )
        data = rv.get_json()

        assert rv.status_code == 200
        assert data["name"] == req_payload["name"]
        assert data["description"] == req_payload["description"]

    def test_update_role_with_abilities(self, client):

        token = login("coyote", "acme", scope={"org": ["manage"]})
        data = dumps(
            {
                "name": "New Role",
                "description": "...",
                "abilities": [
                    {"action_id": 1, "resource_id": 1},
                    {"action_id": 1, "resource_id": 2},
                ],
            }
        )
        rv = client.post(
            "/orgs/acme/roles",
            headers={"Authorization": token},
            data=data,
            content_type="application/json",
        )
        data = rv.get_json()

        assert rv.status_code == 201

        _id = data["id"]

        data = dumps(
            {
                "name": "Updated Role",
                "abilities": [
                    {"action_id": 1, "resource_id": 1},
                    {"action_id": 1, "resource_id": 3},
                ],
            }
        )
        rv = client.patch(
            f"/orgs/acme/roles/{_id}",
            headers={"Authorization": token},
            data=data,
            content_type="application/json",
        )
        data = rv.get_json()

        assert rv.status_code == 200

    @pytest.mark.parametrize(
        "id, expected",
        [(1, 200), (5, 404)],
        ids=["own role", "from another organization"],
    )
    def test_delete_role(self, client, id, expected):
        token = login("coyote", "acme", scope={"org": ["manage"]})

        rv = client.delete(f"/orgs/acme/roles/{id}", headers={"Authorization": token})
        assert rv.status_code == expected

        rv = client.get(f"/orgs/acme/roles/{id}", headers={"Authorization": token})
        assert rv.status_code == 404


@pytest.mark.usefixtures("data_member_role")
class TestMemberRole:
    def test_list_member_roles(self, client):
        token = login("coyote", "acme", scope={"org": ["manage"]})
        rv = client.get(
            "/orgs/acme/members/yosesam/roles", headers={"Authorization": token}
        )
        data = rv.get_json()

        assert rv.status_code == 200
        assert len(data) > 0

        role = data[0]
        data = rv.get_json()
        assert "name" in role
        assert "abilities" in role

    @pytest.mark.parametrize(
        "orgname, username, id, expected",
        [
            ("acme", "yosesam", 2, 200),
            ("acme", "yosesam", 1, 404),
            ("rrinc", "yosesam", 4, 404),
            ("rrinc", "yosesam", 6, 200),
        ],
    )
    def test_get_member_roles(self, client, orgname, username, id, expected):
        token = login(username, orgname, scope={"org": ["manage"]})
        rv = client.get(
            f"/orgs/{orgname}/members/{username}/roles/{id}",
            headers={"Authorization": token},
        )

        assert rv.status_code == expected

    def test_get_member_roles_repsonse_payload(self, client):
        token = login("yosesam", "acme", scope={"org": ["manage"]})
        rv = client.get(
            f"/orgs/acme/members/yosesam/roles/2", headers={"Authorization": token}
        )

        assert rv.status_code == 200

    def test_add_role_to_member(self, client):
        token = login("coyote", "acme", scope={"org": ["manage"]})
        rv = client.post(
            "/orgs/acme/members/yosesam/roles",
            headers={"Authorization": token},
            content_type="application/json",
            data=dumps({"roles": [1, 3]}),
        )

        assert rv.status_code == 201

    def test_delete_role_from_member(self, client):
        token = login("coyote", "acme", scope={"org": ["manage"]})
        rv = client.delete(
            "/orgs/acme/members/yosesam/roles/2", headers={"Authorization": token}
        )
        assert rv.status_code == 200

        rv = client.get(
            "/orgs/acme/members/yosesam/roles/2", headers={"Authorization": token}
        )
        assert rv.status_code == 404
