import pytest
from flask import Flask
from flask.json import dumps
from common import Product, OrderLine, Cartoon, Todo, login

from saraki.endpoints import add_resource
from saraki.model import database, Org
from saraki.testing import get_view_function, assert_allowed_methods


class Test_add_resource:
    def test_basic_usage(self):
        app = Flask(__name__)
        add_resource(Cartoon, app)

        assert_allowed_methods("/cartoon", ["GET", "POST"], app)
        assert_allowed_methods("/cartoon/1", ["GET", "DELETE", "PATCH"], app)

    def test_custom_base_url(self):
        app = Flask(__name__)
        add_resource(Cartoon, app, "animations")

        assert_allowed_methods("/animations", ["GET", "POST"], app)
        assert_allowed_methods("/animations/1", ["GET", "DELETE", "PATCH"], app)

    def test_resource_with_composite_ident(self):
        app = Flask(__name__)
        add_resource(OrderLine, app)

        assert_allowed_methods("/order-line", ["GET", "POST"], app)
        assert_allowed_methods("/order-line/3,14", ["GET", "DELETE", "PATCH"], app)

    def test_resource_with_custom_ident(self):
        app = Flask(__name__)
        add_resource(Cartoon, app, ident="nickname")

        assert_allowed_methods("/cartoon", ["GET", "POST"], app)
        assert_allowed_methods("/cartoon/coyote", ["GET", "DELETE", "PATCH"], app)

    def test_exclude_http_methods(self):
        app = Flask(__name__)
        add_resource(Cartoon, app, methods={"list": ["GET"], "item": ["GET", "PATCH"]})

        assert_allowed_methods("/cartoon", ["GET"], app)
        assert_allowed_methods("/cartoon/1", ["GET", "PATCH"], app)

    def test_endpoint_name(self):
        app = Flask(__name__)
        add_resource(Cartoon, app)
        adapter = app.url_map.bind("")

        list_endpoint = adapter.match("/cartoon")
        add_endpoint = adapter.match("/cartoon", method="POST")
        get_endpoint = adapter.match("/cartoon/1")
        update_endpoint = adapter.match("/cartoon/1", method="PATCH")
        delete_endpoint = adapter.match("/cartoon/1", method="DELETE")

        assert list_endpoint[0] == "list_cartoon"
        assert add_endpoint[0] == "add_cartoon"
        assert get_endpoint[0] == "get_cartoon"
        assert update_endpoint[0] == "update_cartoon"
        assert delete_endpoint[0] == "delete_cartoon"

    def test_custom_resource_name(self):
        app = Flask(__name__)

        add_resource(Cartoon, app, resource_name="film")

        func = get_view_function("/cartoon", app=app)[0]
        assert func._auth_metadata["resource"] == "film"

        func = get_view_function("/cartoon", method="POST", app=app)[0]
        assert func._auth_metadata["resource"] == "film"

        func = get_view_function("/cartoon/1", method="PATCH", app=app)[0]
        assert func._auth_metadata["resource"] == "film"

        func = get_view_function("/cartoon/1", method="DELETE", app=app)[0]
        assert func._auth_metadata["resource"] == "film"

    def test_endpoint_with_same_resource_name(self):
        app = Flask(__name__)

        add_resource(Cartoon, app, resource_name="catalog")
        add_resource(Product, app, resource_name="catalog")

    def test_add_organization_resource(self, app):
        add_resource(Todo, app, "todos")

        assert_allowed_methods("/orgs/acme/todos", ["GET", "POST"], app)
        assert_allowed_methods("/orgs/acme/todos/1", ["GET", "DELETE", "PATCH"], app)


@pytest.mark.usefixtures("data")
class TestResourceList:
    def test_list_endpoint(self, app, client):

        add_resource(Cartoon, app, secure=False)

        rv = client.get("/cartoon")

        assert rv.status_code == 200

        data = rv.get_json()
        assert len(data) == 3


@pytest.mark.usefixtures("data")
class TestGetResourceItem:
    def test_unknown_resource(self, app, client):
        add_resource(Cartoon, app, "cartoons", secure=False)

        rv = client.get("/cartoons/100")
        assert rv.status_code == 404

    def test_get_resource(self, app, client):
        add_resource(Cartoon, app, secure=False)

        rv = client.get("/cartoon/1")
        assert rv.status_code == 200

    def test_resource_with_composite_ident(self, app, client):
        add_resource(OrderLine, app, secure=False)

        rv = client.get("/order-line/1,2")

        assert rv.status_code == 200

        data = rv.get_json()
        assert data["product_id"] == 2

    def test_resource_with_custom_ident(self, app, client):
        add_resource(Cartoon, app, ident="nickname", secure=False)

        rv = client.get("/cartoon/bugs")
        assert rv.status_code == 200

    def test_unknown_resource_with_custom_ident(self, app, client):
        add_resource(Cartoon, app, ident="nickname", secure=False)

        rv = client.get("/cartoon/unknown")
        assert rv.status_code == 404


@pytest.mark.usefixtures("data")
class TestAddResourceItem:
    def test_add_item_endpoint(self, client, app, secure=False):
        add_resource(Cartoon, app, secure=False)

        rv = client.post(
            "/cartoon",
            data=dumps({"name": "Yosemite Sam"}),
            content_type="application/json",
        )
        assert rv.status_code == 201

        data = rv.get_json()
        assert data["name"] == "Yosemite Sam"

    def test_with_invalid_payload(self, app, client):
        add_resource(Cartoon, app, secure=False)

        rv = client.post(
            "/cartoon",
            data=dumps({"unknown": "value"}),
            content_type="application/json",
        )

        assert rv.status_code == 400


@pytest.mark.usefixtures("data")
class TestUpdateResourceItem:
    def test_unknown_resource(self, app, client):
        add_resource(Cartoon, app, "cartoons", secure=False)

        rv = client.patch("/cartoons/100")
        assert rv.status_code == 404

    def test_update(self, app, client):
        add_resource(Cartoon, app, secure=False)

        rv = client.patch(
            "/cartoon/1",
            data=dumps({"name": "Super H."}),
            content_type="application/json",
        )

        data = rv.get_json()

        assert rv.status_code == 200
        assert data["name"] == "Super H."

        rv = client.get("/cartoon/1")
        data = rv.get_json()

        assert rv.status_code == 200
        assert data["name"] == "Super H."

    def test_invalid_payload(self, app, client):
        add_resource(Cartoon, app, secure=False)

        rv = client.patch(
            "/cartoon/1",
            data=dumps({"unknown": "Fried chicken"}),
            content_type="application/json",
        )

        assert rv.status_code == 400


@pytest.mark.usefixtures("data")
class TestDeleteResourceItem:
    def test_unknown_resource(self, app, client):
        add_resource(Cartoon, app, "cartoons", secure=False)

        rv = client.delete("/cartoons/100")
        assert rv.status_code == 404

    def test_delete(self, app, client):
        add_resource(Cartoon, app, "cartoons", secure=False)

        rv = client.delete("/cartoons/1")
        assert rv.status_code == 200

        rv = client.get("/cartoons/1")
        assert rv.status_code == 404


@pytest.mark.usefixtures("data")
class TestResourceAuthorization:
    def test_get_resource_list(self, app, client):
        add_resource(Cartoon, app)
        token = login("coy0te", scope={"cartoon": ["read"]})

        rv = client.get("/cartoon", headers={"Authorization": token})
        assert rv.status_code != 401

    def test_get_resource_item(self, app, client):
        add_resource(Cartoon, app)
        token = login("coy0te", scope={"cartoon": ["read"]})

        rv = client.get("/cartoon/1", headers={"Authorization": token})
        assert rv.status_code != 401

    def test_add_resource_item(self, app, client):
        add_resource(Cartoon, app)
        token = login("coy0te", scope={"cartoon": ["write"]})

        rv = client.post("/cartoon", headers={"Authorization": token})
        assert rv.status_code != 401

    def test_update_resource_item(self, app, client):
        add_resource(Cartoon, app)
        token = login("coy0te", scope={"cartoon": ["write"]})

        rv = client.post("/cartoon", headers={"Authorization": token})
        assert rv.status_code != 401

    def test_delete_resource_item(self, app, client):
        add_resource(Cartoon, app)
        token = login("coy0te", scope={"cartoon": ["delete"]})

        rv = client.delete("/cartoon", headers={"Authorization": token})
        assert rv.status_code != 401


@pytest.mark.usefixtures("data", "data_org")
class TestOrgResource:
    def insert_data(self):
        org_id = Org.query.filter_by(orgname="acme").one().id

        todo = Todo(task="Stop being lazy", org_id=org_id)
        database.session.add(todo)
        database.session.commit()

        return todo

    def test_list_resource(self, app, client):
        _id = self.insert_data().id
        add_resource(Todo, app)

        # Request to Acme endpoint
        token = login("coy0te", "acme", scope={"todo": ["read"]})
        rv = client.get(f"/orgs/acme/todo", headers={"Authorization": token})
        data = rv.get_json()

        assert rv.status_code == 200
        assert data[0]["id"] == _id

        # Request to R.R. Inc endpoint
        token = login("R0adRunner", "rrinc", scope={"todo": ["read"]})
        rv = client.get(f"/orgs/rrinc/todo", headers={"Authorization": token})
        data = rv.get_json()

        assert rv.status_code == 200
        assert len(data) == 0

    def test_get_resource(self, app, client):
        _id = self.insert_data().id
        add_resource(Todo, app)

        # Request to R.R. Inc endpoint
        token = login("R0adRunner", "rrinc", scope={"todo": ["read"]})
        rv = client.get(f"/orgs/rrinc/todo/{_id}", headers={"Authorization": token})

        assert rv.status_code == 404, (
            f"The status code should be 404 because the model id ({_id})"
            " used in the URL belongs to another organization account."
        )

        # Request to Acme endpoint
        token = login("coy0te", "acme", scope={"todo": ["read"]})
        rv = client.get(f"/orgs/acme/todo/{_id}", headers={"Authorization": token})
        data = rv.get_json()

        assert rv.status_code == 200
        assert data["id"] == _id
        assert data["task"] == "Stop being lazy"

    def test_add_resource(self, app, client):
        add_resource(Todo, app)

        token = login("coy0te", "acme", scope={"todo": ["write"]})

        rv = client.post(
            "/orgs/acme/todo",
            data=dumps({"task": "Do something"}),
            content_type="application/json",
            headers={"Authorization": token},
        )

        assert rv.status_code == 201

        data = rv.get_json()
        org = Org.query.filter_by(orgname="acme").one()
        todo = Todo.query.get(data["id"])

        assert org.id == todo.org_id

    def test_update_resource(self, app, client):
        _id = self.insert_data().id
        add_resource(Todo, app)

        # Request to R.R. Inc endpoint with the same id
        token = login("R0adRunner", "rrinc", scope={"todo": ["write"]})
        rv = client.patch(
            f"/orgs/rrinc/todo/{_id}",
            data=dumps({"task": "Do something"}),
            content_type="application/json",
            headers={"Authorization": token},
        )
        assert rv.status_code == 404, (
            f"The status code should be 404 because the model id ({_id})"
            " used in the URL belongs to another organization account."
        )

        # Request to Acme endpoint
        token = login("coy0te", "acme", scope={"todo": ["write"]})
        rv = client.patch(
            f"/orgs/acme/todo/{_id}",
            data=dumps({"task": "Do something"}),
            content_type="application/json",
            headers={"Authorization": token},
        )

        assert rv.status_code == 200

        todo = Todo.query.filter_by(id=_id).one()
        assert todo.task == "Do something"

    def test_delete_resource(self, app, client):
        _id = self.insert_data().id
        add_resource(Todo, app)

        # Request to R.R. Inc.
        token = login("R0adRunner", "rrinc", scope={"todo": ["delete"]})
        headers = {"Authorization": token}
        rv = client.delete(f"/orgs/rrinc/todo/{_id}", headers=headers)

        assert rv.status_code == 404, (
            f"The status code should be 404 because the model id ({_id})"
            " used in the URL belongs to another organization account."
        )

        # Request to Acme
        token = login("coy0te", "acme", scope={"todo": ["delete"]})
        headers = {"Authorization": token}
        rv = client.delete(f"/orgs/acme/todo/{_id}", headers=headers)

        assert rv.status_code == 200
        assert Todo.query.get(_id) is None
