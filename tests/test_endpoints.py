import pytest
from unittest.mock import MagicMock, patch, call
from flask import Flask, request
from flask.json import dumps
from sqlalchemy import Column, Integer
from sqlalchemy.sql.expression import or_
from sqlalchemy import func, Text

from saraki.auth import current_org
from saraki.endpoints import add_resource, collection
from saraki.model import database, Org, Model
from saraki.exc import ValidationError
from saraki.testing import get_view_function, assert_allowed_methods

from common import Person, Product, OrderLine, Cartoon, Todo, login, auth_ctx


class Test_add_resource:
    def test_basic_usage(self):
        app = Flask(__name__)
        add_resource(app, Cartoon)

        assert_allowed_methods("/cartoon", ["GET", "POST"], app)
        assert_allowed_methods("/cartoon/1", ["GET", "DELETE", "PATCH"], app)

    def test_custom_base_url(self):
        app = Flask(__name__)
        add_resource(app, Cartoon, "animations")

        assert_allowed_methods("/animations", ["GET", "POST"], app)
        assert_allowed_methods("/animations/1", ["GET", "DELETE", "PATCH"], app)

    def test_resource_with_composite_ident(self):
        app = Flask(__name__)
        add_resource(app, OrderLine)

        assert_allowed_methods("/order-line", ["GET", "POST"], app)
        assert_allowed_methods("/order-line/3,14", ["GET", "DELETE", "PATCH"], app)

    def test_resource_with_custom_ident(self):
        app = Flask(__name__)
        add_resource(app, Cartoon, ident="nickname")

        assert_allowed_methods("/cartoon", ["GET", "POST"], app)
        assert_allowed_methods("/cartoon/coyote", ["GET", "DELETE", "PATCH"], app)

    def test_exclude_http_methods(self):
        app = Flask(__name__)
        add_resource(app, Cartoon, methods={"list": ["GET"], "item": ["GET", "PATCH"]})

        assert_allowed_methods("/cartoon", ["GET"], app)
        assert_allowed_methods("/cartoon/1", ["GET", "PATCH"], app)

    def test_endpoint_name(self):
        app = Flask(__name__)
        add_resource(app, Cartoon)
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

        add_resource(app, Cartoon, resource_name="film")

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

        add_resource(app, Cartoon, resource_name="catalog")
        add_resource(app, Product, resource_name="catalog")

    def test_add_organization_resource(self, app):
        add_resource(app, Todo, "todos")

        assert_allowed_methods("/orgs/acme/todos", ["GET", "POST"], app)
        assert_allowed_methods("/orgs/acme/todos/1", ["GET", "DELETE", "PATCH"], app)


@pytest.mark.usefixtures("data")
class TestResourceList:
    def test_list_endpoint(self, app, client):

        add_resource(app, Cartoon, secure=False)

        rv = client.get("/cartoon")

        assert rv.status_code == 200

        data = rv.get_json()
        assert len(data) == 3


@pytest.mark.usefixtures("data")
class TestGetResourceItem:
    def test_unknown_resource(self, app, client):
        add_resource(app, Cartoon, "cartoons", secure=False)

        rv = client.get("/cartoons/100")
        assert rv.status_code == 404

    def test_get_resource(self, app, client):
        add_resource(app, Cartoon, secure=False)

        rv = client.get("/cartoon/1")
        assert rv.status_code == 200

    def test_resource_with_composite_ident(self, app, client):
        add_resource(app, OrderLine, secure=False)

        rv = client.get("/order-line/1,2")

        assert rv.status_code == 200

        data = rv.get_json()
        assert data["product_id"] == 2

    def test_resource_with_custom_ident(self, app, client):
        add_resource(app, Cartoon, ident="nickname", secure=False)

        rv = client.get("/cartoon/bugs")
        assert rv.status_code == 200

    def test_unknown_resource_with_custom_ident(self, app, client):
        add_resource(app, Cartoon, ident="nickname", secure=False)

        rv = client.get("/cartoon/unknown")
        assert rv.status_code == 404


@pytest.mark.usefixtures("data")
class TestAddResourceItem:
    def test_add_item_endpoint(self, client, app, secure=False):
        add_resource(app, Cartoon, secure=False)

        rv = client.post(
            "/cartoon",
            data=dumps({"name": "Yosemite Sam"}),
            content_type="application/json",
        )
        assert rv.status_code == 201

        data = rv.get_json()
        assert data["name"] == "Yosemite Sam"

    def test_with_invalid_payload(self, app, client):
        add_resource(app, Cartoon, secure=False)

        rv = client.post(
            "/cartoon",
            data=dumps({"unknown": "value"}),
            content_type="application/json",
        )

        assert rv.status_code == 400


@pytest.mark.usefixtures("data")
class TestUpdateResourceItem:
    def test_unknown_resource(self, app, client):
        add_resource(app, Cartoon, "cartoons", secure=False)

        rv = client.patch("/cartoons/100")
        assert rv.status_code == 404

    def test_update(self, app, client):
        add_resource(app, Cartoon, secure=False)

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
        add_resource(app, Cartoon, secure=False)

        rv = client.patch(
            "/cartoon/1",
            data=dumps({"unknown": "Fried chicken"}),
            content_type="application/json",
        )

        assert rv.status_code == 400


@pytest.mark.usefixtures("data")
class TestDeleteResourceItem:
    def test_unknown_resource(self, app, client):
        add_resource(app, Cartoon, "cartoons", secure=False)

        rv = client.delete("/cartoons/100")
        assert rv.status_code == 404

    def test_delete(self, app, client):
        add_resource(app, Cartoon, "cartoons", secure=False)

        rv = client.delete("/cartoons/1")
        assert rv.status_code == 200

        rv = client.get("/cartoons/1")
        assert rv.status_code == 404


@pytest.mark.usefixtures("data")
class TestResourceAuthorization:
    def test_get_resource_list(self, app, client):
        add_resource(app, Cartoon)
        token = login("coyote", scope={"cartoon": ["read"]})

        rv = client.get("/cartoon", headers={"Authorization": token})
        assert rv.status_code != 401

    def test_get_resource_item(self, app, client):
        add_resource(app, Cartoon)
        token = login("coyote", scope={"cartoon": ["read"]})

        rv = client.get("/cartoon/1", headers={"Authorization": token})
        assert rv.status_code != 401

    def test_add_resource_item(self, app, client):
        add_resource(app, Cartoon)
        token = login("coyote", scope={"cartoon": ["write"]})

        rv = client.post("/cartoon", headers={"Authorization": token})
        assert rv.status_code != 401

    def test_update_resource_item(self, app, client):
        add_resource(app, Cartoon)
        token = login("coyote", scope={"cartoon": ["write"]})

        rv = client.post("/cartoon", headers={"Authorization": token})
        assert rv.status_code != 401

    def test_delete_resource_item(self, app, client):
        add_resource(app, Cartoon)
        token = login("coyote", scope={"cartoon": ["delete"]})

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
        add_resource(app, Todo)

        # Request to Acme endpoint
        token = login("coyote", "acme", scope={"todo": ["read"]})
        rv = client.get(f"/orgs/acme/todo", headers={"Authorization": token})
        data = rv.get_json()

        assert rv.status_code == 200
        assert data[0]["id"] == _id
        assert "org_id" not in data[0]

        # Request to R.R. Inc endpoint
        token = login("RoadRunner", "rrinc", scope={"todo": ["read"]})
        rv = client.get(f"/orgs/rrinc/todo", headers={"Authorization": token})
        data = rv.get_json()

        assert rv.status_code == 200
        assert len(data) == 0

    def test_get_resource(self, app, client):
        _id = self.insert_data().id
        add_resource(app, Todo)

        # Request to R.R. Inc endpoint
        token = login("RoadRunner", "rrinc", scope={"todo": ["read"]})
        rv = client.get(f"/orgs/rrinc/todo/{_id}", headers={"Authorization": token})

        assert rv.status_code == 404, (
            f"The status code should be 404 because the model id ({_id})"
            " used in the URL belongs to another organization account."
        )

        # Request to Acme endpoint
        token = login("coyote", "acme", scope={"todo": ["read"]})
        rv = client.get(f"/orgs/acme/todo/{_id}", headers={"Authorization": token})
        data = rv.get_json()

        assert rv.status_code == 200
        assert data["id"] == _id
        assert data["task"] == "Stop being lazy"
        assert "org_id" not in data

    def test_add_resource(self, app, client):
        add_resource(app, Todo)

        token = login("coyote", "acme", scope={"todo": ["write"]})

        rv = client.post(
            "/orgs/acme/todo",
            data=dumps({"task": "Do something"}),
            content_type="application/json",
            headers={"Authorization": token},
        )
        data = rv.get_json()

        assert rv.status_code == 201
        assert "org_id" not in data

        org = Org.query.filter_by(orgname="acme").one()
        todo = Todo.query.get(data["id"])

        assert org.id == todo.org_id

    def test_update_resource(self, app, client):
        _id = self.insert_data().id
        add_resource(app, Todo)

        # Request to R.R. Inc endpoint with the same id
        token = login("RoadRunner", "rrinc", scope={"todo": ["write"]})
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
        token = login("coyote", "acme", scope={"todo": ["write"]})
        rv = client.patch(
            f"/orgs/acme/todo/{_id}",
            data=dumps({"task": "Do something"}),
            content_type="application/json",
            headers={"Authorization": token},
        )
        data = rv.get_json()

        assert rv.status_code == 200
        assert "org_id" not in data

        todo = Todo.query.filter_by(id=_id).one()
        assert todo.task == "Do something"

    def test_delete_resource(self, app, client):
        _id = self.insert_data().id
        add_resource(app, Todo)

        # Request to R.R. Inc.
        token = login("RoadRunner", "rrinc", scope={"todo": ["delete"]})
        headers = {"Authorization": token}
        rv = client.delete(f"/orgs/rrinc/todo/{_id}", headers=headers)

        assert rv.status_code == 404, (
            f"The status code should be 404 because the model id ({_id})"
            " used in the URL belongs to another organization account."
        )

        # Request to Acme
        token = login("coyote", "acme", scope={"todo": ["delete"]})
        headers = {"Authorization": token}
        rv = client.delete(f"/orgs/acme/todo/{_id}", headers=headers)

        assert rv.status_code == 200
        assert Todo.query.get(_id) is None


def mock_query():
    query = MagicMock(
        name="Query", spec=["filter", "filter_by", "order_by", "paginate"]
    )
    query.filter_by = MagicMock(return_value=query)
    query.order_by = MagicMock(return_value=query)
    query.filter = MagicMock(return_value=query)

    result = MagicMock(name="result")
    result.items = []

    query.paginate = MagicMock(return_value=result)

    return query


@pytest.mark.usefixtures("database_conn", "ctx")
class TestCollection:
    @pytest.mark.parametrize(
        "key, value, expected",
        [
            (
                "search",
                '{"t": "term", "f": ["name", "color"]}',
                {"t": "term", "f": ["name", "color"]},
            ),
            ("filter", '{"color": "blue", "price": 2}', {"color": "blue", "price": 2}),
            ("select", '{"id": 1, "name": 1}', {"id": 1, "name": 1}),
            ("limit", "50", 50),
            ("page", "3", 3),
        ],
    )
    def test_parse_query_string(self, request_ctx, key, value, expected):
        with request_ctx(f"/?{key}={value}"):
            output = collection._parse_query_string(Product, request.args)

        assert output[key] == expected

    @pytest.mark.parametrize(
        "qs",
        [
            'filter={"unknown": "value", "price": 20}',
            'filter={"unknown": "value", "price": "text"}',
            "filter={name: tnt, enabled: True}",
            'select={"unknown": 1, "name": 1}',
            'select={"id": "text", "name": 1}',
            "select={id: 1, name: 1}",
            "limit=text",
            "page=text",
        ],
        ids=[
            "filter: with unknown column",
            "filter: with invalid value type",
            "filter: invalid JSON string",
            "select: with unknown column",
            "select: with non integer value",
            "select: invalid JSON string",
            "limit : non integer value",
            "page  : non integer value",
        ],
    )
    def test_invalid_modifier(self, request_ctx, qs):
        with request_ctx(f"/?{qs}"):
            with pytest.raises(ValidationError):
                collection()(lambda: Product)()

    def test_unknown_modifier(self, request_ctx):
        with request_ctx("/?unknown=value"):
            with pytest.raises(ValidationError):
                collection()(lambda: Product)()

    @pytest.mark.parametrize(
        "param, expected",
        [
            ({"name": 1, "color": 1}, {"include": ["name", "color"]}),
            ({"name": 1, "color": 0}, {"include": ["name"], "exclude": ["color"]}),
            ({"name": 0, "color": 0}, {"exclude": ["name", "color"]}),
        ],
    )
    @patch.object(Product, "query")
    def test_parse_select_modifier(self, query, request_ctx, param, expected):
        params = collection._parse_select_modifier(param)

        assert params == expected

    @patch.object(Product, "query", new=mock_query())
    def test_filter_modifier(self, request_ctx):

        with request_ctx('/?filter={"name": "tnt", "enabled": true}'):
            collection()(lambda: Product)()

        Product.query.filter_by.assert_called_with(**{"name": "tnt", "enabled": True})

    @patch.object(Product, "query", new=mock_query())
    def test_search_modifier(self, request_ctx):

        with request_ctx('/?search={"t": "black", "f": ["name", "color"]}'):
            collection()(lambda: Product)()

        Product.query.filter.assert_called()

        expected = or_(Product.name.ilike("%black%"), Product.color.ilike("%black%"))
        original = Product.query.filter.call_args[0][0]

        assert original.compare(expected)

    @patch.object(Product, "query", new=mock_query())
    def test_search_modifier_on_non_text_column(self, request_ctx):

        with request_ctx('/?search={"t": "black", "f": ["price", "color"]}'):
            collection()(lambda: Product)()

        Product.query.filter.assert_called()

        expected = or_(
            func.cast(Product.price, Text).ilike("%black%"),
            Product.color.ilike("%black%"),
        )
        original = Product.query.filter.call_args[0][0]

        # clauseelement.compare() is not implemented for cast()
        # so use string comparison instead
        assert str(original) == str(expected)

    @patch.object(Product, "query", new=mock_query())
    def test_sort_modifier_with_single_field(self, request_ctx):
        with request_ctx("/?sort=name"):
            collection()(lambda: Product)()

        Product.query.order_by.assert_called()

        expected = Product.name.asc()
        original = Product.query.order_by.call_args[0][0]
        assert original.compare(expected)

    @patch.object(Product, "query", new=mock_query())
    def test_sort_modifier_with_multiple_fields(self, request_ctx):
        with request_ctx("/?sort=name,color"):
            collection()(lambda: Product)()

        Product.query.order_by.assert_called()

        expected = Product.name.asc()
        original = Product.query.order_by.call_args[0][0]
        assert original.compare(expected)

        expected = Product.color.asc()
        original = Product.query.order_by.call_args[0][1]
        assert original.compare(expected)

    @patch.object(Product, "query", new=mock_query())
    def test_sort_modifier_with_descending_order(self, request_ctx):
        with request_ctx("/?sort=-name"):
            collection()(lambda: Product)()

        Product.query.order_by.assert_called()

        expected = Product.name.desc()
        original = Product.query.order_by.call_args[0][0]
        assert original.compare(expected)

    # fmt: off
    @pytest.mark.parametrize(
        "query_string, expected",
        [
            ("", (1, 30)),
            ("limit=50", (1, 50)),
            ("limit=200", (1, 100))
        ],
        ids=[
            "default limit",
            "custom limit",
            "default max limit"
        ],
    )
    @patch.object(Product, "query", new=mock_query())
    def test_limit_modifier(self, request_ctx, query_string, expected):
        # The mock is created just one time, so reset it
        Product.query.paginate.reset_mock()

        with request_ctx(f"/?{query_string}"):
            collection()(lambda: Product)()

        Product.query.paginate.assert_called_with(*expected)
    # fmt: on

    @patch.object(Product, "query", new=mock_query())
    def test_page_modifier(self, request_ctx):
        with request_ctx("/?page=50"):
            collection()(lambda: Product)()

        Product.query.paginate.assert_called_with(50, 30)

    @patch.object(Product, "query", new=mock_query())
    def test_select_modifier(self, request_ctx):
        item = MagicMock()
        Product.query.paginate().items = [item]

        with request_ctx('/?select={"id": 1}'):
            collection()(lambda: Product)()

        item.export_data.assert_called_with(["id"], ())

    @patch.object(Product, "query")
    def test_returned_value(self, query, request_ctx):
        item = MagicMock()
        item.export_data.return_value = {"id": 300}

        query.paginate().items = [item]
        query.paginate().total = 1

        with request_ctx('/?select={"id": 1}&page=3'):
            rv = collection()(lambda: Product)()

        assert rv[0] == [{"id": 300}]
        assert rv[1] == {"X-Total": 1, "X-Page": 3}

    @patch.object(Product, "query")
    def test_model_class_without_export_data_method(self, query, request_ctx):
        item = Product(id=4, name="Acme explosive tennis balls")

        query.paginate().items = [item]
        query.paginate().total = 1

        with request_ctx('/?select={"id": 1}&page=3'):
            rv = collection()(lambda: Product)()

        assert rv[0] == [{"id": 4}]
        assert rv[1] == {"X-Total": 1, "X-Page": 3}

    @patch.object(Person, "query")
    def test_model_class_with_export_data_method(self, query, request_ctx):
        item = Person(id=300, firstname="John", lastname="Connor")

        query.paginate().items = [item]
        query.paginate().total = 1

        with request_ctx('/?select={"firstname": 1}&page=3'):
            rv = collection()(lambda: Person)()

        assert rv[0] == [{"firstname": "John"}]
        assert rv[1] == {"X-Total": 1, "X-Page": 3}

    def test_model_class_export_data_with_exception(self, request_ctx):
        class TestTable(Model):
            id = Column(Integer, primary_key=True)

            def export_data(self, *args, **kargs):
                raise AttributeError("Inside of export_data method")

        TestTable.query = MagicMock()
        TestTable.query.paginate().items = [TestTable(id=1)]

        with request_ctx("/"):
            with pytest.raises(AttributeError, match="Inside of export_data method"):
                collection()(lambda: TestTable)()

    @patch.object(Todo, "query", new=mock_query())
    def test_basic_request_with_org_model(self, app):

        with app.test_request_context("/"):
            with auth_ctx("coyote", "acme"):
                current_org_id = current_org.id
                collection()(lambda: Todo)()

        Todo.query.filter_by.assert_called_with(org_id=current_org_id)

    @patch.object(Todo, "query", new=mock_query())
    def test_filter_modifier_with_org_model(self, request_ctx):

        with request_ctx('/?filter={"task": "Do something"}'):
            with auth_ctx("coyote", "acme"):
                current_org_id = current_org.id
                collection()(lambda: Todo)()

        Todo.query.filter_by.assert_called_with(
            org_id=current_org_id, task="Do something"
        )

    @patch.object(Todo, "query", new=mock_query())
    def test_search_modifier_with_org_model(self, request_ctx):

        with request_ctx('/?search={"t": "black", "f": ["task"]}'):
            with auth_ctx("coyote", "acme"):
                current_org_id = current_org.id
                collection()(lambda: Todo)()

        Todo.query.filter_by.assert_called_with(org_id=current_org_id)
        Todo.query.filter.assert_called()

        expected = or_(Todo.task.ilike("%black%"))
        original = Todo.query.filter.call_args[0][0]
        assert original.compare(expected)

        # The query should be filtered by the organization id first
        assert Todo.query.method_calls[0] == call.filter_by(org_id=current_org_id)
