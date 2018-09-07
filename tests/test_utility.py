import pytest
from json import loads
from sqlalchemy.orm import joinedload
from werkzeug.exceptions import UnsupportedMediaType, BadRequest
from flask import make_response
from common import Product, Order, OrderLine, DummyBaseModel, DummyModel
from saraki.utility import (
    ExportData,
    import_into_sqla_object,
    json,
    Validator,
    get_key_path,
)


def test_import_into_sqla_object():
    product = Product()
    data = {"name": "Acme anvils", "color": "black", "price": 99}

    import_into_sqla_object(product, data)

    assert product.id is None
    assert product.name == "Acme anvils"
    assert product.color == "black"
    assert product.price == 99


@pytest.mark.wip
@pytest.mark.usefixtures("data")
class TestExportData:
    def test_with_invalid_arguments(self):
        message = "Pass a valid SQLAlchemy mapped class instance"
        export_data = ExportData()

        class NonMappedModel(object):
            pass

        with pytest.raises(ValueError, match=message):
            export_data(NonMappedModel())

        with pytest.raises(ValueError, match=message):
            export_data(1)

    def test_non_persisted_untouched_object(self):
        export_data = ExportData()

        data = export_data(Product())
        assert len(data) == 7

        for prop in ["id", "name", "created_at", "updated_at"]:
            assert data[prop] is None

        assert data["color"] == "white"
        assert data["price"] == 0
        assert data["enabled"] is False

    def test_non_persisted_touched_object(self):
        export_data = ExportData()

        data = export_data(Product(id=9, name="TNT", price=799, color="red"))

        assert len(data) == 7
        assert data["id"] == 9
        assert data["name"] == "TNT"
        assert data["color"] == "red"
        assert data["price"] == 799
        assert data["enabled"] is False
        assert data["created_at"] is None
        assert data["updated_at"] is None

    def test_persisted_object(self, ctx):
        export_data = ExportData()
        product = Product.query.get(1)
        data = export_data(product)

        assert len(data) == 7
        data["id"] = 1
        data["name"] = "Explosive Tennis Balls"
        data["color"] = "white"
        data["price"] = 9

    def test_loaded_one_to_many_relationship(self, ctx):
        export_data = ExportData()

        order = Order.query.options(joinedload(Order.lines)).get(1)
        data = export_data(order)

        assert len(data) == 3
        assert len(data["lines"]) == 3
        assert {"product_id": 1, "quantity": 3, "unit_price": 14} in data["lines"]
        assert {"product_id": 2, "quantity": 4, "unit_price": 142} in data["lines"]
        assert {"product_id": 3, "quantity": 7, "unit_price": 73} in data["lines"]

    def test_loaded_one_to_one_relationship(self, ctx):
        export_data = ExportData()

        order_line = OrderLine.query.options(joinedload(OrderLine.product)).get((1, 2))
        data = export_data(order_line)

        assert len(data) == 5
        assert data["order_id"] == 1
        assert data["product_id"] == 2

        product_data = data["product"]
        assert len(product_data) == 7
        assert product_data["id"] == 2
        assert product_data["name"] == "Binocular"
        assert product_data["color"] == "black"
        assert product_data["price"] == 99

    def test_explicit_column_inclusion(self, ctx):
        export_data = ExportData()

        product = Product.query.get(1)
        data = export_data(product, include=["id", "name"])

        assert len(data) == 2
        assert data["id"] == 1
        assert data["name"] == "Explosive Tennis Balls"

    def test_explicit_column_exclusion(self, ctx):
        export_data = ExportData()

        product = Product.query.get(1)
        data = export_data(product, exclude=["id", "name"])

        assert len(data) == 5
        assert "id" not in data
        assert "name" not in data

    def test_explicit_loaded_relationship_exclusion(self, ctx):
        export_data = ExportData()

        order = (
            Order.query.options(joinedload(Order.lines))
            .options(joinedload(Order.customer))
            .get(1)
        )

        data = export_data(order, exclude=["lines"])

        assert "lines" not in data
        assert "customer" in data

    def test_include_and_exclude_argument(self, ctx):
        export_data = ExportData()
        product = Product.query.get(1)

        data = export_data(product, include=["id", "name", "price"], exclude=["id"])

        assert len(data) == 2
        assert "id" not in data

    def test_exclude_property(self, ctx):
        export_data = ExportData(exclude=["id"])
        product = Product.query.get(1)

        data = export_data(product)

        assert "id" not in data

    def test_exclude_property_and_include_parameter(self, ctx):
        export_data = ExportData(exclude=["id"])
        product = Product.query.get(1)

        data = export_data(product, include=["id"])

        assert "id" not in data

    def test_list_of_sqlalchemy_objects(self, ctx):
        export_data = ExportData()

        lst = export_data(Order.query.all())

        assert type(lst) == list
        assert len(lst) == 2
        assert {"id": 1, "customer_id": 1} in lst

    def test_list_of_sqlalchemy_objects_with_export_method(self, ctx):
        export_data = ExportData()

        lst = export_data(OrderLine.query.all())
        data = lst[0]

        assert len(data) == 3
        assert "product_id" in data
        assert "unit_price" in data
        assert "quantity" in data

    def test_loaded_one_to_one_relationship_with_export_data_method(self, ctx):
        export_data = ExportData()

        order_line = Order.query.options(joinedload(Order.customer)).get(1)
        data = export_data(order_line, include=["id"])

        assert len(data) == 2

        customer = data["customer"]
        assert len(customer) == 2
        assert "id" in customer
        assert "firstname" in customer


class TestJson(object):
    @pytest.mark.parametrize(
        "returned, expected",
        [
            ({"id": 1}, {"id": 1}),
            ([1, 2, 3], [1, 2, 3]),
            (DummyBaseModel(id=2), {"id": 2}),
            (DummyModel(id=2), {"id": 2}),
            ("Hello", "Hello"),
            (1, 1),
            (None, None),
        ],
    )
    def test_return_single_objects(self, returned, expected, request_ctx):
        @json
        def view_func():
            return returned

        with request_ctx("/"):
            rv = view_func()

        assert rv.status_code == 200
        assert rv.content_type == "application/json"
        assert loads(rv.data) == expected

    @pytest.mark.parametrize(
        "returned, expected",
        [
            (({"id": 1}, 500), (500, {"id": 1})),
            (([1, 2, 3], 404), (404, [1, 2, 3])),
            ((DummyBaseModel(id=2), 201), (201, {"id": 2})),
            ((DummyModel(id=2), 201), (201, {"id": 2})),
            (("Hello", 201), (201, "Hello")),
            ((1, 201), (201, 1)),
            ((None, 201), (201, None)),
        ],
    )
    def test_return_status_code(self, returned, expected, request_ctx):
        @json
        def view_func():
            return returned

        with request_ctx("/"):
            rv = view_func()

        assert rv.status_code == expected[0]
        assert rv.content_type == "application/json"
        assert loads(rv.data) == expected[1]

    @pytest.mark.parametrize(
        "returned, expected",
        [
            (({"id": 1}, 500, {"X-header": "x-value"}), (500, {"id": 1})),
            (([1, 2, 3], 404, {"X-header": "x-value"}), (404, [1, 2, 3])),
            ((DummyBaseModel(id=2), 201, {"X-header": "x-value"}), (201, {"id": 2})),
            ((DummyModel(id=2), 201, {"X-header": "x-value"}), (201, {"id": 2})),
            (("Hello", 201, {"X-header": "x-value"}), (201, "Hello")),
            ((1, 201, {"X-header": "x-value"}), (201, 1)),
            ((None, 201, {"X-header": "x-value"}), (201, None)),
        ],
    )
    def test_return_extra_http_header(self, returned, expected, request_ctx):
        @json
        def view_func():
            return returned

        with request_ctx():
            rv = view_func()

        assert rv.status_code == expected[0]
        assert loads(rv.data) == expected[1]
        assert rv.content_type == "application/json"
        assert rv.headers["X-header"] == "x-value"

    def test_return_custom_response(self, request_ctx):
        @json
        def index():
            return make_response("Hello world", 201)

        with request_ctx("/"):
            rv = index()

        assert rv.status_code == 201
        assert rv.data == b"Hello world"
        assert rv.content_type != "application/json"

    def test_post_request_with_wrong_content_type(self, request_ctx):
        @json
        def view_func():
            pass

        error_message = "application/json mimetype expected"

        with request_ctx(method="POST", content_type="text/plain"):
            with pytest.raises(UnsupportedMediaType, match=error_message):
                view_func()

    def test_post_request_with_invalid_json_object(self, request_ctx):
        @json
        def view_func():
            pass

        error_message = "The body request has an invalid JSON object"

        with request_ctx(method="POST", content_type="application/json"):
            with pytest.raises(BadRequest, match=error_message):
                view_func()

    def test_post_request_with_valid_json_object(self, request_ctx):
        @json
        def view_func():
            pass

        config = {"method": "POST", "content_type": "application/json", "data": "{}"}

        with request_ctx(**config):
            view_func()


@pytest.mark.usefixtures("data")
class TestValidator:
    def test_constructor(self):
        v = Validator({}, Order)
        assert v.model_class is Order

    def test_validate_method(self):
        v = Validator({}, Product)

        error_message = "Provide a SQLAlchemy model instance"

        with pytest.raises(RuntimeError, match=error_message):
            v.validate({}, update=True)

        model = {}
        v.validate({}, update=True, model=model)
        assert v.model is model

    def test_unique_rule(self, ctx):
        v = Validator({"name": {"unique": True}}, Product)

        assert v.validate({"name": "product name"}) is True

        error_message = "Must be unique, but 'Acme anvils' already exist"
        assert v.validate({"name": "Acme anvils"}) is False
        assert error_message in v.errors["name"]

    def test_unique_rule_updating(self, ctx):
        model = Product.query.filter_by(name="Acme anvils").one()

        v = Validator({"name": {"unique": True}}, Product)

        kargs = {"update": True, "model": model}
        assert v.validate({"name": "Acme anvils"}, **kargs) is True
        assert v.validate({"name": "new product name"}, **kargs) is True
        assert v.validate({"name": "Binocular"}, **kargs) is False

        error_message = "Must be unique, but 'Binocular' already exist"
        assert error_message in v.errors["name"]


@pytest.fixture(scope="module")
def _object():
    return {
        "5": None,
        "1": {"2": None, "3": {"7": None, "4": {"0": None}}},
        "10": {"11": None, "12": {"13": {"14": None}, "15": None}},
        "6": None,
    }


@pytest.mark.parametrize(
    "key, result",
    [
        ("9", None),
        ("5", ["5"]),
        ("6", ["6"]),
        ("3", ["1", "3"]),
        ("4", ["1", "3", "4"]),
        ("14", ["10", "12", "13", "14"]),
        ("15", ["10", "12", "15"]),
    ],
)
def test_get_key_path(key, _object, result):
    assert get_key_path(key, _object) == result
