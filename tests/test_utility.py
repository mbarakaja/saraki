import pytest
from unittest.mock import patch
from sqlalchemy.orm import joinedload
from saraki.utility import (
    export_from_sqla_object,
    ExportData,
    import_into_sqla_object,
    Validator,
    get_key_path,
    generate_schema,
)
from common import Cartoon, Product, Order, OrderLine, Todo


def test_import_into_sqla_object():
    product = Product()
    data = {"name": "Acme anvils", "color": "black", "price": 99}

    import_into_sqla_object(product, data)

    assert product.id is None
    assert product.name == "Acme anvils"
    assert product.color == "black"
    assert product.price == 99


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
        assert data["id"] == 1
        assert data["name"] == "Explosive Tennis Balls"
        assert data["color"] == "white"
        assert data["price"] == 9

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

    def test_exclude_property_on_model_with_export_data_method(self, ctx):
        assert hasattr(Cartoon, "export_data")
        assert hasattr(Cartoon, "id")

        export_data = ExportData(exclude=["id"])
        product = Cartoon.query.first()
        data = export_data(product)

        assert "id" not in data

    def test_exclude_property_on_list_of_models_with_export_data_method(self, ctx):
        assert hasattr(Todo, "export_data")

        lst = Cartoon.query.all()
        assert len(lst) > 0

        output = export_from_sqla_object(lst)
        assert all(["org_id" not in model for model in output])

    def test_exclude_property_on_list_of_models(self, ctx):
        export_data = ExportData(exclude=["customer_id"])

        assert not hasattr(Order, "export_data")
        lst = Order.query.all()

        assert len(lst) > 0
        output = export_data(lst)

        assert all(["customer_id" not in model for model in output])

    def test_exclude_property_and_include_parameter(self, ctx):
        export_data = ExportData(exclude=["id"])
        product = Product.query.get(1)

        data = export_data(product, include=["id"])

        assert "id" not in data

    def test_list_of_models_without_export_data(self, ctx):
        export_data = ExportData()
        lst = export_data(Order.query.all())

        assert type(lst) == list
        assert len(lst) == 2
        assert {"id": 1, "customer_id": 1} in lst

    def test_list_of_models_with_export_method(self, ctx):
        export_data = ExportData()
        lst = export_data(OrderLine.query.all())
        data = lst[0]

        assert len(data) == 3
        assert "product_id" in data
        assert "unit_price" in data
        assert "quantity" in data

    def test_explicit_inclusion_on_list_of_models(self, ctx):
        export_data = ExportData()
        lst = export_data(Order.query.all(), include=["id"])

        assert type(lst) == list
        assert len(lst) == 2
        assert all(["customer_id" not in model for model in lst])

    def test_explicit_exclusion_on_list_of_models(self, ctx):
        export_data = ExportData()
        lst = export_data(Order.query.all(), exclude=["customer_id"])

        assert type(lst) == list
        assert len(lst) == 2
        assert all(["customer_id" not in model for model in lst])

    def test_explicit_inclusion_on_list_of_model_with_export_data_method(self, ctx):
        export_data = ExportData()
        lst = Cartoon.query.all()
        output = export_data(Cartoon.query.all(), include=["id"])

        assert len(output) == len(lst)
        assert all(["name" not in model for model in output])

    def test_explicit_exclusion_on_list_of_models_with_export_data_method(self, ctx):
        export_data = ExportData()
        lst = OrderLine.query.all()
        output = export_data(lst, exclude=["product_id"])

        assert len(output) == len(lst)
        assert all(["product_id" not in model for model in output])

    def test_loaded_one_to_one_relationship_with_export_data_method(self, ctx):
        export_data = ExportData()

        order_line = Order.query.options(joinedload(Order.customer)).get(1)
        data = export_data(order_line, include=["id"])

        assert len(data) == 2

        customer = data["customer"]
        assert len(customer) == 2
        assert "id" in customer
        assert "firstname" in customer

    def test_model_class_export_data_with_exception(self, request_ctx):
        class Fake:
            def export_data(self, include, exclude):
                raise AttributeError("Inside of export_data method")

        with pytest.raises(AttributeError, match="Inside of export_data method"):
            export_from_sqla_object([Fake()])

    def test_passed_arguments_on_list_of_model_with_export_data_method(self, ctx):
        """Test that the global list of excluded columns are not passed down
        to export_data method.
        """

        with patch.object(OrderLine, "export_data"):
            model = OrderLine()
            export_from_sqla_object([model], exclude=["product_id"])

            model.export_data.assert_called_with((), ["product_id"])


@pytest.mark.usefixtures("data")
class TestValidator:
    def test_constructor(self):
        v = Validator({}, Order)
        assert v.model_class is Order

    def test_unique_rule_missing_model_class(self, ctx):
        v = Validator({"name": {"unique": True}})

        with pytest.raises(RuntimeError):
            v.validate({"name": "Update name"})

    def test_unique_rule(self, ctx):
        v = Validator({"name": {"unique": True}}, Product)
        assert v.validate({"name": "New product name"}) is True

    def test_unique_rule_when_name_already_exist(self, ctx):
        v = Validator({"name": {"unique": True}}, Product)
        assert v.validate({"name": "Acme anvils"}) is False
        assert "Must be unique, but 'Acme anvils' already exist" in v.errors["name"]

    def test_unique_rule_update_without_model_argument(self, ctx):
        v = Validator({"name": {"unique": True}}, Product)

        assert v.validate({"name": "Update name"}, update=True) is True
        assert v.validate({"name": "Acme anvils"}, update=True) is False

    def test_unique_rule_update_with_model_argument(self, ctx):
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


@pytest.fixture(scope="module")
def _schema():
    return generate_schema(Product)


@pytest.mark.wip
class Test_schema_generator:
    def test_included_properties(self, _schema):

        assert len(_schema) == 7
        assert "id" in _schema
        assert "name" in _schema
        assert "color" in _schema
        assert "price" in _schema
        assert "created_at" in _schema
        assert "updated_at" in _schema
        assert "enabled" in _schema

    def test_primary_key_column(self, _schema):
        assert _schema["id"]["readonly"] is True

    def test_integer_data_type(self, _schema):
        assert _schema["id"]["type"] == "integer"
        assert _schema["price"]["type"] == "integer"

    def test_string_data_type_with_max_length(self, _schema):
        assert _schema["name"]["type"] == "string"
        assert _schema["name"]["maxlength"] == 120

    def test_string_data_type_without_max_length(self, _schema):
        assert _schema["color"]["type"] == "string"
        assert "maxlength" not in _schema["color"]

    def test_datetime_data_type(self, _schema):
        assert _schema["created_at"]["type"] == "string"
        assert _schema["updated_at"]["type"] == "string"

    def test_boolean_data_type(self, _schema):
        assert _schema["enabled"]["type"] == "boolean"

    def test_non_nullable_columns(self, _schema):
        assert _schema["name"]["required"] is True

    def test_non_nullable_column_with_default_value(self, _schema):
        assert "required" not in _schema["created_at"]

    def test_non_nullable_columns_with_server_default_value(self, _schema):
        assert "required" not in _schema["updated_at"]

    def test_unique_constraint(self):
        schema = generate_schema(Product)
        assert "unique" not in schema["name"]

        schema = generate_schema(Cartoon)
        assert schema["name"]["unique"] is True

        schema = generate_schema(Cartoon, exclude_rules=["unique"])
        assert "unique" not in schema["name"]

    def test_include_argument(self):
        schema = generate_schema(Product, include=["id", "enabled"])

        assert len(schema) == 2
        assert "id" in schema
        assert "enabled" in schema

    def test_exclude_argument(self):
        schema = generate_schema(Product, exclude=["id", "enabled"])

        assert len(schema) == 5
        assert "id" not in schema
        assert "enabled" not in schema
