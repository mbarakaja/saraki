import pytest
from common import Product
from saraki.utility import generate_schema


@pytest.fixture(scope="module")
def _schema():
    return generate_schema(Product)


def test_included_properties(_schema):

    assert len(_schema) == 7
    assert "id" in _schema
    assert "name" in _schema
    assert "color" in _schema
    assert "price" in _schema
    assert "created_at" in _schema
    assert "updated_at" in _schema
    assert "enabled" in _schema


def test_primary_key_column(_schema):
    assert _schema["id"]["readonly"] is True


def test_integer_data_type(_schema):
    assert _schema["id"]["type"] == "integer"
    assert _schema["price"]["type"] == "integer"


def test_string_data_type_with_max_length(_schema):
    assert _schema["name"]["type"] == "string"
    assert _schema["name"]["maxlength"] == 120


def test_string_data_type_without_max_length(_schema):
    assert _schema["color"]["type"] == "string"
    assert "maxlength" not in _schema["color"]


def test_datetime_data_type(_schema):
    assert _schema["created_at"]["type"] == "string"
    assert _schema["updated_at"]["type"] == "string"


def test_boolean_data_type(_schema):
    assert _schema["enabled"]["type"] == "boolean"


def test_non_nullable_columns(_schema):
    assert _schema["name"]["required"] is True


def test_non_nullable_column_with_default_value(_schema):
    assert "required" not in _schema["created_at"]


def test_non_nullable_columns_with_server_default_value(_schema):
    assert "required" not in _schema["updated_at"]


def test_include_argument():
    schema = generate_schema(Product, include=["id", "enabled"])

    assert len(schema) == 2
    assert "id" in schema
    assert "enabled" in schema


def test_exclude_argument():
    schema = generate_schema(Product, exclude=["id", "enabled"])

    assert len(schema) == 5
    assert "id" not in schema
    assert "enabled" not in schema
