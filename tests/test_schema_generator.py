import pytest
from common import Product
from saraki.utility import generate_schema


@pytest.fixture(scope='module')
def schema():
    return generate_schema(Product)


def test_included_properties(schema):

    assert len(schema) == 7
    assert 'id' in schema
    assert 'name' in schema
    assert 'color' in schema
    assert 'price' in schema
    assert 'created_at' in schema
    assert 'updated_at' in schema
    assert 'enabled' in schema


def test_primary_key_column(schema):
    assert schema['id']['readonly'] is True


def test_integer_data_type(schema):
    assert schema['id']['type'] == 'integer'
    assert schema['price']['type'] == 'integer'


def test_string_data_type_with_max_length(schema):
    assert schema['name']['type'] == 'string'
    assert schema['name']['maxlength'] == 120


def test_string_data_type_without_max_length(schema):
    assert schema['color']['type'] == 'string'
    assert 'maxlength' not in schema['color']


def test_datetime_data_type(schema):
    assert schema['created_at']['type'] == 'string'
    assert schema['updated_at']['type'] == 'string'


def test_boolean_data_type(schema):
    assert schema['enabled']['type'] == 'boolean'


def test_non_nullable_columns(schema):
    assert schema['name']['required'] is True


def test_non_nullable_column_with_default_value(schema):
    assert 'required' not in schema['created_at']


def test_non_nullable_columns_with_server_default_value(schema):
    assert 'required' not in schema['updated_at']


def test_include_argument():
    schema = generate_schema(Product, include=['id', 'enabled'])

    assert len(schema) == 2
    assert 'id' in schema
    assert 'enabled' in schema


def test_exclude_argument():
    schema = generate_schema(Product, exclude=['id', 'enabled'])

    assert len(schema) == 5
    assert 'id' not in schema
    assert 'enabled' not in schema
