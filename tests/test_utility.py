import pytest
from sqlalchemy.orm import joinedload
from saraki.utility import import_into_sqla_object, export_from_sqla_object
from common import Product, Order


def test_import_into_sqla_object():
    product = Product()
    data = {'name': 'Acme anvils', 'color': 'black', 'price': 99}

    import_into_sqla_object(product, data)

    assert product.id is None
    assert product.name == 'Acme anvils'
    assert product.color == 'black'
    assert product.price == 99


class Test_export_from_sqla_object():

    def test_with_invalid_arguments(self):

        class NonMappedModel(object):
            pass

        message = 'Pass a valid SQLAlchemy mapped class instance'

        with pytest.raises(ValueError, match=message):
            export_from_sqla_object(NonMappedModel())

        with pytest.raises(ValueError, match=message):
            export_from_sqla_object(1)

    def test_non_persisted_untouched_object(self):

        data = export_from_sqla_object(Product())

        assert len(data) == 7

        for prop in ['id', 'name', 'created_at', 'updated_at']:
            assert data[prop] is None

        assert data['color'] == 'white'
        assert data['price'] == 0
        assert data['enabled'] is False

    def test_non_persisted_touched_object(self):

        data = export_from_sqla_object(
            Product(id=9, name='TNT', price=799, color='red')
        )

        assert len(data) == 7
        assert data['id'] == 9
        assert data['name'] == 'TNT'
        assert data['color'] == 'red'
        assert data['price'] == 799
        assert data['enabled'] is False
        assert data['created_at'] is None
        assert data['updated_at'] is None

    def test_persisted_object(self, ctx):

        product = Product.query.get(1)
        data = export_from_sqla_object(product)

        assert len(data) == 7
        data['id'] = 1
        data['name'] = 'Explosive Tennis Balls'
        data['color'] = 'white'
        data['price'] = 9

    def test_loaded_one_to_many_relationship(self, ctx):

        order = Order.query.options(joinedload(Order.lines)).get(1)
        data = export_from_sqla_object(order)

        assert len(data) == 3
        assert len(data['lines']) == 3
        assert {
            'id': 1,
            'order_id': 1,
            'product_id': 1,
            'quantity': 3,
            'unit_price': 14
        } in data['lines']

        assert {
            'id': 2,
            'order_id': 1,
            'product_id': 1,
            'quantity': 4,
            'unit_price': 142
        } in data['lines']

        assert {
            'id': 3,
            'order_id': 1,
            'product_id': 1,
            'quantity': 7,
            'unit_price': 73
        } in data['lines']

    def test_loaded_one_to_one_relationship(self, ctx):

        order = Order.query.options(joinedload(Order.customer)).get(1)
        data = export_from_sqla_object(order)

        assert len(data) == 3
        assert data['id'] == 1
        assert data['customer_id'] == 1
        assert data['customer'] == {
            'id': 1,
            'firstname': 'Nikola',
            'lastname': 'Tesla',
            'age': 24
        }

    def test_explicit_column_inclusion(self, ctx):

        product = Product.query.get(1)
        data = export_from_sqla_object(product, include=['id', 'name'])

        assert len(data) == 2
        assert data['id'] == 1
        assert data['name'] == 'Explosive Tennis Balls'

    def test_explicit_column_exclusion(self, ctx):

        product = Product.query.get(1)
        data = export_from_sqla_object(product, exclude=['id', 'name'])

        assert len(data) == 5
        assert 'id' not in data
        assert 'name' not in data

    def test_explicit_loaded_relationship_exclusion(self, ctx):

        order = Order.query \
            .options(joinedload(Order.lines)) \
            .options(joinedload(Order.customer)).get(1)

        data = export_from_sqla_object(order, exclude=['lines'])

        assert 'lines' not in data
        assert 'customer' in data

    def test_include_and_exclude_argument(self, ctx):

        product = Product.query.get(1)
        data = export_from_sqla_object(product,
                                       include=['id', 'name', 'price'],
                                       exclude=['id'])

        assert len(data) == 2
        assert 'id' not in data

    def test_list_of_sqlalchemy_objects(self, ctx):
        lst = export_from_sqla_object(Order.query.all())

        assert type(lst) == list
        assert len(lst) == 2
        assert {'id': 1, 'customer_id': 1} in lst
