from saraki.utility import import_into_sqla_object
from common import Product


def test_import_into_sqla_object():
    product = Product()
    data = {'name': 'Acme anvils', 'color': 'black', 'price': 99}

    import_into_sqla_object(product, data)

    assert product.id is None
    assert product.name == 'Acme anvils'
    assert product.color == 'black'
    assert product.price == 99
