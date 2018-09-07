from cerberus import Validator
from flask import request, abort
from sqlalchemy import inspect
from sqlalchemy.orm.exc import NoResultFound

from saraki.model import database
from saraki.exc import ValidationError
from saraki.auth import require_auth, current_org
from saraki.utility import (
    json,
    generate_schema,
    export_from_sqla_object as export_data,
    import_into_sqla_object as import_data,
)


def _import_data(model, data):
    # Classes with the import_data method can customize the import
    # process, therefore, prioritize it.
    if hasattr(model, "import_data"):
        model.import_data(data)
    else:
        import_data(model, data)


def list_view_func(model_class, ident_prop, primary_key, schema, is_org, **kargs):
    filters = {"org_id": current_org.id} if is_org else {}

    if hasattr(model_class, "export_data"):
        return [
            item.export_data() for item in model_class.query.filter_by(**filters).all()
        ]
    else:
        return [
            export_data(item) for item in model_class.query.filter_by(**filters).all()
        ]


def add_view_func(model_class, ident_prop, primary_key, schema, is_org, **kargs):
    payload = request.get_json()

    if is_org:
        payload["org_id"] = current_org.id

    v = Validator(schema)

    if v.validate(payload) is False:
        raise ValidationError(v.errors)

    model = model_class()
    data = v.normalized(payload)
    _import_data(model, data)

    database.session.add(model)
    database.session.commit()

    return model, 201


def item_view(model_class, ident_prop, primary_key, schema, is_org, **kargs):
    """Generic view function to handle operations on single resource items."""

    ident = {prop: kargs.get(prop) for prop in ident_prop}

    if is_org:
        ident["org_id"] = current_org.id

    try:
        model = model_class.query.filter_by(**ident).one()
    except NoResultFound:
        abort(404)

    if request.method == "GET":
        return model

    if request.method == "DELETE":
        database.session.delete(model)
        database.session.commit()
        return model

    if request.method == "PATCH":
        payload = request.get_json()
        v = Validator(schema)

        if v.validate(payload, update=True) is False:
            raise ValidationError(v.errors)

        data = v.normalized(payload)
        _import_data(model, data)
        database.session.commit()

        return model


type_mapping = {int: "int", str: "string"}


def _generate_route_rules(base_url, model_class, ident_prop, is_org=False):
    list_rule = f"/orgs/<aud:orgname>/{base_url}" if is_org else f"/{base_url}"
    item_rule = f"{list_rule}/"

    columns = [getattr(model_class, column_name) for column_name in ident_prop]

    for column in columns:
        python_type = column.type.python_type
        _type = type_mapping.get(python_type, "string")
        item_rule += f"<{_type}:{column.name}>,"

    # Remove the last , character
    item_rule = item_rule[:-1]

    return (list_rule, item_rule)


def add_resource(
    model_class,
    app,
    base_url=None,
    ident=None,
    methods=None,
    secure=True,
    resource_name=None,
):
    """
    Register a resource and generate API endpoints to interact with it.

    The first parameter is a SQLAlchemy model class and the second can
    be a Flask app instance or a Blueprint instance.

    Let start with a code example::

        class Product(Model):
            __tablename__ = 'product'

            id = Column(Integer, primary_key=True)
            name = Column(String)

        add_resource(Product, app)

    The above code will generate the next route rules.

    +-----------------------+--------+----------------------------+
    | Route rule            | Method | Description                |
    +=======================+========+============================+
    | ``/product``          | GET    | Retrive a collection       |
    +-----------------------+--------+----------------------------+
    | ``/product``          | POST   | Create a new resource item |
    +-----------------------+--------+----------------------------+
    | ``/product/<int:id>`` | GET    | Retrieve a resource item   |
    +-----------------------+--------+----------------------------+
    | ``/product/<int:id>`` | PATCH  | Update a resource item     |
    +-----------------------+--------+----------------------------+
    | ``/product/<int:id>`` | DELETE | Delete a resource item     |
    +-----------------------+--------+----------------------------+

    By default, the **name** of the table is used to render the resource list
    part of the url and the name of the **primary key** column for the resource
    identifier part. Note that the type of the column is used when possible for
    the route rule variable type.

    If the model class has a composite primary key, the identifier part
    are rendered with each column name separated by a comma.

    For example::

        class OrderLine(Model):
            __tablename__ = 'order_line'

            order_id = Column(Integer, primary_key=True)
            product_id = Column(Integer, primary_key=True)

        add_resource(Product, app)

    The route rules will be::

        /order-line
        /order-line/<int:order_id>,<int:product_id>

    Note that the character (_) was sustituted by a dash (-) character in the
    base url.

    To customize the base url (resource list part) use the ``base_url``
    parameter, for example::

        add_resource(Product, app, 'products')

    The rendered route rules will be::

        /products
        /products/<int:id>

    By default, all endpoints are secured using the :meth:`~saraki.auth.require_auth`
    decorator. Once again, the table name is used for the resource parameter of
    require_auth, unless the resource_name parameter are provided.

    To disable this behavior pass ``secure=False``.

    Model classes with a property (column) named ``org_id`` will be considered
    an organization resource and will generate an organization endpoint. For
    instance, supposing the model class Product has the property org_id the
    generated route rules will be::

        /orgs/<aud:orgname>/products
        /orgs/<aud:orgname>/products/<int:id>

    :param model_class: SQLAlchemy model class.
    :param app: Flask or Blueprint instance.
    :param base_url: The base url for the resource.
    :param ident: Names of the column used to identify a resource item.
    :param methods: Dict object with allowd HTTP methods for item and list resources.
    :param secure: Boolean flag to secure a resource using require_auth.
    :param resource_name: resource name required in token scope to access this resource.
    """

    is_org = hasattr(model_class, "org_id")

    # The table name is used to generate flask endpoint names
    table_name = model_class.__tablename__

    # When resource_name is not provided use the name of the table
    resource_name = resource_name or table_name

    # Use the table name as default base URL
    base_url = base_url or "-".join(table_name.split("_"))
    primary_key = inspect(model_class).primary_key
    schema = generate_schema(model_class)

    primary_key = tuple(column.name for column in primary_key)
    ident = (ident,) if ident else primary_key

    list_rule, item_rule = _generate_route_rules(base_url, model_class, ident, is_org)

    methods = methods or {}

    list_methods = methods.get("list", ("GET", "POST"))
    item_methods = methods.get("item", ("GET", "PATCH", "DELETE"))

    defaults = {
        "schema": schema,
        "model_class": model_class,
        "ident_prop": ident,
        "primary_key": primary_key,
        "is_org": is_org,
    }

    # Resource list
    if "GET" in list_methods:
        endpoint = f"list_{table_name}"
        view_func = json(list_view_func)

        if secure:
            view_func = require_auth(resource_name)(view_func)

        app.add_url_rule(list_rule, endpoint, view_func, defaults=defaults)

    if "POST" in list_methods:
        endpoint = f"add_{table_name}"
        view_func = json(add_view_func)

        if secure:
            view_func = require_auth(resource_name)(view_func)

        app.add_url_rule(
            list_rule, endpoint, view_func, defaults=defaults, methods=["POST"]
        )

    # Resource item
    view_func = json(item_view)

    if secure:
        view_func = require_auth(resource_name)(view_func)

    if "GET" in item_methods:
        endpoint = f"get_{table_name}"
        app.add_url_rule(
            item_rule, endpoint, view_func, defaults=defaults, methods=["GET"]
        )

    if "PATCH" in item_methods:
        endpoint = f"update_{table_name}"
        app.add_url_rule(
            item_rule, endpoint, view_func, defaults=defaults, methods=["PATCH"]
        )

    if "DELETE" in item_methods:
        endpoint = f"delete_{table_name}"
        app.add_url_rule(
            item_rule, endpoint, view_func, defaults=defaults, methods=["DELETE"]
        )
