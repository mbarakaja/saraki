from functools import wraps
from json.decoder import JSONDecodeError

from flask import request, abort
from flask.json import loads as json_loads

from sqlalchemy import inspect
from sqlalchemy.orm.exc import NoResultFound
from sqlalchemy import func, Text
from sqlalchemy.sql.expression import or_

from saraki.model import database
from saraki.exc import ValidationError
from saraki.auth import require_auth, current_org
from saraki.utility import (
    Validator,
    json,
    generate_schema,
    export_from_sqla_object as export_data,
    import_into_sqla_object as import_data,
)


class Collection:
    """ Creates a decorator for collection endpoints.

    View functions decorated with this decorator must return a SQLAlchemy
    declarative class. This decorator can handle filtering, search, pagination
    and sorting using HTTP query strings.

    This is implemented as a class to extend or change the format of the query
    strings.

    Usage:

    .. code-block:: python

        # First create a instance
        collection = Collection()

        @app.route('/products')
        @collection()
        def index():
            # return a SQLAlchemy declarative class
            return Product

    """

    def _parse_query_string(self, cls, qs):
        qs = qs.to_dict(flat=True)
        schema = generate_schema(cls)
        mapper = inspect(cls)
        columns = [column.name for column in mapper.c]
        query_string_schema = {
            "select": {
                "type": "dict",
                "allowed": columns,
                "valueschema": {"type": "integer"},
            },
            "search": {
                "type": "dict",
                "schema": {
                    "t": {"required": True},
                    "f": {"required": True, "type": "list", "allowed": columns},
                },
            },
            "filter": {"type": "dict", "schema": schema},
            "sort": {},
            "limit": {"type": "integer", "coerce": int},
            "page": {"type": "integer", "coerce": int},
        }

        # First decode all modifiers with JSON string
        json_keys = {"select", "search", "filter"}
        decoded_qs = {}

        for key, value in qs.items():
            if key in json_keys:
                try:
                    decoded_qs[key] = json_loads(value)
                except JSONDecodeError:
                    raise ValidationError({key: "Invalid JSON string"})
            else:
                decoded_qs[key] = value

        v = Validator(query_string_schema)

        if v.validate(decoded_qs, update=True) is False:
            raise ValidationError(v.errors)

        return v.normalized(decoded_qs)

    def _filter_modifier(self, query, filters):
        return query.filter_by(**filters)

    def _parse_select_modifier(self, select):
        include = []
        exclude = []

        for column_name, flag in select.items():
            if flag:
                include.append(column_name)
                continue

            exclude.append(column_name)

        params = {}

        if include:
            params["include"] = include

        if exclude:
            params["exclude"] = exclude

        return params

    def _search_modifier(self, cls, query, search):
        term = search["t"]
        filters = []
        mapper = cls.__mapper__

        for column_name in search["f"]:
            column = getattr(cls, column_name)

            if mapper.c[column_name].type.python_type != str:
                column = func.cast(column, Text)

            filters.append(column.ilike(f"%{term}%"))

        return query.filter(or_(*filters))

    def _sort_modifier(self, cls, query, sort):
        sorting = []

        for column_name in sort.split(","):
            if column_name.startswith("-"):
                column = getattr(cls, column_name[1:])
                sorting.append(column.desc())
                continue

            column = getattr(cls, column_name)
            sorting.append(column.asc())

        return query.order_by(*sorting)

    def __call__(self, default_limit=30, max_limit=100):
        def decorator(f):
            @wraps(f)
            def wrapper(*args, **kwargs):

                Model = f(*args, **kwargs)
                filters = {}

                if hasattr(Model, "org_id"):
                    filters = {"org_id": current_org.id}

                modifiers = self._parse_query_string(Model, request.args)

                query = Model.query

                if "filter" in modifiers:
                    filters.update(modifiers.get("filter", {}))

                if filters:
                    query = self._filter_modifier(query, filters)

                if "search" in modifiers:
                    query = self._search_modifier(Model, query, modifiers["search"])

                if "sort" in modifiers:
                    query = self._sort_modifier(Model, query, modifiers["sort"])

                page = modifiers.get("page", 1)
                limit = min(modifiers.get("limit", default_limit), max_limit)

                result = query.paginate(page, limit)
                items = result.items

                export_data_params = {}

                if "select" in modifiers:
                    export_data_params = self._parse_select_modifier(
                        modifiers["select"]
                    )

                payload = export_data(items, **export_data_params)

                return payload, {"X-Total": result.total, "X-Page": page}

            return wrapper

        return decorator


#: collection decorator
collection = Collection()


def _import_data(model, data):
    # Classes with the import_data method can customize the import
    # process, therefore, prioritize it.
    if hasattr(model, "import_data"):
        model.import_data(data)
    else:
        import_data(model, data)


def list_view_func(modelcls, ident_prop, primary_key, schema, is_org, **kargs):
    return modelcls


def add_view_func(modelcls, ident_prop, primary_key, schema, is_org, **kargs):
    payload = request.get_json()

    if is_org:
        payload["org_id"] = current_org.id

    v = Validator(schema)

    if v.validate(payload) is False:
        raise ValidationError(v.errors)

    model = modelcls()
    data = v.normalized(payload)
    _import_data(model, data)

    database.session.add(model)
    database.session.commit()

    return model, 201


def item_view(modelcls, ident_prop, primary_key, schema, is_org, **kargs):
    """Generic view function to handle operations on single resource items."""

    ident = {prop: kargs.get(prop) for prop in ident_prop}

    if is_org:
        ident["org_id"] = current_org.id

    try:
        model = modelcls.query.filter_by(**ident).one()
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

        if v.validate(payload, update=True, model=model) is False:
            raise ValidationError(v.errors)

        data = v.normalized(payload)
        _import_data(model, data)
        database.session.commit()

        return model


type_mapping = {int: "int", str: "string"}


def _generate_route_rules(base_url, modelcls, ident_prop, is_org=False):
    list_rule = f"/orgs/<aud:orgname>/{base_url}" if is_org else f"/{base_url}"
    item_rule = f"{list_rule}/"

    columns = [getattr(modelcls, column_name) for column_name in ident_prop]

    for column in columns:
        python_type = column.type.python_type
        _type = type_mapping.get(python_type, "string")
        item_rule += f"<{_type}:{column.name}>,"

    # Remove the last , character
    item_rule = item_rule[:-1]

    return (list_rule, item_rule)


def add_resource(
    app,
    modelcls,
    base_url=None,
    ident=None,
    methods=None,
    secure=True,
    resource_name=None,
):
    """ Register a resource and generate API endpoints to interact with it.

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

        add_resource(ap, Product, 'products')

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

    :param app: Flask or Blueprint instance.
    :param modelcls: SQLAlchemy model class.
    :param base_url: The base url for the resource.
    :param ident: Names of the column used to identify a resource item.
    :param methods: Dict object with allowd HTTP methods for item and list resources.
    :param secure: Boolean flag to secure a resource using require_auth.
    :param resource_name: resource name required in token scope to access this resource.
    """

    is_org = hasattr(modelcls, "org_id")

    # The table name is used to generate flask endpoint names
    table_name = modelcls.__tablename__

    # When resource_name is not provided use the name of the table
    resource_name = resource_name or table_name

    # Use the table name as default base URL
    base_url = base_url or "-".join(table_name.split("_"))
    primary_key = inspect(modelcls).primary_key
    schema = generate_schema(modelcls)

    primary_key = tuple(column.name for column in primary_key)
    ident = (ident,) if ident else primary_key

    list_rule, item_rule = _generate_route_rules(base_url, modelcls, ident, is_org)

    methods = methods or {}

    list_methods = methods.get("list", ("GET", "POST"))
    item_methods = methods.get("item", ("GET", "PATCH", "DELETE"))

    defaults = {
        "schema": schema,
        "modelcls": modelcls,
        "ident_prop": ident,
        "primary_key": primary_key,
        "is_org": is_org,
    }

    # Resource list
    if "GET" in list_methods:
        endpoint = f"list_{table_name}"
        view_func = json(collection()(list_view_func))

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
