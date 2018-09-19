import datetime
from functools import wraps

from cerberus import Validator as _Validator
from sqlalchemy import inspect
from sqlalchemy.orm.collections import InstrumentedList
from sqlalchemy.exc import NoInspectionAvailable
from flask import request, abort, jsonify
from flask.wrappers import Response


schema_type_conversions = {
    int: "integer",
    str: "string",
    bool: "boolean",
    datetime.date: "string",
    datetime.datetime: "string",
}


def is_sqla_obj(obj):
    """Checks if an object is a SQLAlchemy model instance."""
    try:
        inspect(obj)
        return True
    except NoInspectionAvailable:
        return False


def import_into_sqla_object(model_instance, data):
    """Import a dictionary, assigning each item value that match to a
    column name of the object entity class.
    """

    mapper = inspect(model_instance.__class__)

    for key in data:
        if key in mapper.c:
            setattr(model_instance, key, data[key])

    return model_instance


def _get_column_default(c):
    d = c.default
    return d.arg if isinstance(getattr(d, "arg", None), (int, str, bool)) else None


class ExportData:
    """Creates a callable object that convert SQLAlchemy model instances
    to dictionaries.
    """

    def __init__(self, exclude=()):

        #: A global list of column names to exclude. This takes precedence over
        #: the parameters ``include`` and/or ``exclude`` of this instance call.
        self.exclude = tuple(exclude)

    def __call__(self, obj, include=(), exclude=()):
        """Converts SQLAlchemy models into python serializable objects. It can
        take a single model or a list of models.

        By default, all columns are included in the output, unless a list of
        column names are provided to the parameters ``include`` or ``exclude``.
        The latter has precedence over the former. Finally, the columns that
        appear in the :attr:`excluded` property will be excluded, regardless of
        the values that the parameters include and exclude have.

        If the model is not persisted in the database, the default values of
        the columns are used if they exist in the class definition. From the
        example below, the value False will be used for the column active::

            active = Column(Boolean, default=False)

        :param obj: A instance or a list of SQLAlchemy model instances.
        :param include: tuple, list or set.
        :param exclude: tuple, list or set.
        """

        if isinstance(obj, (list, InstrumentedList)):
            try:
                return [item.export_data(include, exclude) for item in obj]
            except AttributeError as e:
                # If the method exist, the exception comes inside of it.
                if hasattr(obj[0], "export_data"):
                    # So re-raise the exception.
                    raise e

                return [self(item, include, exclude) for item in obj]

        try:
            persisted = inspect(obj).persistent
        except NoInspectionAvailable as e:
            raise ValueError("Pass a valid SQLAlchemy mapped class instance")

        columns = obj.__mapper__.columns
        exclude = tuple(exclude) + self.exclude
        data = {}

        for c in columns:
            name = c.name

            if (not include or name in include) and name not in exclude:
                column_value = getattr(obj, name)

                data[name] = (
                    column_value
                    if persisted
                    else _get_column_default(c)
                    if column_value is None
                    else column_value
                )

        if persisted is True:
            unloaded_relationships = inspect(obj).unloaded
            relationship_keys = [
                relationship.key
                for relationship in obj.__class__.__mapper__.relationships
            ]

            for key in relationship_keys:
                if key not in unloaded_relationships and key not in exclude:
                    rproperty = getattr(obj, key)
                    has_export_data = hasattr(rproperty, "export_data")
                    data[key] = None

                    if has_export_data:
                        data[key] = rproperty.export_data()
                    elif rproperty:
                        data[key] = self(rproperty)

        return data


export_from_sqla_object = ExportData(exclude=("org_id",))


def generate_schema(model_class, include=(), exclude=()):
    """Inspect a SQLAlchemy Model Class and return a validation schema
    to be used with the Cerberus library. The schema is generated mapping some
    Cerberus rules with SQLAlchemy model class column types and constraints, as
    follow:

    ================ =======================================================
    Cerberus Rule    Generated value
    ================ =======================================================
    type             Based on the SQLAlchemy column class used (String,
                     Integer, etc).
    readonly         **True** if the column is primary key.
    required         **True** if the constraints ``Column.nullable`` is set to
                     **False** and ``Column.default`` and
                     ``Column.server_default`` are set to **None**.
    default          Not included in the output. This is handled by
                     SQLAlchemy or by the databse engine.
    ================ =======================================================
    """

    schema = {}

    mapper = inspect(model_class)

    for column in mapper.c:

        name = column.name

        if len(include) > 0 and name not in include:
            continue

        if name in exclude:
            continue

        prop = {}

        python_type = column.type.python_type

        prop["type"] = schema_type_conversions.get(python_type)

        if prop["type"] is None:
            raise LookupError("Unable to determine the column type")

        if python_type == str and column.type.length is not None:
            prop["maxlength"] = column.type.length

        if column.primary_key is True:
            prop["readonly"] = True

        if (
            column.default is None
            and column.server_default is None
            and column.nullable is False
            and column.primary_key is False
        ):
            prop["required"] = True

        schema[name] = prop

    return schema


def json(func):
    """Decorator for view functions to return a JSON response.

    When the incoming request is a POST request, it validates the content_type
    and payload before calling the view function. Next, the returned value of
    the view function is transformed into a JSON response.

    The view function can return the response payload, status code and headers
    in the next ways:

    1.  A single object. Can be any JSON serializable object, a Flask Response
        object, or a SQLAlchemy model:

        .. code-block:: python

            return {}

            # custom Response
            return make_response(...)

            # SQLAlchemy model instance
            return Mode.query.filter_by(prop=prop).first()

            return []

            return "string response"

    2.  A tuple in the form **(payload, status, headers)**, or **(payload, headers)**
        the response payload can be any python built-in type, or a SQLAlchemy based
        model object.:

        .. code-block:: python

            # payload, status

            return {}, 201

            return [], 201

            return '...', 400

            # payload, status, headers

            return {}, 201, {'X-Header': 'content'}

            # payload, headers

            return {}, {'X-Header': 'content'}
    """

    @wraps(func)
    def wrapper(*args, **kwargs):

        if request.method == "POST":
            if not request.is_json:
                abort(415, "application/json mimetype expected")

            if request.get_json(silent=True) is None:
                abort(400, "The request payload has an invalid JSON object")

        ro = func(*args, **kwargs)  # returned object

        if type(ro) != tuple:
            if isinstance(ro, (int, bool, str, list, dict, list)):
                return jsonify(ro)

            if isinstance(ro, Response):
                return ro

            ro = (ro,)

        payload, status, headers = ro + (None,) * (3 - len(ro))

        if type(status) != int:
            headers, status = status, None

        if is_sqla_obj(payload):
            try:
                payload = payload.export_data()
            except AttributeError as e:
                # If the method exist, the exception comes inside of it.
                if hasattr(payload, "export_data"):
                    # So re-raise the exception.
                    raise e

                payload = export_from_sqla_object(payload)

        response_object = jsonify(payload)

        if status:
            response_object.status_code = status

        if headers:
            response_object.headers.extend(headers)

        return response_object

    return wrapper


class Validator(_Validator):
    def __init__(self, schema, model_class=None, **kwargs):
        super(Validator, self).__init__(schema, **kwargs)
        self.model_class = model_class

    def validate(self, document, model=None, **kwargs):

        self.model = model

        return super(Validator, self).validate(document, **kwargs)

    def _validate_unique(self, is_unique, field, value):
        """Performs a query to the database to check value is already present
        in a given column.

        The rule's arguments are validated against this schema:
        {'type': 'boolean'}
        """

        if is_unique:
            if not self.model_class:
                raise RuntimeError(
                    "The rule `unique` needs a SQLAlchemy declarative class"
                    " to perform queries to check if the value being validated"
                    " is unique. Provide a class in Validator constructor."
                )

            filters = {field: value}
            model = self.model_class.query.filter_by(**filters).first()

            if model and (not self.update or model is not self.model):
                self._error(field, f"Must be unique, but '{value}' already exist")


def get_key_path(key, _map):

    for map_key, value in _map.items():
        path = []

        if map_key == key:
            return [map_key]

        if type(value) == dict:
            _path = get_key_path(key, value)
            path = ([map_key] + path + _path) if _path else []

        if len(path) > 0:
            return path

    return None
