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


def export_from_sqla_object(model, include=(), exclude=()):
    """Return a dictionary base on the object columns/values. If a list of
    column names is passed, the output will contains just those columns
    that appears in the list.

    If the current object is not persisted in the database, the default
    value of the column is used if provided in the model definition
    like::

        active = Column(Boolean, default=False)

    """

    if isinstance(model, (list, InstrumentedList)):
        has_export_data = len(model) > 0 and hasattr(model[0], "export_data")

        if has_export_data:
            return [item.export_data() for item in model]
        else:
            return [export_from_sqla_object(item, include, exclude) for item in model]

    try:
        persisted = inspect(model).persistent
    except NoInspectionAvailable as e:
        raise ValueError("Pass a valid SQLAlchemy mapped class instance")

    data = {}
    columns = model.__class__.__table__.columns

    for c in columns:
        name = c.name

        if (not include or name in include) and name not in exclude:
            column_value = getattr(model, name)

            data[name] = (
                column_value
                if persisted
                else _get_column_default(c)
                if column_value is None
                else column_value
            )

    if persisted is True:
        unloaded_relationships = inspect(model).unloaded
        relationship_keys = [
            relationship.key
            for relationship in model.__class__.__mapper__.relationships
        ]

        for key in relationship_keys:
            if key not in unloaded_relationships and key not in exclude:
                rproperty = getattr(model, key)
                has_export_data = hasattr(rproperty, "export_data")
                data[key] = None

                if has_export_data:
                    data[key] = rproperty.export_data()
                elif rproperty:
                    data[key] = export_from_sqla_object(rproperty)

    return data


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
    """Decorator for flask view functions.

    Check if the request is properly formatted before calling the view
    function. Next, get the return value of the view function and transform it
    into a JSON response in a standardized way.

    You can return the next values:

    1.  A single object. Can be any JSON serializable object, a Flask Response
        object, or a SQLAlchemy model::

            return {}

            # This return a Flask Response too.
            return make_response(...)

            # SQLAlchemy model
            return Mode.query.filter_by(prop=prop).first()

            return []

            return "..."

    2.  A tuple in the form **(body, status, headers)**, the response body can
        be any python built-in type, or a SQLAlchemy based model object.::

            return {}, 201

            return [], 201

            return '...', 400

            return {}, 201, {'X-Header': 'content'}
    """

    @wraps(func)
    def wrapper(*args, **kwargs):

        if request.method == "POST":
            if (
                request.content_type is None
                or "application/json" not in request.content_type
            ):
                abort(415, "application/json mimetype expected")

            if request.get_json(silent=True) is None:
                abort(400, "The body request has an invalid JSON object")

        ro = func(*args, **kwargs)  # returned object

        is_tuple = type(ro) == tuple

        if not is_tuple:
            if isinstance(ro, (int, bool, str, list, dict, list)):
                return jsonify(ro)

            if isinstance(ro, Response):
                return ro

            ro = (ro,)

        body, status, headers = ro + (None,) * (3 - len(ro))

        if hasattr(body, "__table__"):
            body = (
                body.export_data()
                if hasattr(body, "export_data")
                else export_from_sqla_object(body)
            )

        response_object = jsonify(body)

        if status:
            response_object.status_code = status

        if headers:
            response_object.headers.extend(headers or {})

        return response_object

    return wrapper


class Validator(_Validator):
    def __init__(self, schema, model_class=None, **kwargs):
        super(Validator, self).__init__(schema, **kwargs)
        self.model_class = model_class

    def validate(self, document, model=None, **kwargs):

        update = kwargs.get("update", False)

        if update is True and model is None:
            raise RuntimeError(
                "update is set to True but model is None. Provide a SQLAlchemy"
                " model instance in order to perform uniqueness validation"
                " against the model"
            )

        self.model = model

        return super(Validator, self).validate(document, **kwargs)

    def _validate_unique(self, is_unique, field, value, **kwargs):

        if is_unique:
            filter = {field: value}
            model = self.model_class.query.filter_by(**filter).first()

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
