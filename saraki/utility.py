import datetime
from sqlalchemy import inspect
from sqlalchemy.orm.collections import InstrumentedList
from sqlalchemy.exc import NoInspectionAvailable


schema_type_conversions = {
    int: 'integer',
    str: 'string',
    bool: 'boolean',
    datetime.date: 'string',
    datetime.datetime: 'string',
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
    return d.arg if isinstance(getattr(d, 'arg', None), (int, str, bool)) \
        else None


def export_from_sqla_object(model, include=[], exclude=[]):
    """Return a dictionary base on the object columns/values. If a list of
    column names is passed, the output will contains just those columns
    that appears in the list.

    If the current object is not persisted in the database, the default
    value of the column is used if provided in the model definition
    like::

        active = Column(Boolean, default=False)

    """

    if type(model) == list:
        return [export_from_sqla_object(item, include, exclude)
                for item in model]

    try:
        persisted = inspect(model).persistent
    except NoInspectionAvailable as e:
        raise ValueError('Pass a valid SQLAlchemy mapped class instance')

    data = {}
    is_including = len(include) > 0
    columns = model.__class__.__table__.columns

    for c in columns:

        name = c.name

        if (not is_including or name in include) and (name not in exclude):

            column_value = getattr(model, name)

            data[name] = column_value if persisted else \
                _get_column_default(c) if column_value is None else \
                column_value

    if persisted is True:

        unloaded_relationships = inspect(model).unloaded
        relationship_keys = [relationship.key for relationship in
                             model.__class__.__mapper__.relationships]

        for key in relationship_keys:

            if key not in unloaded_relationships and key not in exclude:

                rproperty = data[key] = getattr(model, key)

                if type(rproperty) is InstrumentedList:
                    data[key] = \
                        [export_from_sqla_object(item) for item in rproperty]
                else:
                    data[key] = export_from_sqla_object(rproperty) \
                        if rproperty is not None else None

    return data


def generate_schema(model_class, include=[], exclude=[]):
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

        prop['type'] = schema_type_conversions.get(python_type)

        if prop['type'] is None:
            raise LookupError('Unable to determine the column type')

        if python_type == str and column.type.length is not None:
            prop['maxlength'] = column.type.length

        if column.primary_key is True:
            prop['readonly'] = True

        if column.default is None and column.server_default is None \
            and column.nullable is False \
           and column.primary_key is False:
            prop['required'] = True

        schema[name] = prop

    return schema
