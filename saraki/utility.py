import datetime
from sqlalchemy import inspect


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
