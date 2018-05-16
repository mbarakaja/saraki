from flask import jsonify, request, abort
from cerberus import Validator

from .model import AppUser, database
from .utility import generate_schema


user_schema = generate_schema(
    AppUser,
    exclude=['canonical_username', 'active']
)


def signup_view():

    data = request.get_json()

    v = Validator(user_schema)

    if v.validate(data) is False:
        abort(400, v.errors)

    user = AppUser()
    user.import_data(data)

    database.session.add(user)
    database.session.commit()

    return jsonify({'username': user.username}), 201
