from flask import jsonify, request, abort
from sqlalchemy.orm import joinedload
from saraki import Blueprint
from .auth import require_auth, current_user, current_org
from .utility import generate_schema, json, export_from_sqla_object, Validator
from .model import (
    database,
    Plan,
    User,
    Org,
    Membership,
    Resource,
    Action,
    Ability,
    Role,
    RoleAbility,
    MemberRole,
)


user_schema = generate_schema(User, exclude=["canonical_username", "active"])


def signup_view():

    data = request.get_json()

    v = Validator(user_schema)

    if v.validate(data) is False:
        abort(400, v.errors)

    user = User()
    user.import_data(data)

    database.session.add(user)
    database.session.commit()

    return jsonify({"username": user.username}), 201


appbp = Blueprint("app", __name__)


# Resources
# ~~~~~~~~~

appbp.add_resource(
    Resource,
    "resources",
    methods={"item": ["GET"], "list": ["GET"]},
    resource_name="app",
)


# Action
# ~~~~~~

appbp.add_resource(
    Action, "actions", methods={"item": ["GET"], "list": ["GET"]}, resource_name="app"
)


# Ability
# ~~~~~~

appbp.add_resource(
    Ability,
    "abilities",
    methods={"item": ["GET"], "list": ["GET"]},
    resource_name="app",
)


#
# Application plans
# ~~~~~~~~~~~~~~~~~
#

appbp.add_resource(
    Plan, "plans", methods={"item": ["GET"], "list": ["GET"]}, secure=False
)

appbp.add_resource(
    Plan,
    "plans",
    resource_name="app",
    methods={"item": ["PATCH", "DELETE"], "list": ["POST"]},
)

"""
    User organizations
    ~~~~~~~~~~~~~~~~~~
"""

ORG_SCHEMA = generate_schema(Org, exclude=["id", "user_id"])
ORG_SCHEMA["orgname"]["unique"] = True


def _add_member(org, user, extra_data=None):
    data = {"user_id": user.id, "org_id": org.id}

    if extra_data:
        data.update(extra_data)

    member = Membership()
    member.import_data(data)
    database.session.add(member)

    return member


@appbp.route("/users/<sub:username>/orgs")
@require_auth()
@json
def list_user_organizations(username):
    """Return a list of organization accounts of a user. This includes those
    owned by the user and those where the user is a member.
    """

    user_id = current_user.id

    memberships = Membership.query.filter_by(user_id=user_id).all()

    org_list = [export_from_sqla_object(m.org) for m in memberships]

    return org_list, 200


@appbp.route("/users/<sub:username>/orgs", methods=["POST"])
@require_auth()
@json
def add_organization_account(username):
    """Creates an new organization account.

    When an user creates an organization account, this user is automatically
    added to the list of members of the organization and then flagged as the
    owner.
    """

    data = request.get_json()
    v = Validator(ORG_SCHEMA, Org)

    if v.validate(data) is False:
        abort(400, v.errors)

    user = current_user._get_current_object()

    data["user_id"] = current_user.id

    org = Org()
    org.import_data(data)

    database.session.add(org)
    database.session.flush()

    _add_member(org, user, {"is_owner": True})

    database.session.commit()

    return org, 201


@appbp.route("/orgs/<aud:orgname>/members")
@require_auth("org")
@json
def list_members(orgname):
    org_id = current_org.id
    member_list = (
        Membership.query.options(joinedload("user")).filter_by(org_id=org_id).all()
    )

    return [member.export_data() for member in member_list], 200


def member_username_validator(field, value, error):
    username = value
    user = User.query.filter_by(username=value).one_or_none()

    if not user:
        error(field, f"User {username} does not exist")
        return

    member = Membership.query.filter_by(
        user_id=user.id, org_id=current_org.id
    ).one_or_none()

    if member:
        orgname = current_org.orgname
        error(field, f"{username} is already a member of {orgname}")


new_member_schema = {
    "username": {
        "type": "string",
        "validator": member_username_validator,
        "required": True,
    }
}


@appbp.route("/orgs/<aud:orgname>/members", methods=["POST"])
@require_auth("org")
@json
def add_member(orgname):
    data = request.get_json()
    v = Validator(new_member_schema)

    if v.validate(data) is False:
        abort(400, v.errors)

    username = data["username"]
    user = User.query.filter_by(username=username).one()

    member = Membership(user_id=user.id, org_id=current_org.id)

    database.session.add(member)
    database.session.commit()

    member = (
        Membership.query.options(joinedload(Membership.user))
        .filter_by(user_id=user.id, org_id=current_org.id)
        .one()
    )

    return member, 201


@appbp.route("/orgs/<aud:orgname>/roles")
@require_auth("org", "manage")
@json
def list_roles(orgname):
    roles = Role.query.filter_by(org_id=current_org.id).all()
    return [model.export_data() for model in roles], 200


@appbp.route("/orgs/<aud:orgname>/roles/<int:id>")
@require_auth("org", "manage")
@json
def get_role(orgname, id):
    return Role.query.filter_by(org_id=current_org.id, id=id).first_or_404()


role_schema = generate_schema(Role, exclude=["org_id"])
role_schema["abilities"] = {
    "type": "list",
    "schema": {
        "type": "dict",
        "schema": {
            "action_id": {"type": "integer", "required": True},
            "resource_id": {"type": "integer", "required": True},
        },
    },
}


@appbp.route("/orgs/<aud:orgname>/roles", methods=["POST"])
@require_auth("org", "manage")
@json
def add_role(orgname):
    """Creates a new role for an organization.

    Here an example of a request payload.

    .. code-block:: json

        {
            "name": "My role",
            "description": "This is an important role",
            "abilities": [
                {"action_id": 1 "resource_id": 4},
                {"action_id": 3 "resource_id": 27},
            ]
        }

    The ``abilities`` property is optional.
    """

    payload = request.get_json()
    v = Validator(role_schema)

    if v.validate(payload) is False:
        abort(400, v.errors)

    payload["org_id"] = current_org.id

    model = Role()
    model.import_data(payload)
    database.session.add(model)

    if "abilities" in payload:
        database.session.flush()

        for data in payload["abilities"]:

            data["role_id"] = model.id
            role_ability = RoleAbility()
            role_ability.import_data(data)
            database.session.add(role_ability)

    database.session.commit()

    model.abilities

    return model, 201


@appbp.route("/orgs/<aud:orgname>/roles/<int:id>", methods=["PATCH"])
@require_auth("org", "manage")
@json
def update_role(orgname, id):
    """ Updates an organization role. This endpoint also adds and removes
    abilities, by passing a list with the abilities that you want to add and
    omitting those that you want to remove. For instance, having the next role;

    .. code-block:: json

        {
            "name": "My role",
            "description": "This is a crazy role",
            "abilities": [
                {"action_id": 1, "resource_id": 4},
                {"action_id": 3, "resource_id": 27},
            ]
        }

    If I send a request as belog:

    .. code-block:: json

        {
            "name": "My new name",
            "abilities": [
                {"action_id": 1, "resource_id": 4},
                {"action_id": 4, "resource_id": 100},
            ]
        }

    This will result in ``{"action_id": 4 "resource_id": 100}`` being
    added and ``{"action_id": 3 "resource_id": 27}`` being removed.
    """

    payload = request.get_json()
    v = Validator(role_schema)

    if v.validate(payload, Role, update=True) is False:
        abort(400, v.errors)

    model = Role.query.filter_by(org_id=current_org.id, id=id).first_or_404()
    model.import_data(payload)

    # Here we checks if an ability is being removed or added
    if "abilities" in payload and isinstance(payload["abilities"], list):

        def was_removed(b):
            for index, value in enumerate(payload["abilities"]):
                # if the ability is still present we remove it from the request
                # value and return a False.
                if (
                    b.resource_id == value["resource_id"]
                    and b.action_id == value["action_id"]
                ):
                    payload["abilities"].pop(index)
                    return False
            return True

        # first we checks if an ability was removed
        for a in model.abilities:
            if was_removed(a):
                database.session.delete(a)

        # secondly we save the remaining abilities in the request value
        for c in payload["abilities"]:
            c["role_id"] = model.id
            role_ability = RoleAbility()
            role_ability.import_data(c)
            database.session.add(role_ability)

    database.session.commit()
    return model


@appbp.route("/orgs/<aud:orgname>/roles/<int:id>", methods=["DELETE"])
@require_auth("org", "manage")
@json
def delete_role(orgname, id):
    model = Role.query.filter_by(org_id=current_org.id, id=id).first_or_404()

    database.session.delete(model)
    database.session.commit()
    return {}


#  Member roles
#  ~~~~~~~~~~~~


def _verify_membership(username):
    # Check membership
    subquery = (
        database.session.query(User.id)
        .filter_by(canonical_username=username.lower())
        .subquery()
    )

    return Membership.query.filter_by(
        user_id=subquery.c.id, org_id=current_org.id
    ).first_or_404()


@appbp.route("/orgs/<aud:orgname>/members/<username>/roles")
@require_auth("org", "manage")
@json
def list_member_roles(orgname, username):
    """Returns all the roles assigned to a member."""

    member = _verify_membership(username)

    # Get roles
    member_role = (
        MemberRole.query.options(joinedload(MemberRole.role).joinedload(Role.abilities))
        .filter_by(user_id=member.user_id, org_id=member.org_id)
        .all()
    )

    return [item.role.export_data() for item in member_role], 200


@appbp.route("/orgs/<aud:orgname>/members/<username>/roles/<int:id>")
@require_auth("org", "manage")
@json
def get_member_role(orgname, username, id):
    """This endpoint serves to check if a member has a role assigned to him and
    get information about it as well.
    """

    member = _verify_membership(username)

    ident = (member.org_id, member.user_id, id)

    member_role = MemberRole.query.options(
        joinedload(MemberRole.role).joinedload(Role.abilities)
    ).get_or_404(ident)

    return member_role.role


@appbp.route("/orgs/<aud:orgname>/members/<username>/roles", methods=["POST"])
@require_auth("org", "manage")
@json
def add_member_role(orgname, username):
    """Assigns one or more role to a member.

    The request payload must have a **roles** property containing a list of
    role IDs that you want to assign. Don't send a role ID that already was
    assigned. Example::

        {"roles": [221, 33, 4000]}

    """

    payload = request.get_json()

    v = Validator(
        {"roles": {"type": "list", "minlength": 1, "schema": {"type": "integer"}}}
    )

    if v.validate(payload) is False:
        abort(400)

    member = _verify_membership(username)

    data = {"org_id": member.org_id, "user_id": member.user_id}

    for role_id in payload["roles"]:
        data["role_id"] = role_id
        member_role = MemberRole()
        member_role.import_data(data)
        database.session.add(member_role)

    database.session.commit()

    return {}, 201


@appbp.route(
    "/orgs/<aud:orgname>/members/<username>/roles/<int:id>", methods=["DELETE"]
)
@require_auth("org", "manage")
@json
def remove_member_role(orgname, username, id):
    """Remove a single role from a member."""

    member = _verify_membership(username)

    ident = (member.org_id, member.user_id, id)

    role = MemberRole.query.get_or_404(ident)

    database.session.delete(role)
    database.session.commit()

    return {}, 200
