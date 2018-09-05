from flask import jsonify, request, abort, Blueprint
from sqlalchemy.orm import joinedload
from .auth import require_auth, current_user, current_org
from .model import database, Plan, User, Org, Membership, Resource
from .utility import generate_schema, json, export_from_sqla_object, Validator
from saraki.endpoints import add_resource


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

add_resource(
    Resource,
    appbp,
    "resources",
    methods={"item": ["GET"], "list": ["GET"]},
    resource_name="app",
)


#
# Application plans
# ~~~~~~~~~~~~~~~~~
#

add_resource(
    Plan, appbp, "plans", methods={"item": ["GET"], "list": ["GET"]}, secure=False
)

add_resource(
    Plan,
    appbp,
    "plans",
    resource_name="app",
    methods={"item": ["PATCH", "DELETE"], "list": ["POST"]},
)

"""
    User organizations
    ~~~~~~~~~~~~~~~~~~
"""

ORG_SCHEMA = generate_schema(Org, exclude=["id", "app_user_id"])
ORG_SCHEMA["orgname"]["unique"] = True


def _add_member(app_org, app_user, extra_data=None):
    data = {"app_user_id": app_user.id, "app_org_id": app_org.id}

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

    app_user_id = current_user.id

    memberships = Membership.query.filter_by(app_user_id=app_user_id).all()

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

    app_user = current_user._get_current_object()

    data["app_user_id"] = current_user.id

    app_org = Org()
    app_org.import_data(data)

    database.session.add(app_org)
    database.session.flush()

    _add_member(app_org, app_user, {"is_owner": True})

    database.session.commit()

    return app_org, 201


@appbp.route("/orgs/<aud:orgname>/members")
@require_auth("org")
@json
def list_members(orgname):
    app_org_id = current_org.id
    member_list = (
        Membership.query.options(joinedload("user"))
        .filter_by(app_org_id=app_org_id)
        .all()
    )

    return [member.export_data() for member in member_list], 200


def member_username_validator(field, value, error):
    username = value
    user = User.query.filter_by(username=value).one_or_none()

    if not user:
        error(field, f"User {username} does not exist")
        return

    member = Membership.query.filter_by(
        app_user_id=user.id, app_org_id=current_org.id
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

    member = Membership(app_user_id=user.id, app_org_id=current_org.id)

    database.session.add(member)
    database.session.commit()

    member = (
        Membership.query.options(joinedload(Membership.user))
        .filter_by(app_user_id=user.id, app_org_id=current_org.id)
        .one()
    )

    return member, 201
