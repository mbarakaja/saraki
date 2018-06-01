from flask import jsonify, request, abort, Blueprint

from .auth import require_auth, current_identity
from .model import database, AppUser, AppOrg, AppOrgMember
from .utility import generate_schema, json, export_from_sqla_object, Validator

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


appbp = Blueprint("app", __name__)


"""
    User organizations
    ~~~~~~~~~~~~~~~~~~
"""

ORG_SCHEMA = generate_schema(AppOrg, exclude=['id', 'app_user_id'])
ORG_SCHEMA['orgname']['unique'] = True


def _add_member(app_org, app_user, extra_data={}):
    data = {'app_user_id': app_user.id, 'app_org_id': app_org.id}
    data.update(extra_data)

    member = AppOrgMember()
    member.import_data(data)
    database.session.add(member)

    return member


@appbp.route('/users/<sub:username>/orgs')
@require_auth()
@json
def list_user_organizations(username):
    """Return a list of organization accounts of a user. This includes those
    owned by the user and those where the user is a member.
    """

    app_user_id = current_identity.id

    memberships = AppOrgMember.query.filter_by(app_user_id=app_user_id).all()

    org_list = [export_from_sqla_object(m.org) for m in memberships]

    return org_list, 200


@appbp.route('/users/<sub:username>/orgs', methods=['POST'])
@require_auth()
@json
def add_organization_account(username):
    """Creates an new organization account.

    When an user creates an organization account, this user is automatically
    added to the list of members of the organization and then flagged as the
    owner.
    """

    data = request.get_json()
    v = Validator(ORG_SCHEMA, AppOrg)

    if v.validate(data) is False:
        abort(400, v.errors)

    app_user = current_identity._get_current_object()

    data['app_user_id'] = current_identity.id

    app_org = AppOrg()
    app_org.import_data(data)

    database.session.add(app_org)
    database.session.flush()

    _add_member(app_org, app_user, {'is_owner': True})

    database.session.commit()

    return app_org, 201
