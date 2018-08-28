from passlib.hash import bcrypt_sha256
from sqlalchemy import Column, ForeignKey, Integer, String, Boolean, Text
from sqlalchemy.orm import relationship
from flask_sqlalchemy import SQLAlchemy
from saraki.utility import import_into_sqla_object, export_from_sqla_object

database = SQLAlchemy()
BaseModel = database.Model


class ModelMixin:

    def import_data(self, data):
        return import_into_sqla_object(self, data)

    def export_data(self, include=[], exclude=[]):
        return export_from_sqla_object(self, include, exclude)


class Model(BaseModel, ModelMixin):

    __abstract__ = True


class Plan(Model):
    """Plans available for your application."""

    __tablename__ = 'plan'

    #: Primary key
    id = Column(Integer, primary_key=True)

    #: A name for the plan. For instance, Pro, Business, Personal, etc.
    name = Column(String(100), nullable=False, unique=True)

    #: The amount of members that an organization can have.
    amount_of_members = Column(Integer, nullable=False, default=1)

    #: Price of the plan.
    price = Column(Integer, nullable=False, unique=True)


class User(Model):
    """Application user accounts."""

    __tablename__ = 'user'

    id = Column(Integer, primary_key=True)

    #: Email associated with the account. Must be unique.
    email = Column(String(128), unique=True, nullable=False)

    #: Username associated with the account. Must be unique.
    username = Column(String(20), unique=True, nullable=False)

    #: The canonical username. Must be unique. This is a lowercase version
    #: of the username, used for authentication and validation in the signup
    #: time.
    canonical_username = Column(String(20), unique=True, nullable=False)

    #: Encrypted password string. Don't set the value of this column directly,
    #: instead use the class method ``set_password`` that will verify the
    #: strength of the password and encrypt it for you.
    password = Column(String(255), nullable=False)

    #: This property defines if the user account is activated or not. To use
    #: when the user verifies its account through an email for instance.
    active = Column(Boolean(), default=False, nullable=False)

    def set_password(self, plain_text):
        self.password = bcrypt_sha256.hash(plain_text)

    def verify_password(self, plain_text):
        return bcrypt_sha256.verify(plain_text, self.password)

    def import_data(self, data):

        data['canonical_username'] = data['username'].lower()
        super(User, self).import_data(data)

        self.set_password(data['password'])

    def export_data(
        self,
        include=[],
        exclude=['id', 'password', 'canonical_username'],
    ):
        return super(User, self).export_data(include, exclude)

    def __str__(self):
        return f'<User {self.username}>'


class Org(Model):
    """Organization accounts registered and managed by the application.

    This table registers all organizations being managed by the application and
    owned by at least one user account registered in the :class:`Membership`
    table.
    """

    __tablename__ = 'org'

    #: Primary Key.
    id = Column(Integer, primary_key=True)

    #: The organization account name.
    orgname = Column(String(20), unique=True, nullable=False)

    #: The name of the organization.
    name = Column(String(80), unique=True, nullable=False)

    #: The primary key of the user that created the organization account. But,
    #: this account not necessarily is the owner of the organization account,
    #: just the user that registered the organization. See the table
    #: :class:`Member` for more information.
    app_user_id = Column(Integer, ForeignKey('user.id'), nullable=False)

    #: Plan selected from the :class:`Plan` table.
    app_plan_id = Column(Integer, ForeignKey('plan.id'))

    #
    # - - - Relationships - - -
    #

    created_by = relationship('User', uselist=False)

    plan = relationship('Plan', uselist=False)


class Membership(Model):
    """Users accounts that are members of an Organization.

    Application users who belong to an organization are considered members,
    including the owner of the account. This table is a many to many
    relationship between the tables :class:`User` and :class:`Org`.
    """

    __tablename__ = 'org_member'

    #: The ID of a user account in the table :class:`User`.
    app_user_id = Column(Integer, ForeignKey('user.id'), primary_key=True)

    #: The ID of an organization account in the table :class:`Org`.
    app_org_id = Column(Integer, ForeignKey('org.id'), primary_key=True)

    #: If this is True, this member is the/an owner of this organization. One
    #: or more members can be owner at the same time.
    is_owner = Column(Boolean, default=False, server_default='FALSE',
                      nullable=False)

    #: Enable or disable a member from an organization.
    enabled = Column(Boolean, default=False, nullable=False)

    #
    # -- Relationships --
    #

    org = relationship('Org', uselist=False,)
    user = relationship('User', uselist=False)

    def export_data(self, include=[], exclude=['app_org_id', 'app_user_id']):
        return super(Membership, self).export_data(include, exclude)


class Action(Model, ModelMixin):
    """Actions performed across the application like manage, create, read,
    update, delete, follow, etc.
    """

    __tablename__ = 'action'

    id = Column(Integer, primary_key=True)

    name = Column(String(80), nullable=False, unique=True)

    description = Column(Text)

    def import_data(self, data):
        super(Action, self).import_data(data)


class Resource(Model, ModelMixin):
    """Application resources."""

    __tablename__ = 'resource'

    #: Primary Key.
    id = Column(Integer, primary_key=True)

    #: The name of the resource.
    name = Column(String(80), nullable=False, unique=True)

    #: A useful description, please.
    description = Column(Text)

    #: Parent resource.
    parent_id = Column(Integer, ForeignKey('resource.id'))

    #
    # -- Relationships --
    #

    parent = relationship('Resource', uselist=False, remote_side=id)


def _persist_actions(actions):
    """Saves a list of actions in the database. Actions in the list that
    already exist in the database are ignored.

    Note that this doesn't commit the current session.

    :param actions: list, tuple or set of action names.
    """

    actions = set(actions)
    persisted = {action.name for action in Action.query.all()}
    new_actions = actions - persisted

    for name in new_actions:
        action = Action(name=name)
        database.session.add(action)


def _persist_resources(resources, parent=None):
    """Save resources in the database.

    Note that this doesn't commit the current session.
    """

    persisted = {r.name: r for r in Resource.query.all()}

    for key, value in resources.items():
        if key not in persisted:
            resource = Resource(name=key)
            resource.parent = parent
            database.session.add(resource)
        else:
            resource = persisted[key]

        if value:
            _persist_resources(value, resource)
