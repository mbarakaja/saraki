from passlib.hash import bcrypt_sha256
from sqlalchemy import (
    Column,
    ForeignKey,
    Integer,
    String,
    Boolean,
    Text,
    UniqueConstraint,
    ForeignKeyConstraint,
)
from sqlalchemy.orm import relationship, aliased
from sqlalchemy.ext.hybrid import hybrid_property
from flask_sqlalchemy import SQLAlchemy
from saraki.utility import import_into_sqla_object, export_from_sqla_object

database = SQLAlchemy()
BaseModel = database.Model


class ModelMixin:
    def import_data(self, data):
        return import_into_sqla_object(self, data)

    def export_data(self, include=(), exclude=()):
        return export_from_sqla_object(self, include, exclude)


class Model(BaseModel, ModelMixin):

    __abstract__ = True


class Plan(Model):
    """Plans available for your application."""

    __tablename__ = "plan"

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

    __tablename__ = "user"

    id = Column(Integer, primary_key=True)

    #: Email associated with the account. Must be unique.
    email = Column(String(128), unique=True, nullable=False)

    _username = Column("username", String(20), unique=True, nullable=False)

    @hybrid_property
    def username(self):
        """Username associated with the account. Must be unique."""
        return self._username

    @username.setter
    def username(self, value):
        self._username = value
        self._canonical_username = value.lower()

    _canonical_username = Column(
        "canonical_username", String(20), unique=True, nullable=False
    )

    @hybrid_property
    def canonical_username(self):
        """ Lowercase version of the username used for authentication.

        Don't set this column directly. This column is filled automatically
        when the :attr:`username` column is assigned with a value.
        """
        return self._canonical_username

    #: Don't set the value of this property directly, instead use the hybrid
    #: property ``password`` that will encrypt it for you.
    _password = Column("password", String(255), nullable=False)

    @hybrid_property
    def password(self):
        """ The password is hashed under the hood, so set this with the
        original/unhashed password directly.
        """
        return self._password

    @password.setter
    def password(self, value):
        self._password = bcrypt_sha256.hash(value)

    #: This property defines if the user account is activated or not. To use
    #: when the user verifies its account through an email for instance.
    active = Column(Boolean(), default=False, nullable=False)

    def verify_password(self, value):
        return bcrypt_sha256.verify(value, self.password)

    def import_data(self, data):
        super(User, self).import_data(data)

        # .import_data does not work with hybrid_property, so we set these
        # manually.
        if "username" in data:
            self.username = data["username"]

        if "password" in data:
            self.password = data["password"]

    def export_data(self, include=(), exclude=("id", "password", "canonical_username")):
        return super(User, self).export_data(include, exclude)

    def __str__(self):
        return f"<User {self.username}>"


class Org(Model):
    """Organization accounts registered and managed by the application.

    This table registers all organizations being managed by the application and
    owned by at least one user account registered in the :class:`Membership`
    table.
    """

    __tablename__ = "org"

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
    user_id = Column(Integer, ForeignKey("user.id"), nullable=False)

    #: Plan selected from the :class:`Plan` table.
    plan_id = Column(Integer, ForeignKey("plan.id"))

    #
    # - - - Relationships - - -
    #

    created_by = relationship("User", uselist=False)

    plan = relationship("Plan", uselist=False)


class Membership(Model):
    """Users accounts that are members of an Organization.

    Application users who belong to an organization are considered members,
    including the owner of the account. This table is a many to many
    relationship between the tables :class:`User` and :class:`Org`.
    """

    __tablename__ = "membership"

    #: The ID of a user account in the table :class:`User`.
    user_id = Column(Integer, ForeignKey("user.id"), primary_key=True)

    #: The ID of an organization account in the table :class:`Org`.
    org_id = Column(Integer, ForeignKey("org.id"), primary_key=True)

    #: If this is True, this member is the/an owner of this organization. One
    #: or more members can be owner at the same time.
    is_owner = Column(Boolean, default=False, server_default="FALSE", nullable=False)

    #: Enable or disable a member from an organization.
    enabled = Column(Boolean, default=False, nullable=False)

    #
    # -- Relationships --
    #

    org = relationship("Org", uselist=False)
    user = relationship("User", uselist=False)

    def export_data(self, include=(), exclude=("org_id", "user_id")):
        return super(Membership, self).export_data(include, exclude)


class Action(Model, ModelMixin):
    """Actions performed across the application like manage, create, read,
    update, delete, follow, etc.
    """

    __tablename__ = "action"

    id = Column(Integer, primary_key=True)

    name = Column(String(80), nullable=False, unique=True)

    description = Column(Text)

    def import_data(self, data):
        super(Action, self).import_data(data)


class Resource(Model, ModelMixin):
    """Application resources."""

    __tablename__ = "resource"

    #: Primary Key.
    id = Column(Integer, primary_key=True)

    #: The name of the resource.
    name = Column(String(80), nullable=False, unique=True)

    #: A useful description, please.
    description = Column(Text)

    #: Parent resource.
    parent_id = Column(Integer, ForeignKey("resource.id"))

    #
    # -- Relationships --
    #

    parent = relationship("Resource", uselist=False, remote_side=id)


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


class Ability(Model, ModelMixin):
    """An ability represents the capacity to perform an action (create, read,
    update, delete) on a resource/module/service of an application. In other
    words is an action/resource pair.

    This table is used to define those pairs, give them a name and a useful
    description.
    """

    __tablename__ = "ability"

    #: Foreign key. References to the column :attr:`~Action.id` of the table
    #: :class:`Action`.
    action_id = Column(Integer, ForeignKey("action.id"), primary_key=True)

    #: Foreign key. References to the column :attr:`~Resource.id` of the table
    #: :class:`Resource`.
    resource_id = Column(Integer, ForeignKey("resource.id"), primary_key=True)

    #: A name for the ability. For instance. Create Products.
    name = Column(String(80), nullable=False, unique=True)

    #: A long text that describes what this ability does.
    description = Column(Text)


def _persist_abilities():
    """This function generates **abilities** (action/resource pair) and inserts
    them into the database.

    Note that this doesn't commit the current session.
    """

    persisted = [(item.action_id, item.resource_id) for item in Ability.query.all()]

    actions = Action.query.all()
    resources = Resource.query.all()

    for resource in resources:
        for action in actions:
            if (action.id, resource.id) not in persisted:

                ability = Ability(
                    name=f"{action.name}:{resource.name}",
                    action_id=action.id,
                    resource_id=resource.id,
                )
                database.session.add(ability)


class Role(Model):
    """A Role is a set of **abilities** that can be assigned to organization
    members, for example, Seller, Cashier, Driver, Manager, etc.

    This table holds all roles of all organizations accounts, determining the
    organization that owns the role by the :class:`Org` identifier in the
    column :attr:`org_id`.

    Since the roles of all organizations reside in this table, the column
    :attr:`name` can have repeated values. But a role name must be unique
    in each organization.
    """

    __tablename__ = "role"

    #: Primary Key.
    id = Column(Integer, primary_key=True)

    #: A name for the paper, Cashier for example.
    name = Column(String(80), nullable=False)

    #: A long text that describes what this role does.
    description = Column(Text, nullable=False)

    #: The :attr:`~Org.id` of the organization account to which this role belongs.
    org_id = Column(Integer, ForeignKey("org.id"))

    #
    # -- Relationships --
    #

    abilities = relationship("RoleAbility", passive_deletes=True)

    __table_args__ = (
        # MemberRole has a composite foreign key referencing those columns.
        UniqueConstraint(id, org_id),
        # The name must be unique to each organization.
        UniqueConstraint(name, org_id),
    )


class RoleAbility(Model, ModelMixin):

    __tablename__ = "role_ability"

    role_id = Column(
        Integer, ForeignKey("role.id", ondelete="CASCADE"), primary_key=True
    )

    action_id = Column(Integer, nullable=False, primary_key=True)

    resource_id = Column(Integer, nullable=False, primary_key=True)

    __table_args__ = (
        ForeignKeyConstraint(
            [action_id, resource_id], [Ability.action_id, Ability.resource_id]
        ),
    )

    #
    # -- Relationships --
    #

    ability = relationship("Ability", uselist=False)

    role = relationship("Role", uselist=False)


class MemberRole(Model, ModelMixin):
    """All the roles that a user has in an organization.

    This table have two composite foreign keys:

    * (:attr:`org_id`, :attr:`user_id`) references to
      :class:`Membership` (:attr:`~Membership.org_id`, :attr:`~Membership.user_id`).
    * (:attr:`org_id`, :attr:`role_id`) references to
      :class:`Role` (:attr:`~Role.org_id`, :attr:`~Role.user_id`).

    Those two composite foreign keys ensure that the user to which a role is
    assigned indeed is a member of the organization.
    """

    __tablename__ = "member_role"

    #: Foreign key. Must be present in the tables :class:`Membership`
    #: and :class:`Role`.
    org_id = Column(Integer, nullable=False, primary_key=True)

    #: Foreign key with :attr:`~Membership.user_id` from the table
    #: :class:`Membership`.
    user_id = Column(Integer, nullable=False, primary_key=True)

    #: Foreign key. :attr:`Role.id` from the table :class:`Role`.
    role_id = Column(Integer, nullable=False, primary_key=True)

    #
    # -- Relationships --
    #

    role = relationship("Role", uselist=False)

    __table_args__ = (
        ForeignKeyConstraint(
            [user_id, org_id],
            [Membership.user_id, Membership.org_id],
            ondelete="CASCADE",
        ),
        ForeignKeyConstraint(
            [role_id, org_id], [Role.id, Role.org_id], ondelete="CASCADE"
        ),
    )


def get_member_privileges(org, user):
    member = Membership.query.filter_by(user_id=user.id, org_id=org.id).one()

    if member.is_owner:
        return {"org": ["manage"]}

    query = database.session.query

    # Get all roles from a specific member
    roles_subquery = (
        query(MemberRole.role_id)
        .filter_by(org_id=member.org_id, user_id=member.user_id)
        .subquery()
    )

    # Get abilities from the list of roles from the subquery above
    abilities_subquery = (
        query(RoleAbility).filter(RoleAbility.role_id.in_(roles_subquery)).subquery()
    )

    action = aliased(Action)
    resource = aliased(Resource)

    # Get all action and resource names from the abilities in the subquery above
    action_resource_query = (
        query(action.name.label("action"), resource.name.label("resource"))
        .select_from(abilities_subquery)
        .join(action, action.id == abilities_subquery.c.action_id)
        .join(resource, resource.id == abilities_subquery.c.resource_id)
    )

    abilities = action_resource_query.all()

    privileges = {}

    for ability in abilities:

        resource_name = ability.resource

        if resource_name not in privileges:
            privileges[resource_name] = []

        privileges[resource_name].append(ability.action)

    return privileges
