from passlib.hash import bcrypt_sha256
from sqlalchemy import Column, ForeignKey, Integer, String, Boolean
from sqlalchemy.orm import relationship
from flask_sqlalchemy import SQLAlchemy
from saraki.utility import import_into_sqla_object, export_from_sqla_object

database = SQLAlchemy()
BaseModel = database.Model


class Model(BaseModel):

    __abstract__ = True

    def import_data(self, data):
        return import_into_sqla_object(self, data)

    def export_data(self, include=[], exclude=[]):
        return export_from_sqla_object(self, include, exclude)


class AppUser(Model):
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
        super(AppUser, self).import_data(data)

        self.set_password(data['password'])

    def export_data(
        self,
        include=[],
        exclude=['id', 'password', 'canonical_username'],
    ):
        return super(AppUser, self).export_data(include, exclude)

    def __str__(self):
        return f'<AppUser {self.username}>'


class AppOrg(Model):
    """Organization accounts registered and managed by the application.

    This table registers all organizations being managed by the application and
    owned by at least one user account registered in the :class:`AppOrgMember`
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
    #: :class:`AppOrgMember` for more information.
    app_user_id = Column(Integer, ForeignKey('user.id'), nullable=False)

    #
    # - - - Relationships - - -
    #

    created_by = relationship('AppUser', uselist=False)


class AppOrgMember(Model):
    """Users accounts that are members of an Organization.

    Application users who belong to an organization are considered members,
    including the owner of the account. This table is a many to many
    relationship between the tables :class:`AppUser` and :class:`AppOrg`.
    """

    __tablename__ = 'org_member'

    #: The ID of a user account in the table :class:`AppUser`.
    app_user_id = Column(Integer, ForeignKey('user.id'), primary_key=True)

    #: The ID of an organization account in the table :class:`AppOrg`.
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

    org = relationship('AppOrg', uselist=False,)
    user = relationship('AppUser', uselist=False)

    def export_data(self, include=[], exclude=['app_org_id', 'app_user_id']):
        return super(AppOrgMember, self).export_data(include, exclude)
