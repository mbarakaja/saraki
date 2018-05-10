from passlib.hash import bcrypt_sha256
from sqlalchemy import Column, Integer, String, Boolean
from flask_sqlalchemy import SQLAlchemy
from saraki.utility import import_into_sqla_object

database = SQLAlchemy()
BaseModel = database.Model


class Model(BaseModel):

    __abstract__ = True

    def import_data(self, data):
        return import_into_sqla_object(self, data)


class AppUser(Model):
    """Application user accounts"""

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

    def import_data(self, data):

        data['canonical_username'] = data['username'].lower()
        super(AppUser, self).import_data(data)

        self.set_password(data['password'])

    def __str__(self):
        return f'<AppUser {self.username}>'
