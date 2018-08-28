from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from . import errors
from . import config as _default_config
from .handlers import signup_view, appbp
from .model import database
from .auth import Auth


class Saraki(Flask):

    def __init__(
        self,
        import_name,
        auth=Auth(),
        db=database,
        **kargs
    ):

        super(Saraki, self).__init__(import_name, **kargs)

        self.config.from_object(_default_config)
        self.add_default_endpoints()

        if isinstance(auth, Auth):
            self.auth = auth
            self.auth.init_app(self)
            self.register_blueprint(appbp)

        if isinstance(db, SQLAlchemy):
            db.init_app(self)

        errors.init_app(self)

    def init(self):
        if hasattr(self, 'auth'):
            self.auth.persist_data()

        database.session.commit()

    def add_default_endpoints(self):
        self.add_url_rule('/signup', 'signup', signup_view, methods=['POST'])
