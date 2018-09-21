from flask import Flask, Blueprint as _Blueprint
from flask_sqlalchemy import SQLAlchemy
from saraki import errors
from saraki import config as _default_config
from saraki.model import database
from saraki.auth import Auth
from saraki.endpoints import add_resource


class Saraki(Flask):
    def __init__(self, import_name, auth=Auth, db=database, **kargs):

        super(Saraki, self).__init__(import_name, **kargs)

        self.config.from_object(_default_config)
        self.add_default_endpoints()

        if auth:
            self.auth = auth() if callable(auth) else auth
            self.auth.init_app(self)
            self.add_default_blueprints()

        if isinstance(db, SQLAlchemy):
            db.init_app(self)

        errors.init_app(self)

    def init(self):
        if hasattr(self, "auth"):
            self.auth.persist_data()

        database.session.commit()

    def add_default_blueprints(self):
        from saraki.api import appbp

        self.register_blueprint(appbp)

    def add_default_endpoints(self):
        from saraki.api import signup_view

        self.add_url_rule("/signup", "signup", signup_view, methods=["POST"])

    def add_resource(self, modelcls, base_url=None, **options):
        add_resource(self, modelcls, base_url=base_url, **options)


class Blueprint(_Blueprint):
    def add_resource(self, modelcls, base_url=None, **options):
        add_resource(self, modelcls, base_url=base_url, **options)
