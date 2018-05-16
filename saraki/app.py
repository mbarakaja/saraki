from flask import Flask
from . import errors
from . import config as _default_config
from .handlers import signup_view
from .model import database
from .auth import Auth


auth = Auth()


class Saraki(Flask):

    def __init__(self, *args, **kargs):
        super(Saraki, self).__init__(*args, **kargs)

        self.config.from_object(_default_config)

        self.add_default_endpoints()

        errors.init_app(self)

        database.init_app(self)

    def add_default_endpoints(self):
        self.add_url_rule('/signup', 'signup', signup_view, methods=['POST'])
