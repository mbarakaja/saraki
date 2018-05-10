from flask import Flask
from saraki.handlers import signup_view
from saraki import errors
from saraki.model import database
from saraki import config as default_config


class Saraki(Flask):

    def __init__(self, *args, **kargs):
        super(Saraki, self).__init__(*args, **kargs)

        self.config.from_object(default_config)

        self.add_default_endpoints()

        errors.init_app(self)

        database.init_app(self)

    def add_default_endpoints(self):
        self.add_url_rule('/signup', 'signup', signup_view, methods=['POST'])
