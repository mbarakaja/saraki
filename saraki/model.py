from flask_sqlalchemy import SQLAlchemy
from saraki.utility import import_into_sqla_object

database = SQLAlchemy()
BaseModel = database.Model


class Model(BaseModel):

    __abstract__ = True

    def import_data(self, data):
        return import_into_sqla_object(self, data)
