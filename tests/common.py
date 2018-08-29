from sqlalchemy import Column, Integer, String, DateTime, Boolean
from sqlalchemy import ForeignKey, func
from sqlalchemy.orm import sessionmaker, scoped_session, relationship
from sqlalchemy import event

from saraki.model import BaseModel, Model


class DummyBaseModel(BaseModel):
    __tablename__ = "dummy_base_model"

    id = Column(Integer, primary_key=True)


class DummyModel(Model):
    __tablename__ = "dummy_model"

    id = Column(Integer, primary_key=True)


class Person(Model):

    __tablename__ = "person"

    id = Column(Integer, primary_key=True)

    firstname = Column(String, nullable=False)

    lastname = Column(String, nullable=False)

    age = Column(Integer, nullable=False)

    def export_data(self, include=("id", "firstname"), exclude=()):
        return super(Person, self).export_data(include, exclude)


class Product(BaseModel):

    __tablename__ = "product"

    id = Column(Integer, primary_key=True)

    name = Column(String(120), nullable=False)

    color = Column(String, default="white")

    price = Column(Integer, default=0)

    created_at = Column(DateTime, nullable=False, default=func.now())

    updated_at = Column(DateTime, nullable=False, server_default=func.now())

    enabled = Column(Boolean, default=False)


class Order(BaseModel):

    __tablename__ = "order"

    id = Column(Integer, primary_key=True)

    customer_id = Column(Integer, ForeignKey("person.id"), nullable=False)

    lines = relationship("OrderLine")

    customer = relationship("Person", uselist=False)


class OrderLine(Model):

    __tablename__ = "order_line"

    id = Column(Integer, primary_key=True)

    order_id = Column(Integer, ForeignKey("order.id"), nullable=False)

    product_id = Column(Integer, ForeignKey("product.id"), nullable=False)

    unit_price = Column(Integer, nullable=False)

    quantity = Column(Integer, default=1, nullable=False)

    product = relationship("Product", uselist=False)

    def export_data(self, include=("id", "unit_price", "quantity"), exclude=()):
        return super(OrderLine, self).export_data(include, exclude)


class TransactionManager(object):
    """Helper that starts and closes PostgreSQL Savepoints. It allow to create
    savepoints and rollback to previous state."""

    session = None
    connection = None
    transaction = None

    def __init__(self, database):
        self.database = database

    def started(self):
        return self.connection and not self.connection.closed

    def start(self):

        if self.started():
            self.close()

        connection = self.database.engine.connect()

        # begin a non-ORM transaction
        transaction = connection.begin()

        options = dict(bind=self.database.engine)
        session = scoped_session(sessionmaker(**options))

        self.database.session = session

        # start a session in a SAVEPOINT...
        session.begin_nested()

        # then each time that SAVEPOINT ends, reopen it
        @event.listens_for(session, "after_transaction_end")
        def restart_savepoint(session, transaction):
            if transaction.nested and not transaction._parent.nested:
                session.expire_all()
                session.begin_nested()

        self.session = session
        self.connection = connection
        self.transaction = transaction

    def close(self):
        self.session.close()
        self.transaction.rollback()
        self.connection.close()
