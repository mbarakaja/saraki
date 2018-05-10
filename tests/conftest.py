import os
import pytest
from sqlalchemy import event
from sqlalchemy.orm import sessionmaker, scoped_session
from saraki import Saraki
from saraki.model import database


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


@pytest.fixture(scope='session')
def app(request):

    app = Saraki('flask_test', root_path=os.path.dirname(__file__))
    app.config['TESTING'] = True

    with app.app_context():
        database.create_all()

    yield app

    with app.app_context():
        database.session.remove()
        database.drop_all()


@pytest.fixture(scope='session')
def trn():
    return TransactionManager(database)


@pytest.fixture
def client(app, trn, request):

    ctx = app.app_context()
    ctx.push()
    trn.start()

    yield app.test_client()

    trn.close()
    ctx.pop()
