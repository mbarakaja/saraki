import os
import pytest
from json import loads as load_json
from sqlalchemy import event
from sqlalchemy.orm import sessionmaker, scoped_session
from saraki import Saraki
from saraki.model import database, AppUser
from common import Person, Product, Order, OrderLine


needdatabase = pytest.mark.skipif(
    os.getenv('DATABASE_URI') is None,
    reason="This need a database connection and DATABASE_URI is not defined"
)


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
    app.config['SECRET_KEY'] = 'secret'
    app.config['SERVER_NAME'] = 'acme.local'

    return app


@pytest.fixture(scope='session')
def db(app):
    """Setup the database

    Creates all tables on setup and deletes all tables on cleanup.
    """

    with app.app_context():
        database.create_all()

    yield

    with app.app_context():
        database.session.remove()
        database.drop_all()


@pytest.fixture(scope='session')
def data(app, db):
    """Put the database in a known state by inserting
    predefined data.

    This is a session scoped fixture.
    """

    with open('tests/data/product.json', 'r') as products_file, \
            open('tests/data/order.json', 'r') as orders_file, \
            open('tests/data/order_line.json', 'r') as order_lines_file,  \
            open('tests/data/person.json', 'r') as persons_file, \
            open('tests/data/user.json') as users_file:

        person_ls = load_json(persons_file.read())
        product_ls = load_json(products_file.read())
        order_ls = load_json(orders_file.read())
        order_line_ls = load_json(order_lines_file.read())
        user_ls = load_json(users_file.read())

    with app.app_context():
        database.session.add_all([Person(**item) for item in person_ls])
        database.session.add_all([Product(**item) for item in product_ls])
        database.session.add_all([Order(**item) for item in order_ls])
        database.session.add_all([OrderLine(**item) for item in order_line_ls])

        for u in user_ls:

            data = {
                'username': u['username'],
                'canonical_username': u['username'].lower(),
                'password': u['hashed_password'],
                'email': u['email']
            }

            user = AppUser(**data)
            database.session.add(user)

        database.session.commit()


@pytest.fixture(scope='session')
def _trn():
    """Create a session wide instance of TransactionManager class.

    TransactionManager helps create nested database transactions.
    This help rollback any transaction using PostgreSQL savepoints.
    """
    return TransactionManager(database)


@pytest.fixture
def client(app, _trn, request, db):
    """Flask Test Client

    This starts a database nested transaction and then closes it
    when the test goes out of scope in order to rollback any change
    made to the database.
    """

    ctx = app.app_context()
    ctx.push()
    _trn.start()

    yield app.test_client()

    _trn.close()
    ctx.pop()


@pytest.fixture
def ctx(app):
    """Push a new application context and closes it automatically
    when the test goes out of scope.

    This helps to avoid creating application contexts manually
    either by calling app.app_context() with python `with` statement or
    by pushing or popping manually."""
    ctx = app.app_context()
    ctx.push()

    yield ctx

    ctx.pop()
