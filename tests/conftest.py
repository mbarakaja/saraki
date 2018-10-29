import os
import pytest

from saraki import Saraki
from saraki.model import database
from saraki.testing import Savepoint

from data import (
    insert_cartoons,
    insert_persons,
    insert_products,
    insert_orders,
    insert_actions,
    insert_resources,
    insert_plans,
    insert_users,
    insert_orgs,
    insert_members,
    insert_roles,
    insert_member_roles,
)


from assertions import pytest_assertrepr_compare  # noqa: F401


needdatabase = pytest.mark.skipif(
    os.getenv("DATABASE_URI") is None,
    reason="This need a database connection and DATABASE_URI is not defined",
)


@pytest.fixture(scope="session")
def _setup_database(request):
    """Setup the database

    Creates all tables on setup and deletes all tables on cleanup.
    """

    _app = Saraki(__name__, db=None)
    _app.config["SQLALCHEMY_DATABASE_URI"] = os.environ["TEST_DATABASE_URI"]
    database.init_app(_app)

    with _app.app_context():
        database.create_all()

    def teardown():
        with _app.app_context():
            database.session.remove()
            database.drop_all()

    request.addfinalizer(teardown)

    return database


@pytest.fixture(scope="session")
def _insert_data(_setup_database):
    """Put the database in a known state by inserting predefined data."""

    _app = Saraki(__name__, db=None)
    _app.config["SQLALCHEMY_DATABASE_URI"] = os.environ["TEST_DATABASE_URI"]
    database.init_app(_app)

    with _app.app_context():
        insert_actions()

    with _app.app_context():
        insert_resources()

    with _app.app_context():
        insert_persons()
        insert_products()
        insert_orders()
        insert_cartoons()
        insert_plans()
        insert_users()

        # Insert all registered resources and actions
        _app.init()

        database.session.commit()


@pytest.fixture
def data(_insert_data, database_conn):
    pass


@pytest.fixture
def data_org(ctx, savepoint):
    insert_orgs()


@pytest.fixture
def data_member(ctx, savepoint, data_org):
    insert_members()


@pytest.fixture
def data_role(ctx, savepoint, data_org):
    insert_roles()


@pytest.fixture
def data_member_role(ctx, savepoint, data_member, data_role):
    insert_member_roles()


@pytest.fixture(scope="session")
def _trn():
    """Create a session wide instance of Savepoint class.

    Savepoint helps create nested database transactions.
    This help rollback any transaction using PostgreSQL savepoints.
    """
    return Savepoint(database)


@pytest.fixture
def app(request):

    app = Saraki("flask_test", root_path=os.path.dirname(__file__), db=None)
    app.config["TESTING"] = True
    app.config["SECRET_KEY"] = "secret"

    return app


@pytest.fixture
def request_ctx(app):
    return app.test_request_context


@pytest.fixture
def database_conn(app):
    app.config["SQLALCHEMY_DATABASE_URI"] = os.environ.get("TEST_DATABASE_URI")
    database.init_app(app)


@pytest.fixture
def savepoint(_setup_database, database_conn, _trn, request):
    _trn.start()

    def teardown():
        _trn.end()

    request.addfinalizer(teardown)


@pytest.fixture
def ctx(app, request):
    """Push a new application context and closes it automatically
    when the test goes out of scope.

    This helps to avoid creating application contexts manually
    either by calling app.app_context() with python `with` statement or
    by pushing or popping manually.
    """
    ctx = app.app_context()
    ctx.push()

    def teardown():
        ctx.pop()

    request.addfinalizer(teardown)

    return ctx


@pytest.fixture
def client(app, ctx, savepoint, database_conn):
    """Flask Test Client

    This starts a database nested transaction and then closes it
    when the test goes out of scope in order to rollback any change
    made to the database.
    """

    return app.test_client()


@pytest.fixture
def xclient(app):
    """Flask Test Client (No DB transaction)"""

    return app.test_client()
