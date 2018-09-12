from werkzeug.exceptions import NotFound
from werkzeug.routing import RequestRedirect, MethodNotAllowed
from sqlalchemy import event


def get_view_function(url, method="GET", app=None):
    adapter = app.url_map.bind("")

    try:
        match = adapter.match(url, method=method)
    except RequestRedirect as e:
        # recursively match redirects
        return get_view_function(e.new_url, method)
    except (MethodNotAllowed, NotFound):
        # no match
        return None

    try:
        # return the view function and arguments
        return app.view_functions[match[0]], match[1]
    except KeyError:
        # no view is associated with the endpoint
        return None


def assert_allowed_methods(path, methods, app):
    """Ensures that a URL only allows a set of HTTP methods.

    It not only checks that the HTTP methods passed in the ``methods`` parameter
    are allowed, but also that the URL does not allow methods not included in
    the list.

    If the path provided does not exist a :class:`werkzeug.exceptions.NotFound`
    exception is raised.

    :param path: The string URL to test.
    :param methods: List of HTTP methods expected to be allowed.
    :param app: A Flask application instance.
    """

    adapter = app.url_map.bind("")

    # Get the list of allowed methods
    current_methods = adapter.allowed_methods(path)

    # If the list is empty is because no route matches the path.
    if not current_methods:
        raise NotFound(
            f"{path}. Make sure that an endpoint is implemented that handles it."
        )

    current_methods.remove("OPTIONS")

    # Check if HEAD is present because just endpoints that implements GET
    # explicily implement the HEAD method.
    if "HEAD" in current_methods:
        current_methods.remove("HEAD")

    for current_method in current_methods:
        assert (
            current_method in methods
        ), "The path `{}` should not allow the method {}".format(
            path, current_method
        )

    for expected_method in methods:
        assert (
            expected_method in current_methods
        ), "The path `{}` does not implement the method {}".format(
            path, expected_method
        )


class Savepoint(object):
    """It helps to interact with the database in isolation and then return to
    a previously known state, discarding changes such as the insertion, deletion
    and update of records.::

        with app.app_context():
            sv = Savepoint(database)
            sv.start()

            model = Cartoon()
            database.session.add(model)
            database.session.commit()

            sv.end()  # Rollback all changes

    """

    def __init__(self, database):
        self.database = database
        self.connection = None

    def started(self):
        return self.connection and not self.connection.closed

    def start(self):
        """Starts a root transaction and uses PostgreSQL SAVEPOINTs to keep
        database modification around without really committing the changes to
        the database.
        """

        if self.started():
            raise RuntimeError("There is already an ongoing transaction.")

        connection = self.database.engine.connect()

        # Begin a non-ORM transaction
        root_transaction = connection.begin()

        options = dict(bind=self.database.engine)
        session = self.database.create_scoped_session(options=options)

        self.database.session = session

        # Each time a SAVEPOINT ends, create a new one.
        @event.listens_for(session, "after_transaction_end")
        def restart_savepoint(session, transaction):
            is_savepoint = transaction.nested

            if is_savepoint and not transaction._parent.nested:
                session.expire_all()
                session.begin_nested()

        # Create the first SAVEPOINT
        session.begin_nested()

        self.root_transaction = root_transaction
        self.connection = connection
        self.session = session

    def end(self):
        # Use remove() istead of close() because this is an scoped session.
        self.session.remove()
        self.root_transaction.rollback()
        self.connection.close()
