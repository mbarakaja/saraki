Quickstart
==========


A Minimal Application
---------------------

Since Saraki is just Flask, a basic app looks exactly the same way with the
difference that we must use the Saraki class:

.. code-block:: python

    from saraki import Saraki
    app = Saraki(__name__)
    app.config["SQLALCHEMY_DATABASE_URI"] = "postgresql://user:pass@hostname/db"

We haven’t done any special yet. we just created an app instance and set up our
database URI, but if we run the application we are going to get out of the box
an API with the next features:

* User signup.
* Multiple organization accounts (tenant) per user.
* Organization members (memberships).
* Role management per organization.
* Authentication and authorization.

Now, let create a ``Todo`` class which will store to-do lists for each
organization account.

.. code-block:: python

    from sqlalchemy import Column, ForeignKey, Integer, String

    class Todo(Model):
        id = Column(Integer, primary_key=True)
        task = Column(String)
        org_id = Column(Integer, ForeignKey("org.id"))

This is just another SQLAlchemy declarative base class. The only important thing
here is the column **org_id**. This column will tell to Saraki that this entity
is going to store multi-tenant data.

Now let create a tenant endpoint to access a to-do list per organization account.

.. code-block:: python

    from saraki.auth import require_auth
    from saraki.endpoints import collection

    @app.route('/orgs/<aud:orgname>/todos')
    @require_auth()
    @collection()
    def list():
        return Todo

Let's talk about what we did in the above code:

1. First, we added a route rule with a special converter **aud**. This converter
   will define the tenant accessed in the current request. So, a request to
   ``/orgs/acme/todos`` means that we are asking for data from the Acme
   organization.
2. Then we use the :func:`~saraki.auth.require_auth` decorator, which will
   validate HTTP requests looking for a valid access token. This decorator is
   mandatory for all tenant endpoints since it checks that an access token
   corresponds to the organization account accessed.
3. We use the :func:`~saraki.endpoints.collection` decorator. This will handle
   operations such as filtering and sorting, but more importantly, it will
   ensure that a query to the database is properly segregated by filtering
   the results by the column **org_id**.
4. And finally, we just return the model class to let the collection decorator
   handle it.

We have not talked about how to insert, update and delete data until now. Each
of these operations can be implemented normally as you would in any other
application based on Flask and SQLAlchemy, for example, an endpoint to add new
records would look like this:

.. code-block:: python

    from saraki.auth import current_org
    from saraki.model import database

    @app.route('/orgs/<aud:orgname>/todos', methods=["POST"])
    @require_auth()
    def add_todo():
        todo = Todo()
        todo.task = "Stop being lazy"
        todo.org_id = current_org.id

        database.session.add(todo)
        database.session.commit()

        return "", 201

When a request is send to a tenant endpoint, the local proxy
:obj:`~saraki.auth.current_org` is available and points to the current
organization being accessed.


Protecting endpoints
--------------------

Every application will have one or more endpoints that should not be open to
the public. The way we protect an endpoint from unauthorized access is by
requiring a token on each HTTP request.

Use the :func:`~saraki.auth.require_auth` decorator to protect an endpoint.

.. code-block:: python

    @app.route('/chat')
    @require_auth()
    def hello_world():
        return "Messages of this chat"

The above snippet is the most basic way of protecting an endpoint. At the
minimum, it will require someone to :ref:`sigup <api-signup>` first and
then get an access token previous :ref:`authentication <api-authentication>`.
It doesn’t specify any authorization constraint so it won’t check the scope
of the access token in the current request.

To learn how to add authorization constraints read the :ref:`authorization`
documentation.
