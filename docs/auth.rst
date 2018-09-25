.. _authorization:

Authorization
=============

Saraki uses an **ability based authorization** mechanism to determine if a given
user can access to an endpoint. This mechanism is composed of **resources**,
**actions**, **abilities**, and **roles**. On each HTTP request, a client must
provide an access token with enough privileges (abilities) to perform a given
action on a given resource.

Before we start with examples and usage information, let define some concepts
and terms:

    * **Resource**: It is any unit or group of data accessible through an API.
      To all the resources we want to be protected we assign a single name to
      them.
    * **Action**: An action is any type of operation that can be performed on a
      resource. We must give a name to the action or task that an API endpoint
      performs. Most of the time it will be one of the classic CRUD operations;
      create, read, update and delete, but it can be any name, for instance,
      follow or listen, for a service that propagates information using
      WebSockets.
    * **Ability:** The ability to perform an action on a resource. For instance;
      read products, create products, etc. It is basically just a resource/action
      pair. But you can add a name and description to it too.
    * **Role**: A set of one or more abilities. For example, a role Cashier
      could have the abilities "read payment", "create payment" or a role Seller
      can have the abilities "read product", "read order", "update order",
      "delete order". A user can have various roles assigned to him.

Saraki uses :ref:`JSON Web Token <jwt>` and stores the privileges that a user
has as a member of given organization in the token payload.


How it works
------------

Assuming we have an endpoint decorated with :func:`~saraki.auth.require_auth`,
the way a request is validated against an endpoint happens in this way:

1. First, look for a valid access token in the incoming request.
2. Then check if the variable converters match the claims of the current access
   token.
3. Finally, check if the scope of the token has the required privileges defined
   in :func:`~saraki.auth.require_auth`.

If any of those steps fail, the application won't execute the view function
and will respond with 401 Unauthorized status code.


Authorization rules
-------------------

The way we define authorization rules on a view function is passing the name
of the **resource** and the **action** required to the :func:`~saraki.auth.require_auth`
decorator.

The :func:`~saraki.auth.require_auth` decorator plays an important role here
because it collects all resources and actions used by the application to latter
save then in the database.

Take into account the next code:

.. code-block:: python

    @app.route("/products")
    @require_auth("product")
    def list_products():
        return []

In the above code, we define that a token must contain the ``product`` resource
explicitly and the action ``read`` implicitly. By implicitly we mean that if an
action name is not provided, the actual route rule HTTP method (GET in this case)
will be mapped to a predefined action (read in this case). So an access token
with the next payload would be able to perform a GET request to the above-defined
endpoint.

.. code-block:: json

    {
        "sub":"coyote",
        "scp": {
            "product": ["read"]
        },
    }

Here the list of predefined action/method mapping:

+--------+--------+
| Method | Action |
+========+========+
| GET    | read   |
+--------+--------+
| POST   | write  |
+--------+--------+
| PATCH  | write  |
+--------+--------+
| DELETE | delete |
+--------+--------+

Let's see three more examples to fully understand how this work:

.. code-block:: python

    @app.route("/products", method=["POST"])
    @require_auth("product")
    def add_product():
        pass

    @app.route("/products/:id", method=["PATCH"])
    @require_auth("product", "update")
    def update_product():
        pass

    @app.route("/products:/id", method=["DELETE"])
    @require_auth("product")
    def delete_product():
        pass

1. The first view function requires an access token with the scope
   ``"product": ["write"]``. The required action is **write** because the
   method to which the route listen is **POST**.
2. The second view function passes a custom action name ``update``,
   so it will require a scope equal to ``"product": ["update"]``. Note that
   the required action is ``update`` and not ``write`` anymore.
3. And the last one requires ``"product": ["delete"]`` because the HTTP
   method is **DELETE**.

The next access token scope should be able to perform a request to any of the
three defined endpoints above:

.. code-block:: json

    {
        "sub":"coyote",
        "scp": {
            "product": ["read", "write", "update", "delete"]
        },
    }

.. _auth-converters:

Variable Converters
-------------------

Another way of adding authorization constraints are the route rule variable
converters. They are very important because they will help the application
segregate the data access between tenant in the database. Currently, there
are two converts:

+-----------+------------------------------------+
| converter | value                              |
+===========+====================================+
| sub       | username. The user account.        |
+-----------+------------------------------------+
| aud       | orgname. The organization account. |
+-----------+------------------------------------+

When one of those variable converters appears in a route rule, the authorization
mechanism will ensure that the current access token claims match the variable
values of the current URL.

Suppose we have a view function with the route rule ``/users/<sub:username>/activity``,
and an incoming request to ``/users/coyote/activity``. For the request to be successful
the access token must have the **sub** claim with the value **coyote**.

.. code-block:: json

    {"sub":"coyote"}

If the request is successful, the local proxy :obj:`~saraki.auth.current_user`
is available. This object always points to the user performing the current request.

The **aud** converter works in exactly the same way, there is no difference.
Let's use both of them in a single route rule:

.. code-block:: python

    from saraki.auth import current_org, current_user

    @app.route("/orgs/<aud:organame>/members/<sub:username>/activity")
    @require_auth()
    def index(organame, username):
        # your code here

In the above code we imported :obj:`~saraki.auth.current_org` which will point
to the current organization being accessed.

A request to ``/orgs/acme/users/coyote/activity`` must have a token with the
next payload:

.. code-block:: json

    {"aud": "acme", "sub":"coyote"}

The local proxies :obj:`~saraki.auth.current_org` and :obj:`~saraki.auth.current_user`
must be used to ensure that operations to the database are made on the correct
organization and user account. So organizations do not end up reading or modifying
data from other organizations.


.. _jwt:

Access token
------------

Currently, the only supported token format is JSON Web Token. You are going to
find a lot of documentation about JWT on the internet, so we are not going to
cover the specification here.

There are two types of access token:

1. **User access token:** This token give access to protected endpoints
   which aren't tenant endpoints. It also gives access to endpoints
   which handles user-specific data. These type of endpoints usually has the
   **sub** :ref:`converter <auth-converters>`.
2. **Org access token:** Gives access to tenant-specific endpoints.
   Those are endpoints which have the **aud** :ref:`converter <auth-converters>`.

A JSON Token transport key/value pairs as payload. Here a list of important
claims that you should be aware of:

* **sub**: This is the username to which a token belongs. This is always present.
* **aud**: This is the organization to which this token has access. What this
  means is that a token that belongs to an organization can not access endpoints
  that belong to other organizations.
* **scp**: This is the scope in which a token can operate. It stores the
  privileges of a user in a dictionary. The properties are the resources and
  the values are a list of actions that can be performed on the resource.

Here a JWT payload that illustrates with the three claims above listed.

.. code-block:: json

    {
        "aud": "acme",
        "sub":"coyote",
        "scp": {
            "catalog": ["read"],
            "sale": ["read", "write", "delete"]
        }
    }
