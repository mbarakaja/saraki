.. _api:

API
===

.. module:: saraki


The Current Account
-------------------

There are two types of accounts; **user accounts** and **organization accounts**,
The user making a request and the tenant being accessed are available throguth
:data:`current_user` and :data:`current_org`.

.. data:: current_user

    A local proxy object that points to the user accessing an endpoint in the
    current request. The value of this object is an instance of the model class
    :class:`~saraki.model.User` or None if there is not a user.

.. data:: current_org

    A local proxy object that points to the tenant being accessed in the current
    request. The value of this object is an instance of the model class
    :class:`~saraki.model.Org` or None if the endpoint is not a tenant endpoint.


.. note::

    :data:`current_user` and :data:`current_org` are available only on endpoints
    decorated with :func:`~saraki.require_auth`.



Authorization
-------------

.. autofunction:: saraki.require_auth


Endpoints
---------

.. module:: saraki.endpoints

.. autofunction:: json
.. autofunction:: collection
.. autofunction:: add_resource

.. autoclass:: Collection
    :members:


Model
-----

Saraki implements a set of predefined entities where all the application
data is stored, such as users, organizations, roles, etc.

Under the hood, Flask-SQLAlchemy is used to manage sessions and connections to
the database. A global object :data:`~saraki.model.database` is already created
for you to perform operations.

.. data:: saraki.model.database

    Global instance of :class:`~flask_sqlalchemy.SQLAlchemy`

.. automodule:: saraki.model
    :members:
    :member-order: bysource


Utility
-------

.. module:: saraki.utility

.. autofunction:: import_into_sqla_object
.. autofunction:: export_from_sqla_object
.. autofunction:: generate_schema
.. autoclass:: ExportData
    :members:
    :special-members: __call__


Exceptions
----------

.. automodule:: saraki.exc
    :members:
