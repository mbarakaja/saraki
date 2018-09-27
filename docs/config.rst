.. _config:


Configuration
=============

The following configuration values are used internally. Some of them can be
configured using environment variables.


.. data:: SECRET_KEY

    It is used to cryptographically sign each JSON Web Token. Beside that, it
    is used to securely sign session cookies. This is mandatory for the
    authorization mechanism to work.

    This can be setup with the ``SRK_SECRET_KEY`` environment variable.

    Default: ``None``


.. data:: SQLALCHEMY_DATABASE_URI

    The database URI where this app should connect. This can be setup with the
    ``SRK_DATABASE_URI`` environment variable. Below an example::

        postgresql://coyote:12345@localhost/mydatabase

    Default: ``None``


.. data:: SERVER_NAME

    This can be setup with the ``SRK_SERVER_NAME`` environment variable.

    Default: ``None``


.. data:: JWT_ALGORITHM

    The digital signature algorithm used to sign JWTs. Under the hood, `PyJWT`_
    is used to generate the tokens, so read the documentation to see what
    cryptographic `algorithms`_ are available.

    Default: ``'HS256'``


.. data:: JWT_LEEWAY

    Default: ``timedelta(seconds=10)``


.. data:: JWT_EXPIRATION_DELTA

    Defaul: ``timedelta(seconds=300)``


.. data:: JWT_AUTH_HEADER_PREFIX

    The prefix for the ``Authorization`` request header. If the value of this
    header in the current request has a different prefix the toke will be
    considered invalid.

    Default: ``'JWT'``


.. data:: JWT_ISSUER

    This value is used to setup the ``iss`` claim of JSON Web Tokens.

    Default to the value of :data:`SERVER_NAME`, otherwise ``None``.


.. data:: JWT_REQUIRED_CLAIMS

    A list of required claims in a JWT. If one of them is not present, the
    token will be considered invalid.

    Default: ``["exp", "iat", "sub"]``

.. _PyJWT: https://pyjwt.readthedocs.io/en/latest/
.. _algorithms: https://pyjwt.readthedocs.io/en/latest/algorithms.html#digital-signature-algorithms
