

class AuthenticationError(Exception):
    pass


class InvalidUserError(AuthenticationError):
    pass


class InvalidPasswordError(AuthenticationError):
    pass


class NotFoundCredentialError(AuthenticationError):
    """Raised when a token or a username/password pair can not be found in
    the current HTTP request."""
    pass


class JWTError(AuthenticationError):
    pass
