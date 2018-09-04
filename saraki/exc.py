class ProgrammingError(Exception):
    pass


class AuthenticationError(Exception):
    pass


class InvalidUserError(AuthenticationError):
    pass


class InvalidOrgError(AuthenticationError):
    pass


class InvalidPasswordError(AuthenticationError):
    pass


class InvalidMemberError(AuthenticationError):
    pass


class NotFoundCredentialError(AuthenticationError):
    """Raised when a token or a username/password pair can not be found in
    the current HTTP request."""

    pass


class TokenNotFoundError(AuthenticationError):
    pass


class JWTError(AuthenticationError):
    pass


class AuthorizationError(Exception):
    pass


class ValidationError(Exception):
    def __init__(self, errors):
        self.errors = errors
