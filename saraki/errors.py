"""
    saraki.erros
    ~~~~~~~~~~~~
"""
from flask import jsonify
from .exc import NotFoundCredentialError, InvalidUserError, \
    InvalidPasswordError, JWTError


def init_app(app):

    @app.errorhandler(NotFoundCredentialError)
    def not_found_credential_handler(error):
        msg = 'Provide an access token or a username/password'
        return jsonify({'error': msg}), 400

    @app.errorhandler(InvalidUserError)
    def invalid_user_handler(error):
        return jsonify({'error': 'Invalid username or password'}), 400

    @app.errorhandler(InvalidPasswordError)
    def invalid_password_handler(error):
        return jsonify({'error': 'Invalid username or password'}), 400

    @app.errorhandler(JWTError)
    def jwt_error_handler(error):
        return jsonify({'error': str(error)}), 400

    @app.errorhandler(400)
    def bad_request_400(error):
        return jsonify({'error': str(error)}), 400
