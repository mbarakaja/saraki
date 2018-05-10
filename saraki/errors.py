"""
    samma.erros
    ~~~~~~~~~~~

    :copyright: (c) 2015 by Kojoi S.A.
"""
from flask import jsonify


def init_app(app):

    @app.errorhandler(400)
    def bad_request_404(error):
        return jsonify({'error': error.description}), 400
