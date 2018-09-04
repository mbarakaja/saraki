import pytest
from flask import Flask
from werkzeug.exceptions import NotFound
from saraki.model import database
from saraki.testing import Savepoint, assert_allowed_methods
from common import Cartoon


class Test_assert_allowed_methods:
    def test_non_existent_path(self):
        app = Flask(__name__)

        with pytest.raises(NotFound):
            assert_allowed_methods("/unknown", ["GET"], app)

    def test_path_allowing_unlisted_methods(self):
        app = Flask(__name__)

        @app.route("/candies", methods=["GET", "POST", "DELETE"])
        def candies():
            pass

        message = "The path `/candies` should not allow the method DELETE"

        with pytest.raises(AssertionError, match=message):
            assert_allowed_methods("/candies", ["GET", "POST"], app)

    def test_path_not_allowing_listed_methods(self):
        app = Flask(__name__)

        @app.route("/candies", methods=["GET"])
        def candies():
            pass

        message = "The path `/candies` does not implement the method POST"

        with pytest.raises(AssertionError, match=message):
            assert_allowed_methods("/candies", ["GET", "POST"], app)

    def test_path_implementing_only_listed_methods(self):
        app = Flask(__name__)

        @app.route("/candies", methods=["PATCH", "PUT"])
        def candies():
            pass

        assert_allowed_methods("/candies", ["PATCH", "PUT"], app)


@pytest.mark.usefixtures("data")
class TestSavepoint:
    def test_insert_rows(self, app):
        sv = Savepoint(database)

        with app.app_context():
            assert len(Cartoon.query.all()) == 3

        with app.app_context():
            sv.start()

            cartoon = Cartoon(name="aaa")
            database.session.add(cartoon)
            database.session.commit()

            assert len(Cartoon.query.all()) == 4

            sv.end()

        with app.app_context():
            assert len(Cartoon.query.all()) == 3

    def test_deleting_rows(self, app):
        sv = Savepoint(database)

        with app.app_context():
            assert len(Cartoon.query.all()) == 3

        with app.app_context():
            sv.start()

            cartoon = Cartoon.query.get(1)
            database.session.delete(cartoon)
            database.session.commit()

            assert len(Cartoon.query.all()) == 2

            sv.end()

        with app.app_context():
            assert len(Cartoon.query.all()) == 3

    def test_start_without_closing_current_transaction(self, app):
        sv = Savepoint(database)

        with app.app_context():
            message = "There is already an ongoing transaction."

            with pytest.raises(RuntimeError, match=message):
                sv.start()
                sv.start()
