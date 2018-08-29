import pytest
from saraki.auth import require_auth
from saraki.model import Resource, Action


@pytest.mark.usefixtures("ctx", "savepoint")
def test_init(app):
    @app.route("/routes")
    @require_auth("resource1", "action1")
    def route():
        pass

    app.init()

    assert Action.query.filter_by(name="action1").first()
    assert Resource.query.filter_by(name="resource1").first()
