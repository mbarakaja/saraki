import pytest
from saraki.model import Resource, Action, _persist_actions, _persist_resources


class Test_persist_actions:
    @pytest.mark.usefixtures("ctx", "savepoint")
    def test_empty_action_table(self):
        data = ["manage", "read", "write", "delete", "print"]
        _persist_actions(data)

        actions = Action.query.all()
        assert len(actions) == len(data)

    @pytest.mark.usefixtures("ctx", "savepoint")
    def test_repeated_actions(self):
        data = {"manage", "read", "write", "delete", "print"}
        _persist_actions(data)

        data |= {"manage", "read", "follow"}
        _persist_actions(data)

        actions = Action.query.all()
        assert len(actions) == len(data)


class Test_persist_resources:
    @pytest.mark.usefixtures("ctx", "savepoint")
    def test_empty_resource_table(self):

        data = {"purchase": None, "product": {"catalog": None}}

        _persist_resources(data)
        resources = {r.name: r for r in Resource.query.all()}
        assert len(resources) == 3

        assert resources["purchase"].parent is None
        assert resources["product"].parent is None
        assert resources["catalog"].parent is resources["product"]

    @pytest.mark.usefixtures("ctx", "savepoint")
    def test_repeated_resources(self):

        data = {"purchase": None, "product": {"catalog": None}}

        _persist_resources(data)

        resources = Resource.query.all()
        assert len(resources) == 3

        data = {
            "sales": None,
            "purchase": None,
            "product": {"catalog": None, "descontinued": None},
        }

        _persist_resources(data)

        resources = {r.name: r for r in Resource.query.all()}
        assert len(resources) == 5

        assert resources["sales"].parent is None
        assert resources["purchase"].parent is None
        assert resources["product"].parent is None
        assert resources["catalog"].parent is resources["product"]
        assert resources["descontinued"].parent is resources["product"]
