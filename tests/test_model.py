import pytest
from saraki.model import (
    User,
    Org,
    Resource,
    Action,
    _persist_actions,
    _persist_resources,
    get_member_privileges,
)


class Test_persist_actions:
    @pytest.mark.usefixtures("ctx", "savepoint")
    def test_add_new_actions(self):

        # Amount of actions registered in source code may change overtime.
        # So base this test on the current amount of resources.
        current_length = len(Action.query.all())

        data = ["follow", "print"]
        _persist_actions(data)

        actions = Action.query.all()
        assert len(actions) == current_length + 2

    @pytest.mark.usefixtures("ctx", "savepoint")
    def test_repeated_actions(self):
        data = {"follow", "print"}
        _persist_actions(data)

        # Amount of actions registered in source code may change overtime.
        # So base this test on the current amount of resources.

        current_length = len(Action.query.all())

        data |= {"follow", "erase", "spy"}
        _persist_actions(data)

        actions = Action.query.all()
        assert len(actions) == current_length + 2


class Test_persist_resources:
    @pytest.mark.usefixtures("ctx", "savepoint")
    def test_add_new_resources(self):

        # Amount of resources registered in source code may change overtime.
        # So base this test on the current amount of resources.
        current_length = len(Resource.query.all())

        data = {"purchase": None, "product": {"catalog": None}}

        _persist_resources(data)
        resources = {r.name: r for r in Resource.query.all()}
        assert len(resources) == 3 + current_length

        assert resources["purchase"].parent is None
        assert resources["product"].parent is None
        assert resources["catalog"].parent is resources["product"]

    @pytest.mark.usefixtures("ctx", "savepoint")
    def test_repeated_resources(self):

        # Amount of resources registered in source code may change overtime.
        # So base this test on the current amount of resources.
        current_length = len(Resource.query.all())

        data = {"purchase": None, "product": {"catalog": None}}

        _persist_resources(data)

        resources = Resource.query.all()
        assert len(resources) == 3 + current_length

        # repeat purchase, product and catalog
        data = {
            "sales": None,
            "purchase": None,
            "product": {"catalog": None, "descontinued": None},
        }

        _persist_resources(data)

        resources = {r.name: r for r in Resource.query.all()}
        assert len(resources) == 5 + current_length

        assert resources["sales"].parent is None
        assert resources["purchase"].parent is None
        assert resources["product"].parent is None
        assert resources["catalog"].parent is resources["product"]
        assert resources["descontinued"].parent is resources["product"]


@pytest.mark.usefixtures("data", "data_member_role")
class Test_get_member_privileges:
    def test_when_member_is_owner(self, ctx):
        user = User.query.filter_by(canonical_username="coyote").one()
        org = Org.query.filter_by(orgname="acme").one()

        privileges = get_member_privileges(org, user)

        assert privileges == {"org": ["manage"]}

    def test_member_without_privileges(self, ctx):

        user = User.query.filter_by(canonical_username="yosesam").one()
        org = Org.query.filter_by(orgname="acme").one()

        privileges = get_member_privileges(org, user)

        assert privileges == {}

    def test_member_with_privileges(self, ctx):

        user = User.query.filter_by(canonical_username="roadrunner").one()
        org = Org.query.filter_by(orgname="acme").one()

        privileges = get_member_privileges(org, user)

        assert privileges == {"org": ["read", "write"]}
