from saraki.model import (
    database,
    Plan,
    User,
    Org,
    Membership,
    Action,
    Role,
    RoleAbility,
    Resource,
    MemberRole,
)
from common import Person, Product, Order, OrderLine, Cartoon, reset_secuence


def insert_persons():
    lst = [
        {"id": 1, "firstname": "Nikola", "lastname": "Tesla", "age": 24},
        {"id": 2, "firstname": "Albert", "lastname": "Einstein", "age": 21},
        {"id": 3, "firstname": "Isaac", "lastname": "Newton", "age": 12},
    ]

    database.session.add_all([Person(**item) for item in lst])


def insert_products():
    lst = [
        {"name": "Explosive Tennis Balls", "color": "white", "price": 9},
        {"name": "Binocular", "color": "black", "price": 99},
        {"name": "Acme anvils", "color": "black", "price": 999},
    ]

    database.session.add_all([Product(**item) for item in lst])


def insert_orders():

    # Orders
    order_lst = [{"id": 1, "customer_id": 1}, {"id": 2, "customer_id": 2}]
    database.session.add_all([Order(**item) for item in order_lst])

    # Order lines
    order_line_lst = [
        {"order_id": 1, "product_id": 1, "quantity": 3, "unit_price": 14},
        {"order_id": 1, "product_id": 2, "quantity": 4, "unit_price": 142},
        {"order_id": 1, "product_id": 3, "quantity": 7, "unit_price": 73},
        {"order_id": 2, "product_id": 1, "quantity": 2, "unit_price": 21},
    ]
    database.session.add_all([OrderLine(**item) for item in order_line_lst])


def insert_cartoons():
    lst = [
        {"name": "Bugs Bunny", "nickname": "bugs"},
        {"name": "Pepé Le Pew", "nickname": "pepe"},
        {"name": "Sylvester J. Pussycat Sr.", "nickname": "sylvester"},
    ]

    database.session.add_all([Cartoon(**item) for item in lst])


def insert_actions():
    reset_secuence(Action)

    lst = [
        {"name": "manage", "description": "manage description"},
        {"name": "read", "description": "read description"},
        {"name": "write", "description": "write description"},
        {"name": "delete", "description": "delete description"},
    ]

    database.session.add_all([Action(**item) for item in lst])
    database.session.commit()


def insert_resources():
    reset_secuence(Resource)

    lst = [
        {"name": "app", "description": "app description"},
        {"name": "org", "description": "org description"},
        {"name": "inventory", "description": "inventory description"},
    ]

    database.session.add_all([Resource(**item) for item in lst])
    database.session.commit()


def insert_plans():
    lst = [
        {"name": "Basic", "amount_of_members": 5, "price": 0},
        {"name": "RoadRunner", "amount_of_members": 10, "price": 20},
        {"name": "YoseSam", "amount_of_members": 50, "price": 100},
    ]

    database.session.add_all([Plan(**item) for item in lst])


def insert_users():
    lst = [
        {
            "username": "coyote",
            "email": "coyote@acme",
            "plain_text_password": "12345",
            "_password": (
                "$bcrypt-sha256$2b,"
                "12$lBIBMOF0u7gt6ruXNKalIO$i2MHLlTAbDNrw./RtN9jhDbdC/3dMXu"
            ),
        },
        {
            "username": "RoadRunner",
            "email": "RoadRunner@acme",
            "plain_text_password": "password",
            "_password": (
                "$bcrypt-sha256$2b,"
                "12$f9QIjKmLyaWb3gEp4KTORe$jrfpqWIANSyaEBnzQNz6YLcJusn9uH6"
            ),
        },
        {
            "username": "YoseSam",
            "email": "y0sesam@acme",
            "plain_text_password": "secret",
            "_password": (
                "$bcrypt-sha256$2b,"
                "12$3n9wunxWHfvZj0mg8v10Ru$lSo2YkVRepteVO62W8Q4L3Dn3xmoPna"
            ),
        },
    ]

    for item in lst:
        user = User(
            username=item["username"], email=item["email"], _password=item["_password"]
        )
        database.session.add(user)


def insert_orgs():
    lst = [
        {"username": "coyote", "orgname": "acme", "name": "Acme Corporation"},
        {"username": "RoadRunner", "orgname": "rrinc", "name": "RR Inc"},
    ]

    for data in lst:
        user = User.query.filter_by(username=data["username"]).one()

        org = Org(orgname=data["orgname"], name=data["name"], created_by=user)
        database.session.add(org)

        member = Membership(user=user, org=org, is_owner=True)

        database.session.add(member)

    database.session.commit()


def insert_members():
    acme = Org.query.filter_by(orgname="acme").one()
    rr = Org.query.filter_by(orgname="rrinc").one()

    yosesam = User.query.filter_by(username="YoseSam").one()
    runner = User.query.filter_by(username="RoadRunner").one()

    lst = [
        {"user_id": runner.id, "org_id": acme.id, "is_owner": False},
        {"user_id": yosesam.id, "org_id": acme.id, "is_owner": False},
        {"user_id": yosesam.id, "org_id": rr.id, "is_owner": False},
    ]

    database.session.add_all([Membership(**data) for data in lst])
    database.session.commit()


def insert_roles():
    reset_secuence(Role)

    acme = Org.query.filter_by(orgname="acme").one()
    rr = Org.query.filter_by(orgname="rrinc").one()

    lst = [
        # Acme
        {"name": "role 1", "description": "description 1", "org_id": acme.id},
        {"name": "role 2", "description": "description 2", "org_id": acme.id},
        {"name": "role 3", "description": "description 3", "org_id": acme.id},
        # R.R. Inc
        {"name": "role 4", "description": "description 4", "org_id": rr.id},
        {"name": "role 5", "description": "description 5", "org_id": rr.id},
        {"name": "role 6", "description": "description 6", "org_id": rr.id},
        {"name": "role 7", "description": "description 7", "org_id": rr.id},
    ]

    roles = [Role(**data) for data in lst]

    database.session.add_all(roles)

    role_abilities = [
        {"role": roles[0], "resource_id": 2, "action_id": 2},
        {"role": roles[0], "resource_id": 2, "action_id": 3},
    ]

    database.session.add_all([RoleAbility(**data) for data in role_abilities])

    database.session.commit()


def insert_member_roles():
    runner = User.query.filter_by(username="RoadRunner").one()
    yosesam = User.query.filter_by(username="YoseSam").one()

    acme = Org.query.filter_by(orgname="acme").one()
    rr = Org.query.filter_by(orgname="rrinc").one()

    lst = [
        {"role_id": 1, "user_id": runner.id, "org_id": acme.id},
        {"role_id": 2, "user_id": yosesam.id, "org_id": acme.id},
        {"role_id": 6, "user_id": yosesam.id, "org_id": rr.id},
    ]

    database.session.add_all([MemberRole(**data) for data in lst])
    database.session.commit()
