from saraki.model import database, Plan, User, Org, Membership
from common import Person, Product, Order, OrderLine, Cartoon


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
            "hashed_password": (
                "$bcrypt-sha256$2b,"
                "12$lBIBMOF0u7gt6ruXNKalIO$i2MHLlTAbDNrw./RtN9jhDbdC/3dMXu"
            ),
        },
        {
            "username": "RoadRunner",
            "email": "RoadRunner@acme",
            "plain_text_password": "password",
            "hashed_password": (
                "$bcrypt-sha256$2b,"
                "12$f9QIjKmLyaWb3gEp4KTORe$jrfpqWIANSyaEBnzQNz6YLcJusn9uH6"
            ),
        },
        {
            "username": "YoseSam",
            "email": "y0sesam@acme",
            "plain_text_password": "secret",
            "hashed_password": (
                "$bcrypt-sha256$2b,"
                "12$3n9wunxWHfvZj0mg8v10Ru$lSo2YkVRepteVO62W8Q4L3Dn3xmoPna"
            ),
        },
    ]

    for item in lst:

        data = {
            "username": item["username"],
            "canonical_username": item["username"].lower(),
            "password": item["hashed_password"],
            "email": item["email"],
        }

        user = User(**data)
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
    lst = [
        {"username": "RoadRunner", "orgname": "acme", "is_owner": False},
        {"username": "YoseSam", "orgname": "acme", "is_owner": False},
    ]

    for data in lst:
        user = User.query.filter_by(username=data["username"]).one()
        org = Org.query.filter_by(orgname=data["orgname"]).one()

        member = Membership(user=user, org=org, is_owner=data["is_owner"])

        database.session.add(member)

    database.session.commit()
