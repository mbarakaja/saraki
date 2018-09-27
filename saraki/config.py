import os
from datetime import timedelta


class Config:
    def __init__(self):
        self.SECRET_KEY = os.getenv("SRK_SECRET_KEY")

        self.SERVER_NAME = os.getenv("SRK_SERVER_NAME")

        self.SQLALCHEMY_DATABASE_URI = os.getenv("SRK_DATABASE_URI")

        self.SQLALCHEMY_TRACK_MODIFICATIONS = False

        self.JWT_AUTH_HEADER_PREFIX = "JWT"

        self.JWT_ALGORITHM = "HS256"

        self.JWT_LEEWAY = timedelta(seconds=10)

        self.JWT_EXPIRATION_DELTA = timedelta(seconds=300)

        self.JWT_ISSUER = self.SERVER_NAME

        self.JWT_REQUIRED_CLAIMS = ["exp", "iat", "sub"]
