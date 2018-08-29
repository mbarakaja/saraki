import os
from datetime import timedelta


SECRET_KEY = os.getenv("SECRET_KEY")

SERVER_NAME = os.getenv("SERVER_NAME")

SQLALCHEMY_DATABASE_URI = os.getenv("DATABASE_URI")

SQLALCHEMY_TRACK_MODIFICATIONS = False

JWT_LEEWAY = timedelta(seconds=10)

JWT_ALGORITHM = "HS256"

JWT_EXPIRATION_DELTA = timedelta(seconds=300)

JWT_AUTH_HEADER_PREFIX = "JWT"

JWT_ISSUER = SERVER_NAME

JWT_REQUIRED_CLAIMS = ["exp", "iat", "sub"]
