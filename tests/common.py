from sqlalchemy import Column, Integer, String, DateTime, Boolean
from sqlalchemy import func

from saraki.model import BaseModel


class Product(BaseModel):

    __tablename__ = 'product'

    id = Column(Integer, primary_key=True)

    name = Column(String(120), nullable=False)

    color = Column(String)

    price = Column(Integer, default=0)

    created_at = Column(DateTime, nullable=False, default=func.now())

    updated_at = Column(DateTime, nullable=False, server_default=func.now())

    enabled = Column(Boolean)
