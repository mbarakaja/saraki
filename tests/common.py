from sqlalchemy import Column, Integer, String, DateTime, Boolean
from sqlalchemy import ForeignKey, func
from sqlalchemy.orm import relationship

from saraki.model import BaseModel


class Dummy(BaseModel):
    __tablename__ = 'dummy'

    id = Column(Integer, primary_key=True)


class Person(BaseModel):

    __tablename__ = 'person'

    id = Column(Integer, primary_key=True)

    firstname = Column(String, nullable=False)

    lastname = Column(String, nullable=False)

    age = Column(Integer, nullable=False)


class Product(BaseModel):

    __tablename__ = 'product'

    id = Column(Integer, primary_key=True)

    name = Column(String(120), nullable=False)

    color = Column(String, default='white')

    price = Column(Integer, default=0)

    created_at = Column(DateTime, nullable=False, default=func.now())

    updated_at = Column(DateTime, nullable=False, server_default=func.now())

    enabled = Column(Boolean, default=False)


class Order(BaseModel):

    __tablename__ = 'order'

    id = Column(Integer, primary_key=True)

    customer_id = Column(Integer, ForeignKey('person.id'), nullable=False)

    lines = relationship('OrderLine')

    customer = relationship('Person', uselist=False)


class OrderLine(BaseModel):

    __tablename__ = 'order_line'

    id = Column(Integer, primary_key=True)

    order_id = Column(Integer, ForeignKey('order.id'), nullable=False)

    product_id = Column(Integer, ForeignKey('product.id'), nullable=False)

    unit_price = Column(Integer, nullable=False)

    quantity = Column(Integer, default=1, nullable=False)
