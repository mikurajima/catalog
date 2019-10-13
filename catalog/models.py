#!/usr/bin/env python3
# -*- coding:utf-8 -*-
from sqlalchemy import Column, Integer, String
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import relationship, sessionmaker
from sqlalchemy import create_engine
from passlib.apps import custom_app_context as pwd_context
import random
import string
from itsdangerous import(
    TimedJSONWebSignatureSerializer as Serializer,
    BadSignature, SignatureExpired)

Base = declarative_base()
secret_key = ''.join(random.choice(
    string.ascii_uppercase + string.digits) for x in range(32))


class User(Base):
    __tablename__ = 'user'
    id = Column(Integer, primary_key=True)
    username = Column(String(32), index=True)
    picture = Column(String(120))
    email = Column(String(100))
    password_hash = Column(String(64))

    def hash_password(self, password):
        self.password_hash = pwd_context.encrypt(password)

    def verify_password(self, password):
        return pwd_context.verify(password, self.password_hash)

    def generate_auth_token(self, expiration=600):
        s = Serializer(secret_key, expires_in=expiration)
        return s.dumps({'id': self.id})

    @staticmethod
    def verify_auth_token(token):
        s = Serializer(secret_key)
        try:
            data = s.loads(token)
        except SignatureExpired:
            # Valid Token, but expired
            return None
        except BadSignature:
            # Invalid Token
            return None
        user_id = data['id']
        return user_id


class Items(Base):
    __tablename__ = 'items'
    id = Column(Integer, primary_key=True)
    item_name = Column(String(30))
    category_id = Column(Integer)
    description = Column(String(700))
    registered_at = Column(String(30))
    registered_user_id = Column(Integer)

    @property
    def serialize(self):
        """Return object data in easily serializeable format"""
        return {
            'item_name': self.item_name,
            # 'picture' : self.picture,
            'category_id': self.category_id,
            'description': self.description,
            'registered_at': self.registered_at,
            'registered_user_id': self.registered_user_id
        }


class Category(Base):
    __tablename__ = 'category'
    id = Column(Integer, primary_key=True)
    category_name = Column(String(30))
    registered_at = Column(String(30))
    registered_user_id = Column(Integer)

    @property
    def serialize(self):
        """Return object data in easily serializeable format"""
        return {
            'id': self.id,
            'category_name': self.category_name,
            'registered_at': self.registered_at,
            'registered_user_id': self.registered_user_id
        }


dialect = "mysql"
driver = "pymysql"
username = "grader"
password = "Shinskau050$"
host = "127.0.0.1"
database = "udacity1"
charset_type = "utf8"
db_url = "{}+{}://{}:{}@{}/{}?charset={}".format(
    dialect, driver, username, password, host, database, charset_type)
engine = create_engine(db_url, echo=True)

Base.metadata.create_all(engine)
