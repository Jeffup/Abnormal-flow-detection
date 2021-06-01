# -*- coding: utf-8 -*-
# tips:

from sqlalchemy import *
from sqlalchemy.orm import sessionmaker
from sqlalchemy.ext.declarative import declarative_base
from config import DB_URI

engine=create_engine(DB_URI, encoding='utf-8')
Base = declarative_base()  # 生成orm基类
create_session = sessionmaker(bind=engine)  # 实例和engine绑定

class IP_COUNT(Base):
    __tablename__ = 'IP_COUNT'
    ip=Column(String(20),primary_key=True)
    mac=Column(String(50))
    first_time=Column(DATETIME)
    last_time=Column(DATETIME)
    attack_count=Column(INTEGER)
    def __repr__(self):
        return '<IP_COUNT {} {}>'.format(self.ip, self.attack_count)
class EVENT_COUNT(Base):
    __tablename__ = 'EVENT_COUNT'
    id = Column(INTEGER, autoincrement=True,primary_key=True)
    ip = Column(String(20))
    # mac = Column(String(50))
    time = Column(DATETIME)
    type = Column(String(10))
    length = Column(INTEGER)
    protocol =Column(String(30))
    # port = Column(INTEGER)
    description = Column(String(100))
    detail = Column(TEXT)
    def __repr__(self):
        return '<EVENT_COUNT {}{}>'.format(self.ip, self.type)
class EVENT_ALARM(Base):
    __tablename__='EVENT_ALARM'
    id = Column(INTEGER, autoincrement=True,primary_key=True)
    ip = Column(String(20))
    time = Column(DATETIME)# sort and expire
    dealtime = Column(DATETIME)
    description = Column(String(100))
    isdeal = Column(String(10)) # ok expire wait

def initdb():
    Base.metadata.create_all(engine)
def dropdb():
    Base.metadata.drop_all(engine)
def recreate():
    Base.metadata.drop_all(engine)
    Base.metadata.create_all(engine)



