from database import Base
from flask_security import UserMixin, RoleMixin
from sqlalchemy.orm import relationship, backref
from sqlalchemy import Boolean, Column, Integer, String, ForeignKey


class EntriesUsers(Base):                       # TODO проверить
    __tablename__ = 'entries_users'
    id = Column(Integer(), primary_key=True)
    user_id = Column('user_id', Integer(), ForeignKey('user.id'))
    entry_id = Column('entry_id', Integer(), ForeignKey('entry.id'))


class Entry(Base, RoleMixin):                   # TODO проверить RoleMixin??
    __tablename__ = 'entry'
    id = Column(Integer(), primary_key=True)
    title = Column(String(80), unique=True)
    text = Column(String(255))


class RolesUsers(Base):
    __tablename__ = 'roles_users'
    id = Column(Integer(), primary_key=True)
    user_id = Column('user_id', Integer(), ForeignKey('user.id'))
    role_id = Column('role_id', Integer(), ForeignKey('role.id'))


class Role(Base, RoleMixin):
    __tablename__ = 'role'
    id = Column(Integer(), primary_key=True)
    name = Column(String(80), unique=True)
    description = Column(String(255))


class User(Base, UserMixin):
    __tablename__ = 'user'
    id = Column(Integer, primary_key=True)
    email = Column(String(255), unique=True)
    password = Column(String(255), nullable=False)
    active = Column(Boolean())
    fs_uniquifier = Column(String(255), unique=True, nullable=False)

    # TODO если не робит, то попробовать user / users
    roles = relationship('Role', secondary='roles_users',
                         backref=backref('user', lazy='dynamic'))
    entries = relationship('Entry', secondary='entries_users',
                           backref=backref('user', lazy='dynamic'))