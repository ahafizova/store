from flask_security import RoleMixin, UserMixin
from sqlalchemy import Boolean, Column, ForeignKey, Integer, String, Text
from sqlalchemy.orm import backref, relationship

from database import Base


class EntriesUsers(Base):
    __tablename__ = 'entries_users'

    id = Column(Integer(), primary_key=True)
    user_id = Column('user_id', Integer(), ForeignKey('user.id'))
    entry_id = Column('entry_id', Integer(), ForeignKey('entry.id'))


class Entry(Base):
    __tablename__ = 'entry'

    id = Column(Integer(), primary_key=True)
    title = Column(String(63))
    tagline = Column(String(255))
    text = Column(String(4095))
    path = Column(String(255), unique=True)  # TODO уменьшить длину?
    score = Column(Text(), default='{"1": 5}')
    download = Column(Integer(), default=0)

    def __repr__(self):
        return f"Entry(id={self.id!r}, title={self.title!r})"


class RolesUsers(Base):
    __tablename__ = 'roles_users'

    id = Column(Integer(), primary_key=True)
    user_id = Column('user_id', Integer(), ForeignKey('user.id'))
    role_id = Column('role_id', Integer(), ForeignKey('role.id'))


class Role(Base, RoleMixin):
    __tablename__ = 'role'

    id = Column(Integer(), primary_key=True)
    name = Column(String(63), unique=True)  # 80
    description = Column(String(255))

    def __repr__(self):
        return f"Role(id={self.id!r}, name={self.name!r})"


class User(Base, UserMixin):
    __tablename__ = 'user'

    id = Column(Integer(), primary_key=True)
    email = Column(String(255), unique=True)
    password = Column(String(255), nullable=False)
    name = Column(String(127), unique=True)
    active = Column(Boolean())
    fs_uniquifier = Column(String(255), unique=True, nullable=False)

    roles = relationship('Role', secondary='roles_users',
                         backref=backref('user', lazy='dynamic'))
    entries = relationship('Entry', secondary='entries_users',
                           backref=backref('user', lazy='dynamic'))

    def __repr__(self):
        return f"User(id={self.id!r}, email={self.email!r})"
