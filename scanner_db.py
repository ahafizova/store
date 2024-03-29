from sqlalchemy import Column, create_engine, Integer, String
from sqlalchemy.orm import scoped_session, sessionmaker
from sqlalchemy.ext.declarative import declarative_base

from config import DB_URL


engine = create_engine(DB_URL)
db_session = scoped_session(sessionmaker(autocommit=False,
                                         autoflush=False,
                                         bind=engine))
Base = declarative_base()
Base.query = db_session.query_property()


class Hash(Base):
    __tablename__ = 'hash'

    id = Column(Integer(), primary_key=True)
    name = Column(String(), unique=True, nullable=False)

    def __repr__(self):
        return f"Hash(id={self.id!r}, name={self.name!r})"


def init_db():
    Base.metadata.create_all(bind=engine)
