from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from app.core.config import settings

engine = create_engine(settings.database_url, pool_pre_ping=True)

SessionFactory = sessionmaker()
SessionFactory.configure(bind=engine)


def get_db():
    with SessionFactory() as db:
        yield db
