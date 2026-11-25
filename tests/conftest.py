import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine, delete
from sqlalchemy.orm import sessionmaker

from app.core.config import settings
from app.core.database import get_db
from app.main import app
from app.models.password_reset_token import PasswordResetToken
from app.models.user import User

test_engine = create_engine(
    settings.test_database_url,
    pool_pre_ping=True,
)

TestSessionFactory = sessionmaker(bind=test_engine)


@pytest.fixture
def db():
    with TestSessionFactory() as db:
        db.execute(delete(PasswordResetToken))
        db.execute(delete(User))
        db.commit()

        yield db


@pytest.fixture
def client(db):
    def override_get_db():
        yield db

    app.dependency_overrides[get_db] = override_get_db

    with TestClient(app) as client:
        yield client

    app.dependency_overrides.clear()
