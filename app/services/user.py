from datetime import UTC, datetime

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.security import create_access_token, hash_password, verify_password
from app.exceptions.user import (
    InvalidCurrentPasswordError,
    UserAlreadyExistsError,
    UserOrPasswordError,
)
from app.models.user import User
from app.schemas.user import PasswordChange, TokenResponse, UserCreate, UserLogin


def create_user(db: Session, user_data: UserCreate) -> User:
    stmt = select(User.id).where(User.email == user_data.email)

    if db.scalar(stmt) is not None:
        raise UserAlreadyExistsError()

    hashed_password = hash_password(user_data.password)

    user = User(
        email=user_data.email,
        password_hash=hashed_password,
        first_name=user_data.first_name,
        last_name=user_data.last_name,
    )

    db.add(user)
    db.commit()
    db.refresh(user)

    return user


def login(db: Session, user_data: UserLogin) -> TokenResponse:
    stmt = select(User).where(User.email == user_data.email)
    user = db.scalar(stmt)

    if user is None or not verify_password(user_data.password, user.password_hash):
        raise UserOrPasswordError()

    token = create_access_token(user.id)

    return TokenResponse(access_token=token, token_type="bearer")


def change_password(db: Session, user: User, password_data: PasswordChange) -> None:
    if not verify_password(password_data.current_password, user.password_hash):
        raise InvalidCurrentPasswordError()

    user.password_hash = hash_password(password_data.new_password)
    user.password_changed_at = datetime.now(UTC)

    db.commit()
