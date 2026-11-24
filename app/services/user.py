from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.security import create_access_token, hash_password, verify_password
from app.exceptions.user import UserAlreadyExistsError, UserOrPasswordError
from app.models.user import User
from app.schemas.user import TokenResponse, UserCreate, UserLogin


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

    return TokenResponse(
            access_token=token,
            token_type="bearer"
            )
