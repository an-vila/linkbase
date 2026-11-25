import secrets
from datetime import UTC, datetime, timedelta

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.security import (
    create_access_token,
    hash_password,
    verify_password,
)
from app.exceptions.password_reset_token import InvalidPasswordResetTokenError
from app.exceptions.user import (
    InvalidCurrentPasswordError,
    UserAlreadyExistsError,
    UserOrPasswordError,
)
from app.models.password_reset_token import PasswordResetToken
from app.models.user import User
from app.schemas.user import (
    ForgotPasswordRequest,
    NewPasswordRequest,
    PasswordChange,
    TokenResponse,
    UserCreate,
    UserLogin,
)


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


def forgot_password(db: Session, user_data: ForgotPasswordRequest) -> str | None:
    stmt = select(User).where(User.email == user_data.email)
    user = db.scalar(stmt)

    if user is not None:
        token = secrets.token_urlsafe(32)
        prefix = token[:10]

        password_reset_token = PasswordResetToken(
            user_id=user.id,
            token_hash=hash_password(token),
            token_prefix=prefix,
            expires_at=datetime.now(UTC) + timedelta(hours=1),
        )

        db.add(password_reset_token)
        db.commit()

        return token

    return None


def reset_password(db: Session, new_password_request: NewPasswordRequest) -> None:
    raw_token = new_password_request.token
    prefix = raw_token[:10]
    now = datetime.now(UTC)

    stmt = select(PasswordResetToken).where(
        PasswordResetToken.token_prefix == prefix,
        PasswordResetToken.used_at.is_(None),
        PasswordResetToken.expires_at > now,
    )

    saved_token = db.scalar(stmt)

    if saved_token is None or not verify_password(raw_token, saved_token.token_hash):
        raise InvalidPasswordResetTokenError

    hashed_password = hash_password(new_password_request.new_password)

    user_stmt = select(User).where(User.id == saved_token.user_id)
    user = db.scalar(user_stmt)

    if user is None:
        raise InvalidPasswordResetTokenError

    user.password_hash = hashed_password
    user.password_changed_at = now
    saved_token.used_at = now

    db.commit()
