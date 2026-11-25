from datetime import UTC, datetime, timedelta

import pytest
from sqlalchemy import select

from app.core.security import hash_password, verify_password
from app.exceptions.password_reset_token import InvalidPasswordResetTokenError
from app.models.password_reset_token import PasswordResetToken
from app.schemas.user import (
    ForgotPasswordRequest,
    NewPasswordRequest,
    UserCreate,
)
from app.services.user import (
    create_user,
    forgot_password,
    reset_password,
)


def test_get_current_user_without_token(client):
    response = client.get("/users/me")

    assert response.status_code == 401


def test_get_current_user_with_invalid_token(client):
    response = client.get(
        "/users/me",
        headers={
            "Authorization": "Bearer invalid-token",
        },
    )

    assert response.status_code == 401


def test_get_current_user_with_valid_token(client):
    user_data = {
        "email": "test-auth@example.com",
        "password": "TestPassword123!",
    }

    create_response = client.post("users/", json=user_data)

    assert create_response.status_code == 200

    login_response = client.post("/auth/login", json=user_data)

    assert login_response.status_code == 200

    token = login_response.json()["access_token"]

    response = client.get(
        "/users/me",
        headers={"Authorization": f"Bearer {token}"},
    )

    assert response.status_code == 200
    assert response.json()["email"] == user_data["email"]


def test_forgot_password_creates_reset_token(db):
    user = create_user(
        db,
        UserCreate(
            email="test@example.com",
            password="OldPassword123!",
        ),
    )

    token = forgot_password(
        db,
        ForgotPasswordRequest(email=user.email),
    )

    assert token is not None

    stmt = select(PasswordResetToken).where(
        PasswordResetToken.user_id == user.id
    )
    reset_token = db.scalar(stmt)

    assert reset_token is not None
    assert reset_token.token_prefix == token[:10]
    assert reset_token.token_hash != token
    assert verify_password(token, reset_token.token_hash)
    assert reset_token.used_at is None
    assert reset_token.expires_at > datetime.now(UTC)


def test_forgot_password_nonexistent_email(db):
    token = forgot_password(
        db,
        ForgotPasswordRequest(email="does-not-exist@example.com"),
    )

    assert token is None

    stmt = select(PasswordResetToken)
    reset_token = db.scalar(stmt)

    assert reset_token is None


def test_reset_password_changes_password(db):
    user = create_user(
        db,
        UserCreate(
            email="test@example.com",
            password="OldPassword123!",
        ),
    )

    token = forgot_password(
        db,
        ForgotPasswordRequest(email=user.email),
    )

    assert token is not None

    reset_password(
        db,
        NewPasswordRequest(
            token=token,
            new_password="NewPassword123!",
        ),
    )

    db.refresh(user)

    assert verify_password(
        "NewPassword123!",
        user.password_hash,
    )
    assert not verify_password(
        "OldPassword123!",
        user.password_hash,
    )
    assert user.password_changed_at is not None


def test_reset_password_marks_token_as_used(db):
    user = create_user(
        db,
        UserCreate(
            email="test@example.com",
            password="OldPassword123!",
        ),
    )

    token = forgot_password(
        db,
        ForgotPasswordRequest(email=user.email),
    )

    assert token is not None

    reset_password(
        db,
        NewPasswordRequest(
            token=token,
            new_password="NewPassword123!",
        ),
    )

    stmt = select(PasswordResetToken).where(
        PasswordResetToken.user_id == user.id
    )
    reset_token = db.scalar(stmt)

    assert reset_token is not None
    assert reset_token.used_at is not None


def test_reset_password_rejects_used_token(db):
    user = create_user(
        db,
        UserCreate(
            email="test@example.com",
            password="OldPassword123!",
        ),
    )

    token = forgot_password(
        db,
        ForgotPasswordRequest(email=user.email),
    )

    assert token is not None

    request = NewPasswordRequest(
        token=token,
        new_password="NewPassword123!",
    )

    reset_password(db, request)

    with pytest.raises(InvalidPasswordResetTokenError):
        reset_password(db, request)


def test_reset_password_rejects_invalid_token(db):
    with pytest.raises(InvalidPasswordResetTokenError):
        reset_password(
            db,
            NewPasswordRequest(
                token="invalid-token",
                new_password="NewPassword123!",
            ),
        )


def test_reset_password_rejects_expired_token(db):
    user = create_user(
        db,
        UserCreate(
            email="test@example.com",
            password="OldPassword123!",
        ),
    )

    token = "expired-token"

    reset_token = PasswordResetToken(
        user_id=user.id,
        token_hash=hash_password(token),
        token_prefix=token[:10],
        expires_at=datetime.now(UTC) - timedelta(hours=1),
    )

    db.add(reset_token)
    db.commit()

    with pytest.raises(InvalidPasswordResetTokenError):
        reset_password(
            db,
            NewPasswordRequest(
                token=token,
                new_password="NewPassword123!",
            ),
        )
