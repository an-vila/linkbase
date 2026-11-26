from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import EmailStr
from sqlalchemy.orm import Session

from app.core.database import get_db
from app.core.security import get_current_user
from app.exceptions.password_reset_token import InvalidPasswordResetTokenError
from app.exceptions.user import (
    InvalidCurrentPasswordError,
    UserAlreadyExistsError,
    UserOrPasswordError,
)
from app.models.user import User
from app.schemas.user import (
    ForgotPasswordRequest,
    NewPasswordRequest,
    PasswordChange,
    TokenResponse,
    UserCreate,
    UserLogin,
    UserResponse,
)
from app.services.user import change_password as change_password_service
from app.services.user import (
    create_user as create_user_service,
)
from app.services.user import forgot_password as forgot_password_service
from app.services.user import (
    login as login_user_service,
)
from app.services.user import reset_password as reset_password_service

router = APIRouter(prefix="/users",
                   tags=["Auth"]
                   )


@router.get("/me", response_model=UserResponse)
def get_user(
    db: Session = Depends(get_db), current_user: User = Depends(get_current_user)
):
    return current_user


@router.post("", response_model=UserResponse)
def create_user(
    user_data: UserCreate,
    db: Session = Depends(get_db),
):
    try:
        new_user = create_user_service(db, user_data)
    except UserAlreadyExistsError:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT, detail="Email already registered"
        )
    return new_user


@router.post("/login", response_model=TokenResponse)
def login(user_data: UserLogin, db: Session = Depends(get_db)):
    try:
        token_response = login_user_service(db, user_data)
    except UserOrPasswordError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid credentials"
        )

    return token_response


@router.post("/change-password")
def change_password(
    password_data: PasswordChange,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    try:
        change_password_service(db, current_user, password_data)
    except InvalidCurrentPasswordError:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Current password does not match",
        )

    return {"message": "Password changed successfully"}


@router.post("/forgot-password")
def forgot_password(user_data: ForgotPasswordRequest, db: Session = Depends(get_db)):
    forgot_password_service(db, user_data)

    return {
        "message": "If the email is registered, a password reset link has been sent"
    }


@router.post("/reset-password")
def reset_password(
    new_password_request: NewPasswordRequest, db: Session = Depends(get_db)
):
    try:
        reset_password_service(db, new_password_request)
    except InvalidPasswordResetTokenError:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid or expired reset token",
        )

    return {"message": "Password reset successfully"}
