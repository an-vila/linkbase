from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.database import get_db
from app.core.security import get_current_user
from app.exceptions.user import UserAlreadyExistsError, UserOrPasswordError
from app.models.user import User
from app.schemas.user import TokenResponse, UserCreate, UserLogin, UserResponse
from app.services.user import (
    create_user as create_user_service,
)
from app.services.user import (
    login as login_user_service,
)

router = APIRouter()


@router.get("/users/me", response_model=UserResponse)
def get_user(
    db: Session = Depends(get_db), current_user: User = Depends(get_current_user)
):
    return current_user


@router.post("/users", response_model=UserResponse)
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


@router.post("/auth/login", response_model=TokenResponse)
def login(user_data: UserLogin, db: Session = Depends(get_db)):
    try:
        token_response = login_user_service(db, user_data)
    except UserOrPasswordError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid credentials"
        )

    return token_response
