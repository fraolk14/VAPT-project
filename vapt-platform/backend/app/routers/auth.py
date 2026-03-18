from fastapi import APIRouter, Depends, HTTPException, status
from fastapi.security import OAuth2PasswordRequestForm
from sqlalchemy.orm import Session

from app.database import get_db
from app.models.user import User
from app.schemas.auth import TokenResponse, UserCreate, UserResponse
from app.services.auth import create_access_token, hash_password, verify_password
from app.services.ldap_auth import authenticate_ldap
from app.services.security import get_current_user

router = APIRouter(prefix="/auth", tags=["Auth"])


@router.post("/register", response_model=UserResponse, status_code=status.HTTP_201_CREATED)
def register_user(payload: UserCreate, db: Session = Depends(get_db)):
    existing = db.query(User).filter(
        (User.username == payload.username) | (User.email == payload.email)
    ).first()
    if existing:
        raise HTTPException(status_code=409, detail="User already exists")

    user = User(
        username=payload.username,
        email=payload.email,
        password_hash=hash_password(payload.password),
        role=payload.role,
        auth_source="local",
    )
    db.add(user)
    db.commit()
    db.refresh(user)
    return user


@router.post("/login", response_model=TokenResponse)
def login(
    form_data: OAuth2PasswordRequestForm = Depends(),
    db: Session = Depends(get_db),
):
    user = db.query(User).filter(User.username == form_data.username).first()

    if user:
        if user.password_hash != "LDAP" and not verify_password(
            form_data.password, user.password_hash
        ):
            raise HTTPException(status_code=401, detail="Invalid credentials")
    else:
        ldap_user = authenticate_ldap(form_data.username, form_data.password)
        if not ldap_user:
            raise HTTPException(status_code=401, detail="Invalid credentials")

        user = User(
            username=ldap_user["username"],
            email=ldap_user.get("email", f"{ldap_user['username']}@directory.local"),
            role=ldap_user["role"],
            password_hash="LDAP",
            auth_source="ldap",
        )
        db.add(user)
        db.commit()
        db.refresh(user)

    access_token, expires_in = create_access_token({"sub": user.username, "role": user.role})
    return {
        "access_token": access_token,
        "token_type": "bearer",
        "expires_in": expires_in,
    }


@router.get("/me", response_model=UserResponse)
def read_profile(current_user: User = Depends(get_current_user)):
    return current_user
