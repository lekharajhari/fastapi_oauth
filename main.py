from datetime import datetime, timedelta, timezone
from typing import Annotated
import secrets
from fastapi.security import OAuth2PasswordBearer
import jwt
from fastapi import Depends, FastAPI, HTTPException, status
from jwt.exceptions import InvalidTokenError
from pydantic import BaseModel

# Dictionary to store temporary secret keys for users (in-memory)
session_secrets = {}

# JWT Algorithm
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 1


class Token(BaseModel):
    access_token: str
    token_type: str


class TokenData(BaseModel):
    secret_key: str | None = None


class User(BaseModel):
    secret_key: str


# OAuth2PasswordBearer no longer needs username/password, but we still use the token mechanism
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

app = FastAPI()


def create_access_token(secret_key: str, expires_delta: timedelta | None = None):
    """Creates JWT token with dynamic secret key."""
    to_encode = {"sub": "session", "secret_key": secret_key}
    if expires_delta:
        expire = datetime.now(timezone.utc) + expires_delta
    else:
        expire = datetime.now(timezone.utc) + timedelta(minutes=1)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, secret_key, algorithm=ALGORITHM)
    return encoded_jwt


async def get_current_user(token: Annotated[str, Depends(oauth2_scheme)]):
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        # Decode token using the stored session secret
        payload = jwt.decode(token, options={"verify_signature": False}, algorithms=[ALGORITHM])
        secret_key = payload.get("secret_key")
        if secret_key is None or secret_key not in session_secrets:
            raise credentials_exception

        # Verify the token using the dynamic secret key stored in session
        jwt.decode(token, session_secrets[secret_key], algorithms=[ALGORITHM])
        token_data = TokenData(secret_key=secret_key)
    except InvalidTokenError:
        raise credentials_exception
    return User(secret_key=token_data.secret_key)


@app.post("/token")
async def login_for_access_token() -> Token:
    """Login endpoint that generates a new secret key and token."""
    # Generate a dynamic secret key for this session
    secret_key = secrets.token_hex(32)
    session_secrets[secret_key] = secret_key

    # Create access token with the secret key
    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(secret_key=secret_key, expires_delta=access_token_expires)

    return Token(access_token=access_token, token_type="bearer")


@app.get("/users/me/", response_model=User)
async def read_users_me(
    current_user: Annotated[User, Depends(get_current_user)],
):
    """Return the current user based on their session secret."""
    return current_user


@app.get("/users/me/items/")
async def read_own_items(
    current_user: Annotated[User, Depends(get_current_user)],
):
    """Return items belonging to the current user."""
    return [{"item_id": "Foo", "owner": current_user.secret_key}]
