# This file is now a simple wrapper to maintain backward compatibility
# but delegates to app.py for the actual FastAPI application

# Import required items from auth
from fastapi import Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer
import jwt
from auth import (
    User, TokenData, get_user, users_db, 
    SECRET_KEY, ALGORITHM, oauth2_scheme
)

# Import app from app.py
from app import app

# Main entry point
if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)

# Redefine auth functions here for backward compatibility
async def get_current_user(token: str = Depends(oauth2_scheme)):
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        if username is None:
            raise credentials_exception
        token_data = TokenData(username=username)
    except jwt.PyJWTError:
        raise credentials_exception
    user = get_user(users_db, username=token_data.username)
    if user is None:
        raise credentials_exception
    return user

async def get_current_active_user(current_user: User = Depends(get_current_user)):
    if current_user.disabled:
        raise HTTPException(status_code=400, detail="Inactive user")
    return current_user

# For backward compatibility, re-export auth models and functions
from auth import (
    User, Token, TokenData, authenticate_user, create_access_token,
    ACCESS_TOKEN_EXPIRE_MINUTES, timedelta, datetime, BaseModel
)
