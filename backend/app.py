# Import libraries
from fastapi import FastAPI, Depends, HTTPException, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import OAuth2PasswordRequestForm
import os
from dotenv import load_dotenv
from datetime import datetime, timedelta

# Load environment variables
load_dotenv()

# Import auth module
from auth import (
    User, Token, authenticate_user, create_access_token, 
    get_current_active_user, users_db, ACCESS_TOKEN_EXPIRE_MINUTES
)

# Initialize FastAPI app
app = FastAPI(
    title="OxSecure Suite API",
    description="API for OxSecure Suite - Security tools and AI services",
    version="1.0.0"
)

# Setup CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:3000"],  # Update this with your Next.js frontend URL in production
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Authentication routes
@app.post("/token", response_model=Token)
async def login_for_access_token(form_data: OAuth2PasswordRequestForm = Depends()):
    user = authenticate_user(users_db, form_data.username, form_data.password)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(
        data={"sub": user.username}, expires_delta=access_token_expires
    )
    return {"access_token": access_token, "token_type": "bearer"}

@app.get("/users/me", response_model=User)
async def read_users_me(current_user: User = Depends(get_current_active_user)):
    return current_user

# Health check endpoint
@app.get("/health")
async def health_check():
    return {"status": "healthy", "timestamp": datetime.now().isoformat()}

# Example of a protected route
@app.get("/protected-data")
async def get_protected_data(current_user: User = Depends(get_current_active_user)):
    return {
        "data": "This is protected data that only authenticated users can see",
        "user": current_user.username
    }

# Defer importing route modules to avoid circular imports
from routes import oxrag, oximage, oxintell

# Register routes
app.include_router(oxrag.get_router())
app.include_router(oximage.get_router())
app.include_router(oxintell.get_router())

# Add more routes for other tools as needed

if __name__ == "__main__":
    import uvicorn
    port = int(os.getenv("PORT", 8000))
    uvicorn.run("app:app", host="0.0.0.0", port=port, reload=True)
