# Import routes here
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
import os
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

# Import the main FastAPI app
from main import app

# Import route modules
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
