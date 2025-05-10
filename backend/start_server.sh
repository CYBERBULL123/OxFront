#!/bin/bash
# Script to start the OxSuite backend server using the virtual environment

# Activate the virtual environment
source venv/bin/activate

# Start the FastAPI server
uvicorn main:app --host 0.0.0.0 --port 8000 --reload
