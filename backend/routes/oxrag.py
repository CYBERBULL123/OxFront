from fastapi import APIRouter, HTTPException, Depends, UploadFile, File, Form
from fastapi.responses import JSONResponse
from typing import Optional, List
import os
import numpy as np
import faiss
import google.generativeai as genai
from PIL import Image
import io
from PyPDF2 import PdfReader
from bs4 import BeautifulSoup
import requests
from auth import get_current_active_user, User
import re
import json
from google.api_core.exceptions import GoogleAPIError

# Create a router
router = APIRouter(
    prefix="/api/oxrag",
    tags=["OxRAG"],
)

# Configure Gemini API Key (get from environment variable in production)
GEMINI_API_KEY = os.getenv("GEMINI_API_KEY", "your-gemini-api-key")
genai.configure(api_key=GEMINI_API_KEY)

# Function to query Gemini model
def query_gemini(context, prompt, image=None):
    try:
        model = genai.GenerativeModel('gemini-2.0-flash')
        if image:
            response = model.generate_content([context + prompt, image])
        else:
            response = model.generate_content(context + prompt)
        
        if hasattr(response, 'candidates') and response.candidates:
            return ' '.join(part.text for part in response.candidates[0].content.parts)
        else:
            return {"error": "Unexpected response format from Gemini API."}
    except GoogleAPIError as e:
        return {"error": f"An error occurred while querying the Gemini API: {str(e)}"}

# Helper functions for text processing
def chunk_text(text, chunk_size=2048):
    return [text[i:i+chunk_size] for i in range(0, len(text), chunk_size)]

def extract_text_from_pdf(pdf_file):
    pdf_reader = PdfReader(pdf_file)
    text = ""
    for page_num in range(len(pdf_reader.pages)):
        text += pdf_reader.pages[page_num].extract_text()
    return text

def extract_text_from_website(url):
    try:
        response = requests.get(url)
        response.raise_for_status()
        soup = BeautifulSoup(response.text, 'html.parser')
        
        # Remove script and style elements
        for script in soup(["script", "style"]):
            script.extract()
            
        # Get text
        text = soup.get_text()
        
        # Break into lines and remove leading and trailing space
        lines = (line.strip() for line in text.splitlines())
        # Break multi-headlines into a line each
        chunks = (phrase.strip() for line in lines for phrase in line.split("  "))
        # Drop blank lines
        text = '\n'.join(chunk for chunk in chunks if chunk)
        
        return text
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Error extracting text from website: {str(e)}")

# Routes
@router.post("/analyze/text")
async def analyze_text(
    text: str,
    query: str,
    current_user: User = Depends(get_current_active_user)
):
    # Process the text and query using RAG techniques
    prompt = (
        "🔍 **Comprehensive Analysis Request** 🔍\n\n"
        "Please analyze the following content and answer the query with detailed and engaging response. Use proper emojis for better visualization:\n\n"
        f"Content: {text}\n\n"
        f"Query: {query}\n\n"
        "📋 **Key Aspects to Include:**\n"
        "1. **Direct Answer**: Provide a clear, concise answer to the query. 🧠\n"
        "2. **Supporting Evidence**: Include relevant information from the content that supports your answer. 📌\n"
        "3. **Context**: Explain any necessary background or context. 🌍\n"
        "4. **Additional Insights**: Provide any additional relevant information that might be helpful. 🌟\n"
    )
    
    response = query_gemini("", prompt)
    return {"response": response}

@router.post("/analyze/pdf")
async def analyze_pdf(
    file: UploadFile = File(...),
    query: str = Form(...),
    current_user: User = Depends(get_current_active_user)
):
    # Check if the file is a PDF
    if not file.filename.lower().endswith('.pdf'):
        raise HTTPException(status_code=400, detail="File must be a PDF")
    
    # Read the PDF content
    contents = await file.read()
    pdf_file = io.BytesIO(contents)
    
    # Extract text from PDF
    text = extract_text_from_pdf(pdf_file)
    
    # Process the text using the analyze_text endpoint
    return await analyze_text(text, query, current_user)

@router.post("/analyze/url")
async def analyze_url(
    url: str,
    query: str,
    current_user: User = Depends(get_current_active_user)
):
    # Extract text from website
    text = extract_text_from_website(url)
    
    # Process the text using the analyze_text endpoint
    return await analyze_text(text, query, current_user)

@router.post("/analyze/image")
async def analyze_image(
    file: UploadFile = File(...),
    query: str = Form(...),
    current_user: User = Depends(get_current_active_user)
):
    # Check if the file is an image
    if not file.filename.lower().endswith(('.png', '.jpg', '.jpeg', '.gif', '.bmp')):
        raise HTTPException(status_code=400, detail="File must be an image (PNG, JPG, JPEG, GIF, BMP)")
    
    # Read the image content
    contents = await file.read()
    image = Image.open(io.BytesIO(contents))
    
    # Process the image and query
    prompt = (
        f"Please analyze this image and answer the following query: {query}\n\n"
        "Provide a detailed response that fully addresses the query based on what you can see in the image."
    )
    
    response = query_gemini("", prompt, image)
    return {"response": response}

# Export the router
def get_router():
    return router
