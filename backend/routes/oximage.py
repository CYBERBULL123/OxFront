from fastapi import APIRouter, HTTPException, Depends, UploadFile, File, Form
from fastapi.responses import JSONResponse
from typing import Optional, List
import os
import google.generativeai as genai
from PIL import Image
import io
from main import get_current_active_user, User
from google.api_core.exceptions import GoogleAPIError
import base64

# Create a router
router = APIRouter(
    prefix="/api/oximage",
    tags=["OxImage"],
)

# Configure Gemini API Key (get from environment variable in production)
GEMINI_API_KEY = os.getenv("GEMINI_API_KEY", "your-gemini-api-key")
genai.configure(api_key=GEMINI_API_KEY)

# Function to query Gemini model for text-to-image generation
def generate_image(prompt):
    try:
        model = genai.GenerativeModel('gemini-1.5-flash')
        response = model.generate_content(
            prompt,
            generation_config={
                "temperature": 0.9,
                "top_p": 0.95,
                "top_k": 64,
                "max_output_tokens": 8192,
                "response_mime_type": "image/png"
            }
        )
        if hasattr(response, 'candidates') and response.candidates:
            # Return the image data from the response
            if hasattr(response.candidates[0].content, 'parts'):
                for part in response.candidates[0].content.parts:
                    if hasattr(part, 'inline_data') and part.inline_data:
                        # Get the base64 encoded image data
                        return part.inline_data.data
        return None
    except GoogleAPIError as e:
        raise HTTPException(status_code=500, detail=f"An error occurred while generating the image: {str(e)}")

# Function to enhance image
def enhance_image(image, prompt):
    try:
        model = genai.GenerativeModel('gemini-1.5-pro')
        response = model.generate_content([image, prompt])
        if hasattr(response, 'candidates') and response.candidates:
            # Return the response text
            return ' '.join(part.text for part in response.candidates[0].content.parts)
        return None
    except GoogleAPIError as e:
        raise HTTPException(status_code=500, detail=f"An error occurred while enhancing the image: {str(e)}")

# Routes
@router.post("/generate")
async def generate_image_route(
    prompt: str,
    current_user: User = Depends(get_current_active_user)
):
    enhanced_prompt = (
        f"Generate a high-quality, detailed image based on the following description: {prompt}. "
        "The image should be visually appealing with good lighting, composition, and detail."
    )
    
    image_data = generate_image(enhanced_prompt)
    if image_data:
        return {"image_data": image_data}
    else:
        raise HTTPException(status_code=500, detail="Failed to generate image")

@router.post("/enhance")
async def enhance_image_route(
    file: UploadFile = File(...),
    prompt: str = Form(...),
    current_user: User = Depends(get_current_active_user)
):
    # Check if the file is an image
    if not file.filename.lower().endswith(('.png', '.jpg', '.jpeg', '.gif', '.bmp')):
        raise HTTPException(status_code=400, detail="File must be an image (PNG, JPG, JPEG, GIF, BMP)")
    
    # Read the image content
    contents = await file.read()
    image = Image.open(io.BytesIO(contents))
    
    # Process the image and prompt
    enhanced_prompt = f"Enhance this image according to the following instructions: {prompt}"
    
    response = enhance_image(image, enhanced_prompt)
    if response:
        return {"response": response}
    else:
        raise HTTPException(status_code=500, detail="Failed to enhance image")

@router.post("/analyze")
async def analyze_image_route(
    file: UploadFile = File(...),
    prompt: str = Form(...),
    current_user: User = Depends(get_current_active_user)
):
    # Check if the file is an image
    if not file.filename.lower().endswith(('.png', '.jpg', '.jpeg', '.gif', '.bmp')):
        raise HTTPException(status_code=400, detail="File must be an image (PNG, JPG, JPEG, GIF, BMP)")
    
    # Read the image content
    contents = await file.read()
    image = Image.open(io.BytesIO(contents))
    
    # Process the image and prompt
    analysis_prompt = (
        f"Please analyze this image and respond to the following: {prompt}\n\n"
        "Provide a detailed analysis of the image content, relevant features, and address the prompt specifically."
    )
    
    model = genai.GenerativeModel('gemini-1.5-pro')
    response = model.generate_content([image, analysis_prompt])
    
    if hasattr(response, 'candidates') and response.candidates:
        return {"response": ' '.join(part.text for part in response.candidates[0].content.parts)}
    else:
        raise HTTPException(status_code=500, detail="Failed to analyze image")

# Export the router
def get_router():
    return router
