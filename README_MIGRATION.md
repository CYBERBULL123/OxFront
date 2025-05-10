# OxSuite

OxSuite is a comprehensive security and AI tool suite that has been migrated from a Streamlit application to a modern Next.js frontend with a FastAPI backend.

## Architecture

The application now uses a modern stack:

- **Frontend**: Next.js with TypeScript, Tailwind CSS, and Framer Motion
- **Backend**: FastAPI with Python
- **Authentication**: JWT-based authentication with NextAuth.js

## Setup Instructions

### Backend Setup

1. Navigate to the backend directory:
   ```bash
   cd backend
   ```

2. Create a virtual environment:
   ```bash
   python -m venv venv
   source venv/bin/activate  # On Windows: venv\Scripts\activate
   ```

3. Install the dependencies:
   ```bash
   pip install -r requirements.txt
   ```

4. Set up environment variables:
   - Create a `.env` file in the backend directory
   - Add your Gemini API key:
     ```
     GEMINI_API_KEY=your-api-key-here
     SECRET_KEY=your-jwt-secret-key
     ```

5. Run the backend server:
   ```bash
   uvicorn app:app --reload --port 8000
   ```

### Frontend Setup

1. Install the dependencies:
   ```bash
   npm install
   ```

2. Set up environment variables:
   - Update `.env.local` with the appropriate values:
     ```
     NEXTAUTH_URL=http://localhost:3000
     NEXTAUTH_SECRET=your-nextauth-secret-here
     NEXT_PUBLIC_API_BASE_URL=http://localhost:8000
     ```

3. Run the development server:
   ```bash
   npm run dev
   ```

4. Build for production:
   ```bash
   npm run build
   npm start
   ```

## Features

- **Authentication**: User login/signup with JWT authentication
- **OxRAG**: Research Assistant for analyzing text, PDFs, URLs, and images
- **OxImage**: Image generation and manipulation using AI
- **Responsive Design**: Works on mobile, tablet, and desktop devices

## Migration Notes

This project has been migrated from a Streamlit-based application to a modern Next.js + FastAPI architecture. The benefits include:

1. **Better User Experience**: Modern, fast, and responsive UI with client-side routing
2. **Scalability**: Separate backend and frontend for better scaling
3. **Performance**: Server-side rendering and static generation for faster page loads
4. **Maintainability**: TypeScript for better type safety and code quality

## API Endpoints

### Authentication
- POST `/token`: Get JWT token

### OxRAG
- POST `/api/oxrag/analyze/text`: Analyze text
- POST `/api/oxrag/analyze/pdf`: Analyze PDF
- POST `/api/oxrag/analyze/url`: Analyze URL
- POST `/api/oxrag/analyze/image`: Analyze image

### OxImage
- POST `/api/oximage/generate`: Generate image
- POST `/api/oximage/enhance`: Enhance image
- POST `/api/oximage/analyze`: Analyze image

## Development

1. Backend API development:
   - Add new endpoints in the respective route files in `backend/routes/`
   - Update the main `app.py` to include new routes

2. Frontend development:
   - Add new API client functions in `lib/api.ts`
   - Create new pages in the `app/` directory
   - Add UI components in the `components/` directory

## Deployment

For production deployment:

1. **Backend**: Deploy to a service like Heroku, Azure, or AWS
2. **Frontend**: Deploy to Vercel, Netlify, or any hosting service
3. **Environment Variables**: Set all the necessary environment variables in your deployment platform
