# OxSuite Migration Guide

This guide provides a step-by-step breakdown of migrating OxSuite from Streamlit to a modern Next.js frontend with FastAPI backend.

## Why Migrate?

The migration offers several significant advantages:

1. **Better User Experience**: Modern, responsive UI with client-side navigation
2. **Scalability**: Separate backend and frontend for better service scalability
3. **Performance**: Server-side rendering and static generation capabilities
4. **Maintainability**: TypeScript for better type safety and code organization
5. **Ecosystem**: Access to a vast ecosystem of React components and libraries

## Architecture Overview

The new architecture consists of:

- **Frontend**: Next.js 14+ with TypeScript, Tailwind CSS, and Framer Motion
- **Backend**: FastAPI with Python 3.10+
- **Authentication**: JWT-based auth with NextAuth.js
- **API Communication**: Axios for HTTP requests

## Migration Steps

### 1. Setting Up the Backend

The backend is implemented as a FastAPI application with the following structure:

```
backend/
├── app.py              # Main application entry point
├── main.py             # Core FastAPI app with auth
├── requirements.txt    # Python dependencies
└── routes/             # API route modules
    ├── __init__.py
    ├── oximage.py      # OxImage endpoints
    └── oxrag.py        # OxRAG endpoints
```

Key changes:
- Extracted core functionality from Streamlit into FastAPI endpoints
- Implemented JWT authentication
- Created modular API routes for each tool

### 2. Setting Up the Frontend

The frontend is implemented as a Next.js application with the following structure:

```
app/                  # Next.js app router
├── api/              # Next.js API routes
├── dashboard/        # Dashboard page
├── login/            # Authentication pages
├── oximage/          # Tool-specific pages
├── oxrag/
├── layout.tsx        # Main layout
components/           # Reusable UI components
lib/                  # Shared utilities
├── api.ts            # API client
├── auth.ts           # Auth configuration
├── utils.ts          # Helper functions
public/               # Static assets
```

Key changes:
- Moved from Streamlit's Python-based UI to React components
- Implemented authentication with NextAuth.js
- Structured the app using Next.js App Router

### 3. Migrating Authentication

The authentication system was migrated from Streamlit's simple username/password system to a JWT-based auth flow:

1. **Backend**: Implemented JWT token generation in FastAPI
2. **Frontend**: Set up NextAuth.js with credentials provider
3. **Protection**: Created middleware to protect routes

### 4. Migrating OxRAG

OxRAG functionality was migrated to:

1. **Backend API**: Created endpoints for text, PDF, URL, and image analysis
2. **Frontend UI**: Built a modern interface with tabs for different content types
3. **Integration**: Connected the frontend to the backend APIs

### 5. Migrating OxImage

OxImage functionality was migrated to:

1. **Backend API**: Created endpoints for image generation and enhancement
2. **Frontend UI**: Built an intuitive interface for image generation and editing
3. **Integration**: Connected the UI to the backend API

### 6. Styling and UI Components

The UI was completely redesigned with:

1. **Tailwind CSS**: For responsive, utility-first styling
2. **Framer Motion**: For smooth animations and transitions
3. **Custom Components**: Built reusable UI components

## Running Both Systems

### Development Setup

Run the backend and frontend separately during development:

```bash
# Terminal 1 - Backend
cd backend
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
pip install -r requirements.txt
uvicorn app:app --reload --port 8000

# Terminal 2 - Frontend
npm install
npm run dev
```

### Production Setup

For production, you can use Docker Compose:

```bash
docker-compose up -d
```

## Migration Challenges

Some challenges encountered during migration:

1. **State Management**: Moving from Streamlit's session state to React state
2. **Authentication**: Implementing a secure auth system with JWT
3. **File Handling**: Managing file uploads and processing between frontend and backend
4. **API Integration**: Ensuring seamless communication between Next.js and FastAPI

## Next Steps

Future improvements could include:

1. **Database Integration**: Adding a database for persistent storage
2. **Additional Tools**: Migrating more tools from the Streamlit version
3. **Performance Optimization**: Implementing caching and optimizing API calls
4. **Enhanced Security**: Adding more security features like rate limiting and CSRF protection
