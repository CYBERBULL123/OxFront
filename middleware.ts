import { NextResponse } from 'next/server';
import type { NextRequest } from 'next/server';

// Paths that don't require authentication
const publicPaths = ['/login', '/signup', '/api/auth'];

// Helper function to check if the path is public
const isPublicPath = (path: string) => {
  return publicPaths.some(publicPath => 
    path === publicPath || path.startsWith(`${publicPath}/`)
  );
};

// Middleware function to protect routes
export default async function middleware(request: NextRequest) {
  const path = request.nextUrl.pathname;
  
  // Check if the path is public
  if (isPublicPath(path)) {
    return NextResponse.next();
  }

  // Check for JWT token in cookies
  const token = request.cookies.get('auth_token')?.value;
  
  // If no token and trying to access protected route, redirect to login
  if (!token && !isPublicPath(path)) {
    const url = new URL('/login', request.url);
    // Add the original URL as a query parameter for redirect after login
    url.searchParams.set('callbackUrl', encodeURI(request.url));
    return NextResponse.redirect(url);
  }
  
  // Allow access to protected routes if token exists
  // Note: This doesn't validate the token - that should happen in your API routes
  // For more security, you could make a call to your backend to validate the token
  return NextResponse.next();
}

// Configure the middleware to run on specific paths
export const config = {
  matcher: [
    // Match all routes except static files, images, and other exceptions
    '/((?!_next/static|_next/image|favicon.ico).*)',
  ],
};
