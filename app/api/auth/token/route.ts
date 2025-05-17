import { NextRequest, NextResponse } from 'next/server';

export async function POST(request: NextRequest) {
  try {
    const { token } = await request.json();
    
    if (!token) {
      return NextResponse.json(
        { error: 'Token is required' },
        { status: 400 }
      );
    }
    
    // Create the response
    const response = NextResponse.json(
      { success: true },
      { status: 200 }
    );
    
    // Set the token in an HTTP-only cookie
    // Max-Age is set to 7 days (in seconds)
    response.cookies.set({
      name: 'auth_token',
      value: token,
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      maxAge: 60 * 60 * 24 * 7, // 7 days
      path: '/',
    });
    
    return response;
  } catch (error) {
    console.error('Error setting auth cookie:', error);
    return NextResponse.json(
      { error: 'Failed to authenticate' },
      { status: 500 }
    );
  }
}

export async function DELETE(request: NextRequest) {
  // Create a response
  const response = NextResponse.json(
    { success: true },
    { status: 200 }
  );
  
  // Remove the auth cookie
  response.cookies.delete('auth_token');
  
  return response;
}
