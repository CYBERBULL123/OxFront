import { NextRequest, NextResponse } from 'next/server';

export async function POST(request: NextRequest) {
  // Create a response
  const response = NextResponse.json(
    { success: true },
    { status: 200 }
  );
  
  // Remove the auth cookie
  response.cookies.delete('auth_token');
  
  return response;
}
