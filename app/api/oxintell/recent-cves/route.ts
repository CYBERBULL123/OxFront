import { NextRequest, NextResponse } from 'next/server';
import { getToken } from 'next-auth/jwt';

export async function GET(req: NextRequest) {
  try {
    const token = await getToken({ req });
    
    if (!token) {
      return new NextResponse(JSON.stringify({ error: 'Unauthorized' }), {
        status: 401,
        headers: { 'Content-Type': 'application/json' },
      });
    }

    // Extract query parameters
    const url = new URL(req.url);
    const pubStartDate = url.searchParams.get('pub_start_date');
    const pubEndDate = url.searchParams.get('pub_end_date');
    const maxResults = url.searchParams.get('max_results') || '10';

    let apiUrl = `${process.env.BACKEND_URL}/api/oxintell/recent-cves?max_results=${maxResults}`;
    
    if (pubStartDate) {
      apiUrl += `&pub_start_date=${pubStartDate}`;
    }
    
    if (pubEndDate) {
      apiUrl += `&pub_end_date=${pubEndDate}`;
    }
    
    const response = await fetch(apiUrl, {
      method: 'GET',
      headers: {
        'Authorization': `Bearer ${token.accessToken}`,
        'Content-Type': 'application/json',
      },
    });

    if (!response.ok) {
      const errorText = await response.text();
      return new NextResponse(JSON.stringify({ error: errorText }), {
        status: response.status,
        headers: { 'Content-Type': 'application/json' },
      });
    }

    const data = await response.json();
    return new NextResponse(JSON.stringify(data), {
      status: 200,
      headers: { 'Content-Type': 'application/json' },
    });
  } catch (error) {
    console.error('Error in recent CVEs route:', error);
    return new NextResponse(JSON.stringify({ error: 'Internal server error' }), {
      status: 500,
      headers: { 'Content-Type': 'application/json' },
    });
  }
}
