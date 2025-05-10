import { NextRequest, NextResponse } from 'next/server'
import { getServerSession } from 'next-auth'
import { authOptions } from '@/lib/auth'

export async function GET(request: NextRequest) {
  const session = await getServerSession(authOptions)
  
  if (!session) {
    return NextResponse.json({ error: 'Unauthorized' }, { status: 401 })
  }
  
  try {
    const searchParams = request.nextUrl.searchParams
    const days = searchParams.get('days') || '30'
    
    const API_BASE_URL = process.env.NEXT_PUBLIC_API_BASE_URL || 'http://localhost:8000'
    const response = await fetch(`${API_BASE_URL}/api/oxintell/scan-history?days=${days}`, {
      headers: {
        'Authorization': `Bearer ${session.accessToken || ''}`
      }
    })
    
    if (!response.ok) {
      throw new Error(`API responded with status: ${response.status}`)
    }
    
    const data = await response.json()
    return NextResponse.json(data)
  } catch (error: any) {
    console.error('Error retrieving scan history:', error)
    return NextResponse.json(
      { error: 'Failed to retrieve scan history', details: error.message },
      { status: 500 }
    )
  }
}
