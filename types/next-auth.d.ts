import { DefaultSession } from 'next-auth'

declare module 'next-auth' {
  interface Session extends DefaultSession {
    accessToken?: string
    user?: {
      id?: string
      name?: string
      email?: string
      role?: string
    }
  }
  
  interface User {
    id: string
    name?: string
    accessToken?: string
    role?: string
  }
}

declare module 'next-auth/jwt' {
  interface JWT {
    accessToken?: string
    id?: string
    role?: string
  }
}
