import { NextAuthOptions } from "next-auth";
import CredentialsProvider from "next-auth/providers/credentials";
import { login } from "@/lib/api";
import { AxiosError } from "axios"; // Import AxiosError

export const authOptions: NextAuthOptions = {
  session: {
    strategy: "jwt",
  },
  providers: [
    CredentialsProvider({
      name: "Credentials",
      credentials: {
        username: { label: "Username", type: "text", placeholder: "Username" },
        password: { label: "Password", type: "password" },
      },
      async authorize(credentials) {
        if (!credentials?.username || !credentials?.password) {
          console.error("Authorize function: Missing username or password.");
          return null;
        }

        try {
          console.log(`Attempting to login user: ${credentials.username} via FastAPI backend.`);
          const backendResponse = await login(credentials.username, credentials.password);
          
          if (backendResponse && backendResponse.access_token) {
            console.log(`Successfully received access_token for user: ${credentials.username}`);
            return {
              id: credentials.username, // Consider if user ID should come from backend
              name: credentials.username, // Consider if name should come from backend
              accessToken: backendResponse.access_token,
            };
          } else {
            console.error("FastAPI login response missing access_token or backendResponse is null/undefined. Response:", backendResponse);
            return null;
          }
        } catch (error) {
          console.error("Authentication error during FastAPI login call in authorize function:", error);
          // If error is an axios error, it might have more details
          const axiosError = error as AxiosError;
          if (axiosError.isAxiosError && axiosError.response) {
            console.error("FastAPI error response status:", axiosError.response.status);
            console.error("FastAPI error response data:", axiosError.response.data);
          }
          return null;
        }
      },
    }),
  ],
  callbacks: {
    async jwt({ token, user }) {
      if (user) {
        // Note: The 'user' object here is what was returned from the 'authorize' callback
        token.accessToken = (user as any).accessToken;
        token.id = user.id;
      }
      return token;
    },
    async session({ session, token }) {
      if (token && session.user) {
        session.user.id = token.id as string;
        // session.user.name = token.name; // name is already part of token from provider
        (session as any).accessToken = token.accessToken as string;
      }
      return session;
    },
  },
  pages: {
    signIn: "/login",
    error: "/login", // Optionally, redirect to a custom error page: /auth/error
  },
};
