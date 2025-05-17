'use client';

import React, { createContext, useContext, useState, useEffect } from 'react';
import { getToken } from '@/lib/api';

// Define the shape of our auth context
interface AuthContextType {
  isAuthenticated: boolean;
  loading: boolean;
}

// Create the context with default values
const AuthContext = createContext<AuthContextType>({
  isAuthenticated: false,
  loading: true,
});

// Hook for components to easily access auth state
export const useAuth = () => useContext(AuthContext);

// Provider component that wraps app and makes auth object available
export function AuthProvider({ children }: { children: React.ReactNode }) {
  const [authState, setAuthState] = useState<AuthContextType>({
    isAuthenticated: false,
    loading: true,
  });

  useEffect(() => {
    // Check if user is authenticated on component mount
    const checkAuth = async () => {
      try {
        const token = getToken();
        setAuthState({
          isAuthenticated: !!token,
          loading: false,
        });
      } catch (error) {
        console.error('Auth context error:', error);
        setAuthState({
          isAuthenticated: false,
          loading: false,
        });
      }
    };

    checkAuth();
  }, []);

  return (
    <AuthContext.Provider value={authState}>
      {children}
    </AuthContext.Provider>
  );
}
