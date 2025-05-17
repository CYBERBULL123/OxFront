'use client';

import React, { useState, useEffect } from 'react';
import { useRouter } from 'next/navigation';
import { motion } from 'framer-motion';
import { Lock, Shield, User, AlertCircle } from 'lucide-react';
import { login, storeToken } from '@/lib/api'; // Import login and storeToken

export default function LoginPage() {
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [error, setError] = useState('');
  const [isLoading, setIsLoading] = useState(false);
  const router = useRouter();
  const [dynamicInnerHeight, setDynamicInnerHeight] = useState(0);

  useEffect(() => {
    setDynamicInnerHeight(window.innerHeight);
  }, []);

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setError('');
    setIsLoading(true);
    
    try {
      // Call our login function directly
      const result = await login(username, password);
      
      if (result && result.access_token) {
        // Store the token in both localStorage and cookies
        await storeToken(result.access_token);
        console.log('Successfully logged in and stored token');
        
        // Redirect to dashboard
        router.push('/dashboard');
      } else {
        setError('Invalid username or password');
      }
    } catch (error) {
      console.error('Login error:', error);
      setError('An unexpected error occurred. Please try again.');
    } finally {
      setIsLoading(false);
    }
  };

  const navigateToSignUp = () => {
    router.push('/signup'); // Navigate to signup page
  };

  return (
    <div className="min-h-screen flex items-center justify-center bg-gray-900 relative overflow-hidden">
      {/* Background Graphics */}
      <div className="absolute inset-0 z-0">
        <div className="absolute inset-0 bg-[url('/images/cyber-bg.jpg')] bg-cover bg-center opacity-20"></div>
        <div className="absolute inset-0 bg-gradient-to-r from-black-900/50 to-gray-900/50"></div>
        <motion.div
          initial={{ opacity: 0 }}
          animate={{ opacity: 1 }}
          transition={{ duration: 1 }}
          className="absolute inset-0 bg-[url('/images/binary-code.png')] bg-repeat opacity-10"
        ></motion.div>
      </div>

      {/* Login Form */}
      <motion.div
        initial={{ opacity: 0, y: -50 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ duration: 0.5 }}
        className="relative z-10 max-w-md w-full space-y-8 bg-gray-800/50 backdrop-blur-md rounded-2xl shadow-2xl border border-gray-700/30 p-8"
      >
        <div className="text-center">
          <motion.div
            initial={{ scale: 0 }}
            animate={{ scale: 1 }}
            transition={{ delay: 0.2, duration: 0.5 }}
            className="mx-auto flex items-center justify-center w-16 h-16 bg-blue-600 rounded-full"
          >
            <Shield className="h-8 w-8 text-white" />
          </motion.div>
          <h2 className="mt-6 text-center text-3xl font-extrabold text-white">Sign in to OxSuite</h2>
          <p className="mt-2 text-sm text-gray-300">Secure your digital world with OxSuite</p>
        </div>
        {error && (
          <div className="flex items-center p-4 text-sm text-red-400 border border-red-500/30 rounded-md bg-red-500/10">
            <AlertCircle className="h-4 w-4 mr-2 flex-shrink-0" />
            <span>{error}</span>
          </div>
        )}
        <form className="mt-8 space-y-6" onSubmit={handleSubmit}>
          <input type="hidden" name="remember" defaultValue="true" />
          <div className="rounded-md shadow-sm -space-y-px">
            <div>
              <label htmlFor="username" className="sr-only">
                Username
              </label>
              <motion.div
                initial={{ opacity: 0, x: -20 }}
                animate={{ opacity: 1, x: 0 }}
                transition={{ delay: 0.4, duration: 0.5 }}
              >
                <input
                  id="username"
                  name="username"
                  type="text"
                  autoComplete="username"
                  required
                  className="appearance-none rounded-none relative block w-full px-3 py-3 border border-gray-700 placeholder-gray-400 text-white bg-gray-900/50 rounded-t-md focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-blue-500 sm:text-sm"
                  placeholder="Username"
                  value={username}
                  onChange={(e) => setUsername(e.target.value)}
                />
              </motion.div>
            </div>
            <div>
              <label htmlFor="password" className="sr-only">
                Password
              </label>
              <motion.div
                initial={{ opacity: 0, x: -20 }}
                animate={{ opacity: 1, x: 0 }}
                transition={{ delay: 0.6, duration: 0.5 }}
              >
                <input
                  id="password"
                  name="password"
                  type="password"
                  autoComplete="current-password"
                  required
                  className="appearance-none rounded-none relative block w-full px-3 py-3 border border-gray-700 placeholder-gray-400 text-white bg-gray-900/50 rounded-b-md focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-blue-500 sm:text-sm"
                  placeholder="Password"
                  value={password}
                  onChange={(e) => setPassword(e.target.value)}
                />
              </motion.div>
            </div>
          </div>

          <div className="flex flex-col space-y-4">
            <motion.button
              whileHover={{ scale: 1.05 }}
              whileTap={{ scale: 0.95 }}
              type="submit"
              className="group relative w-full py-3 px-4 border border-transparent text-sm font-medium rounded-md text-white bg-blue-600 hover:bg-blue-700 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-blue-500 transition-all"
            >
              <span className="absolute left-0 inset-y-0 flex items-center pl-3">
                <Lock className="h-5 w-5 text-blue-300 group-hover:text-blue-200" aria-hidden="true" />
              </span>
              Sign in
            </motion.button>

            <motion.button
              whileHover={{ scale: 1.05 }}
              whileTap={{ scale: 0.95 }}
              type="button"
              onClick={navigateToSignUp}
              className="w-full py-3 px-4 border border-transparent text-sm font-medium rounded-md text-blue-600 bg-white hover:bg-gray-100 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-blue-500 transition-all"
            >
              <span className="font-semibold">Sign Up</span>
            </motion.button>
          </div>
        </form>
      </motion.div>

      {/* Floating Icons Animation */}
      <motion.div
        initial={{ opacity: 0 }}
        animate={{ opacity: 1 }}
        transition={{ delay: 1, duration: 1 }}
        className="absolute inset-0 z-0 overflow-hidden"
      >
        {[...Array(20)].map((_, i) => (
          <motion.div
            key={i}
            initial={{ y: -10, x: Math.random() * 100 - 50, opacity: 0 }}
            animate={{ y: dynamicInnerHeight, x: Math.random() * 100 - 50, opacity: [0, 1, 0] }}
            transition={{
              duration: Math.random() * 5 + 5,
              repeat: Infinity,
              delay: Math.random() * 2,
              ease: 'linear',
            }}
            className="absolute text-blue-500"
            style={{
              left: `${Math.random() * 100}%`,
              fontSize: `${Math.random() * 20 + 10}px`,
            }}
          >
            {Math.random() > 0.5 ? '0' : '1'}
          </motion.div>
        ))}
      </motion.div>
    </div>
  );
}