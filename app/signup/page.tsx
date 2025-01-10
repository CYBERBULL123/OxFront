'use client';

import React, { useState } from 'react';
import Link from 'next/link';
import { motion } from 'framer-motion';
import { Shield, User, Lock, Check } from 'lucide-react';

const Signup: React.FC = () => {
  const [name, setName] = useState('');
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [confirmPassword, setConfirmPassword] = useState('');

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    // Handle signup logic here
  };

  const getPasswordStrength = (password: string) => {
    if (password.length === 0) return 'empty';
    if (password.length < 6) return 'weak';
    if (password.length < 10) return 'medium';
    return 'strong';
  };

  const passwordStrengthColor = (strength: string) => {
    switch (strength) {
      case 'weak':
        return 'bg-red-600';
      case 'medium':
        return 'bg-yellow-500';
      case 'strong':
        return 'bg-green-500';
      default:
        return 'bg-gray-600';
    }
  };

  return (
    <div className="flex items-center min-h-screen bg-gray-900 relative overflow-hidden p-6 sm:p-12">
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

      {/* Signup Form */}
      <motion.div
        initial={{ opacity: 0, y: -50 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ duration: 0.5 }}
        className="relative z-10 w-full max-w-md mx-auto bg-gray-800/50 backdrop-blur-md rounded-2xl shadow-2xl border border-gray-700/30 p-8"
      >
        <div className="text-center">
          <motion.div
            initial={{ scale: 0 }}
            animate={{ scale: 1 }}
            transition={{ delay: 0.2, duration: 0.5 }}
            className="mx-auto flex items-center justify-center w-16 h-16 bg-purple-600 rounded-full"
          >
            <Shield className="h-8 w-8 text-white" />
          </motion.div>
          <h1 className="mt-6 text-2xl font-semibold text-white">Create your account</h1>
          <p className="mt-2 text-sm text-gray-300">Join OxSuite to secure your digital world</p>
        </div>

        <form onSubmit={handleSubmit} className="mt-8 space-y-6">
          <motion.div
            initial={{ opacity: 0, x: -20 }}
            animate={{ opacity: 1, x: 0 }}
            transition={{ delay: 0.4, duration: 0.5 }}
          >
            <label className="block text-sm text-gray-300">
              <span>Name</span>
              <div className="relative mt-2">
                <User className="absolute left-3 top-1/2 transform -translate-y-1/2 h-5 w-5 text-gray-400" />
                <input
                  className="block w-full pl-10 pr-4 py-2 rounded-lg bg-gray-700 text-gray-300 focus:outline-none focus:ring-2 focus:ring-purple-500"
                  type="text"
                  value={name}
                  onChange={(e) => setName(e.target.value)}
                  placeholder="John Doe"
                />
              </div>
            </label>
          </motion.div>

          <motion.div
            initial={{ opacity: 0, x: -20 }}
            animate={{ opacity: 1, x: 0 }}
            transition={{ delay: 0.6, duration: 0.5 }}
          >
            <label className="block text-sm text-gray-300 mt-4">
              <span>Email</span>
              <div className="relative mt-2">
                <User className="absolute left-3 top-1/2 transform -translate-y-1/2 h-5 w-5 text-gray-400" />
                <input
                  className="block w-full pl-10 pr-4 py-2 rounded-lg bg-gray-700 text-gray-300 focus:outline-none focus:ring-2 focus:ring-purple-500"
                  type="email"
                  value={email}
                  onChange={(e) => setEmail(e.target.value)}
                  placeholder="johndoe@example.com"
                />
              </div>
            </label>
          </motion.div>

          <motion.div
            initial={{ opacity: 0, x: -20 }}
            animate={{ opacity: 1, x: 0 }}
            transition={{ delay: 0.8, duration: 0.5 }}
          >
            <label className="block text-sm text-gray-300 mt-4">
              <span>Password</span>
              <div className="relative mt-2">
                <Lock className="absolute left-3 top-1/2 transform -translate-y-1/2 h-5 w-5 text-gray-400" />
                <input
                  className="block w-full pl-10 pr-4 py-2 rounded-lg bg-gray-700 text-gray-300 focus:outline-none focus:ring-2 focus:ring-purple-500"
                  type="password"
                  value={password}
                  onChange={(e) => setPassword(e.target.value)}
                  placeholder="********"
                />
              </div>
            </label>
          </motion.div>

          <motion.div
            initial={{ opacity: 0, x: -20 }}
            animate={{ opacity: 1, x: 0 }}
            transition={{ delay: 1, duration: 0.5 }}
          >
            <label className="block text-sm text-gray-300 mt-4">
              <span>Confirm password</span>
              <div className="relative mt-2">
                <Lock className="absolute left-3 top-1/2 transform -translate-y-1/2 h-5 w-5 text-gray-400" />
                <input
                  className="block w-full pl-10 pr-4 py-2 rounded-lg bg-gray-700 text-gray-300 focus:outline-none focus:ring-2 focus:ring-purple-500"
                  type="password"
                  value={confirmPassword}
                  onChange={(e) => setConfirmPassword(e.target.value)}
                  placeholder="********"
                />
              </div>
            </label>
          </motion.div>

          <motion.div
            initial={{ opacity: 0, x: -20 }}
            animate={{ opacity: 1, x: 0 }}
            transition={{ delay: 1.2, duration: 0.5 }}
          >
            <div className="mt-4">
              <span className="text-sm text-gray-400">Password strength:</span>
              <div className="mt-2 w-full h-2 bg-gray-600 rounded-full overflow-hidden">
                <div
                  className={`h-full ${passwordStrengthColor(getPasswordStrength(password))}`}
                  style={{ width: `${(password.length / 12) * 100}%` }}
                ></div>
              </div>
            </div>
          </motion.div>

          <motion.button
            whileHover={{ scale: 1.05 }}
            whileTap={{ scale: 0.95 }}
            type="submit"
            className="w-full mt-6 px-4 py-2 text-white bg-purple-600 rounded-lg hover:bg-purple-700 focus:outline-none focus:ring-2 focus:ring-purple-500 transition duration-200"
          >
            Create account
          </motion.button>
        </form>

        <hr className="my-6 border-gray-600" />
        <p className="text-sm text-gray-400 text-center">
          Already have an account?{' '}
          <Link href="/login" className="text-purple-400 hover:underline">
            Login here
          </Link>
        </p>
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
            animate={{ y: window.innerHeight, x: Math.random() * 100 - 50, opacity: [0, 1, 0] }}
            transition={{
              duration: Math.random() * 5 + 5,
              repeat: Infinity,
              delay: Math.random() * 2,
              ease: 'linear',
            }}
            className="absolute text-purple-500"
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
};

export default Signup;