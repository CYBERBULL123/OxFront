'use client'

import React, { useState } from 'react'
import Link from 'next/link'

const Signup: React.FC = () => {
  const [name, setName] = useState('')
  const [email, setEmail] = useState('')
  const [password, setPassword] = useState('')
  const [confirmPassword, setConfirmPassword] = useState('')

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault()
    // Handle signup logic here
  }

  const getPasswordStrength = (password: string) => {
    // Implement password strength logic here
    return 'weak' // or 'medium' or 'strong'
  }

  return (
    <div className="flex items-center min-h-screen bg-gray-900 p-6 sm:p-12">
      <div className="w-full max-w-md mx-auto bg-gray-800 rounded-lg shadow-xl">
        <div className="flex flex-col p-8">
          <h1 className="text-2xl font-semibold text-white mb-4">Create your account</h1>
          <form onSubmit={handleSubmit}>
            <label className="block text-sm text-gray-300">
              <span>Name</span>
              <input
                className="block w-full mt-2 px-4 py-2 rounded-lg bg-gray-700 text-gray-300 focus:outline-none focus:ring-2 focus:ring-purple-500"
                type="text"
                value={name}
                onChange={(e) => setName(e.target.value)}
                placeholder="John Doe"
              />
            </label>

            <label className="block text-sm text-gray-300 mt-4">
              <span>Email</span>
              <input
                className="block w-full mt-2 px-4 py-2 rounded-lg bg-gray-700 text-gray-300 focus:outline-none focus:ring-2 focus:ring-purple-500"
                type="email"
                value={email}
                onChange={(e) => setEmail(e.target.value)}
                placeholder="johndoe@example.com"
              />
            </label>

            <label className="block text-sm text-gray-300 mt-4">
              <span>Password</span>
              <input
                className="block w-full mt-2 px-4 py-2 rounded-lg bg-gray-700 text-gray-300 focus:outline-none focus:ring-2 focus:ring-purple-500"
                type="password"
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                placeholder="********"
              />
            </label>

            <label className="block text-sm text-gray-300 mt-4">
              <span>Confirm password</span>
              <input
                className="block w-full mt-2 px-4 py-2 rounded-lg bg-gray-700 text-gray-300 focus:outline-none focus:ring-2 focus:ring-purple-500"
                type="password"
                value={confirmPassword}
                onChange={(e) => setConfirmPassword(e.target.value)}
                placeholder="********"
              />
            </label>

            <div className="mt-4">
              <span className="text-sm text-gray-400">Password strength:</span>
              <div className="mt-2 w-full h-2 bg-gray-600 rounded-full overflow-hidden">
                <div
                  className={`h-full ${
                    getPasswordStrength(password) === 'weak'
                      ? 'bg-red-600'
                      : getPasswordStrength(password) === 'medium'
                      ? 'bg-yellow-500'
                      : 'bg-green-500'
                  }`}
                  style={{ width: `${(password.length / 12) * 100}%` }}
                ></div>
              </div>
            </div>

            <button
              type="submit"
              className="w-full mt-6 px-4 py-2 text-white bg-purple-600 rounded-lg hover:bg-purple-700 focus:outline-none focus:ring-2 focus:ring-purple-500 transition duration-200"
            >
              Create account
            </button>
          </form>

          <hr className="my-6 border-gray-600" />
          <p className="text-sm text-gray-400">
            Already have an account?{' '}
            <Link href="/login" className="text-purple-400 hover:underline">
              Login here
            </Link>
          </p>
        </div>
      </div>
    </div>
  )
}

export default Signup
