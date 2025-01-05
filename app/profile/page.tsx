'use client'

import React, { useState } from 'react'
import Layout from '../../components/Layout'
import { motion } from 'framer-motion'
import { User, Mail, Lock, Save } from 'lucide-react'

export default function Profile() {
  const [name, setName] = useState('John Doe')
  const [email, setEmail] = useState('john@example.com')
  const [currentPassword, setCurrentPassword] = useState('')
  const [newPassword, setNewPassword] = useState('')
  const [confirmPassword, setConfirmPassword] = useState('')

  const handleProfileUpdate = (e: React.FormEvent) => {
    e.preventDefault()
    console.log('Profile updated')
  }

  const handlePasswordChange = (e: React.FormEvent) => {
    e.preventDefault()
    console.log('Password changed')
  }

  return (
    <Layout>
      <motion.div
        initial={{ opacity: 0, y: 20 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ duration: 0.5 }}
      >
        <h2 className="text-3xl font-semibold text-gray-800 dark:text-white mb-6">Profile</h2>

        {/* Profile Update Section */}
        <div className="space-y-8">
          <div className="min-w-0 p-6 bg-white rounded-lg shadow-xs dark:bg-gray-800">
            <h3 className="text-lg font-semibold text-gray-700 dark:text-gray-300 mb-6">Profile Information</h3>
            <form onSubmit={handleProfileUpdate}>
              <div className="space-y-4">
                <div>
                  <label className="block text-sm text-gray-700 dark:text-gray-400 mb-1">Name</label>
                  <div className="relative">
                    <input
                      className="block w-full text-sm dark:bg-gray-700 dark:border-gray-600 focus:ring-2 focus:ring-purple-600 focus:outline-none form-input pl-10 py-2"
                      value={name}
                      onChange={(e) => setName(e.target.value)}
                    />
                    <User className="absolute left-3 top-1/2 transform -translate-y-1/2 w-4 h-4 text-gray-400" />
                  </div>
                </div>
                <div>
                  <label className="block text-sm text-gray-700 dark:text-gray-400 mb-1">Email</label>
                  <div className="relative">
                    <input
                      className="block w-full text-sm dark:bg-gray-700 dark:border-gray-600 focus:ring-2 focus:ring-purple-600 focus:outline-none form-input pl-10 py-2"
                      value={email}
                      onChange={(e) => setEmail(e.target.value)}
                    />
                    <Mail className="absolute left-3 top-1/2 transform -translate-y-1/2 w-4 h-4 text-gray-400" />
                  </div>
                </div>
              </div>
              <button
                type="submit"
                className="mt-6 w-full px-6 py-3 text-sm font-medium text-white bg-purple-600 rounded-lg shadow-sm hover:bg-purple-700 focus:outline-none focus:ring-2 focus:ring-purple-600"
              >
                <Save className="w-4 h-4 mr-2 inline" />
                Save Changes
              </button>
            </form>
          </div>

          {/* Change Password Section */}
          <div className="min-w-0 p-6 bg-white rounded-lg shadow-xs dark:bg-gray-800">
            <h3 className="text-lg font-semibold text-gray-700 dark:text-gray-300 mb-6">Change Password</h3>
            <form onSubmit={handlePasswordChange}>
              <div className="space-y-4">
                <div>
                  <label className="block text-sm text-gray-700 dark:text-gray-400 mb-1">Current Password</label>
                  <div className="relative">
                    <input
                      type="password"
                      className="block w-full text-sm dark:bg-gray-700 dark:border-gray-600 focus:ring-2 focus:ring-purple-600 focus:outline-none form-input pl-10 py-2"
                      value={currentPassword}
                      onChange={(e) => setCurrentPassword(e.target.value)}
                    />
                    <Lock className="absolute left-3 top-1/2 transform -translate-y-1/2 w-4 h-4 text-gray-400" />
                  </div>
                </div>
                <div>
                  <label className="block text-sm text-gray-700 dark:text-gray-400 mb-1">New Password</label>
                  <div className="relative">
                    <input
                      type="password"
                      className="block w-full text-sm dark:bg-gray-700 dark:border-gray-600 focus:ring-2 focus:ring-purple-600 focus:outline-none form-input pl-10 py-2"
                      value={newPassword}
                      onChange={(e) => setNewPassword(e.target.value)}
                    />
                    <Lock className="absolute left-3 top-1/2 transform -translate-y-1/2 w-4 h-4 text-gray-400" />
                  </div>
                </div>
                <div>
                  <label className="block text-sm text-gray-700 dark:text-gray-400 mb-1">Confirm New Password</label>
                  <div className="relative">
                    <input
                      type="password"
                      className="block w-full text-sm dark:bg-gray-700 dark:border-gray-600 focus:ring-2 focus:ring-purple-600 focus:outline-none form-input pl-10 py-2"
                      value={confirmPassword}
                      onChange={(e) => setConfirmPassword(e.target.value)}
                    />
                    <Lock className="absolute left-3 top-1/2 transform -translate-y-1/2 w-4 h-4 text-gray-400" />
                  </div>
                </div>
              </div>
              <button
                type="submit"
                className="mt-6 w-full px-6 py-3 text-sm font-medium text-white bg-purple-600 rounded-lg shadow-sm hover:bg-purple-700 focus:outline-none focus:ring-2 focus:ring-purple-600"
              >
                <Save className="w-4 h-4 mr-2 inline" />
                Change Password
              </button>
            </form>
          </div>
        </div>
      </motion.div>
    </Layout>
  )
}
