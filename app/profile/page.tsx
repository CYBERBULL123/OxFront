'use client'

import React, { useState } from 'react'
import Layout from '../../components/Layout'
import { motion } from 'framer-motion'
import { User, Mail, Lock, Save, Check, X, ChevronDown, ChevronUp, Calendar, Shield, AlertTriangle } from 'lucide-react'

export default function Profile() {
  // Profile Information
  const [name, setName] = useState('John Doe')
  const [email, setEmail] = useState('john@example.com')
  const [avatar, setAvatar] = useState<File | null>(null)
  const [avatarPreview, setAvatarPreview] = useState<string>('/assets/default-avatar.png')
  
  // Password Management
  const [currentPassword, setCurrentPassword] = useState('')
  const [newPassword, setNewPassword] = useState('')
  const [confirmPassword, setConfirmPassword] = useState('')
  
  // Security Settings
  const [twoFactorEnabled, setTwoFactorEnabled] = useState(false)
  const [showTwoFactorSetup, setShowTwoFactorSetup] = useState(false)
  const [twoFactorCode, setTwoFactorCode] = useState('')
  
  // Notification Preferences
  const [emailNotifications, setEmailNotifications] = useState(true)
  const [securityAlerts, setSecurityAlerts] = useState(true)
  const [weeklyReports, setWeeklyReports] = useState(false)
  const [productUpdates, setProductUpdates] = useState(true)
  
  // API Keys
  const [apiKeys, setApiKeys] = useState<Array<{name: string, key: string, created: Date, lastUsed: Date | null}>>([
    { name: 'Development', key: 'ox_api_key_123456', created: new Date(2025, 3, 15), lastUsed: new Date(2025, 4, 8) },
    { name: 'Production', key: 'ox_api_key_654321', created: new Date(2025, 2, 10), lastUsed: null }
  ])
  const [newApiKeyName, setNewApiKeyName] = useState('')
  
  // Active Tab
  const [activeTab, setActiveTab] = useState('profile')
  
  // Status message
  const [statusMessage, setStatusMessage] = useState<{type: 'success' | 'error', message: string} | null>(null)

  const handleProfileUpdate = (e: React.FormEvent) => {
    e.preventDefault()
    setStatusMessage({ type: 'success', message: 'Profile information updated successfully' })
    setTimeout(() => setStatusMessage(null), 3000)
  }

  const handlePasswordChange = (e: React.FormEvent) => {
    e.preventDefault()
    if (newPassword !== confirmPassword) {
      setStatusMessage({ type: 'error', message: 'New passwords do not match' })
      return
    }
    setStatusMessage({ type: 'success', message: 'Password changed successfully' })
    setCurrentPassword('')
    setNewPassword('')
    setConfirmPassword('')
    setTimeout(() => setStatusMessage(null), 3000)
  }
  
  const handleAvatarChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    if (e.target.files && e.target.files[0]) {
      const file = e.target.files[0]
      setAvatar(file)
      const reader = new FileReader()
      reader.onload = (e) => {
        if (e.target?.result) {
          setAvatarPreview(e.target.result.toString())
        }
      }
      reader.readAsDataURL(file)
    }
  }
  
  const generateApiKey = () => {
    if (!newApiKeyName.trim()) {
      setStatusMessage({ type: 'error', message: 'Please enter a name for your API key' })
      return
    }
    
    const newKey = `ox_api_key_${Math.random().toString(36).substring(2, 10)}${Math.random().toString(36).substring(2, 10)}`
    const newApiKey = {
      name: newApiKeyName,
      key: newKey,
      created: new Date(),
      lastUsed: null
    }
    
    setApiKeys([...apiKeys, newApiKey])
    setNewApiKeyName('')
    setStatusMessage({ type: 'success', message: 'New API key generated' })
    setTimeout(() => setStatusMessage(null), 3000)
  }
  
  const deleteApiKey = (keyToDelete: string) => {
    setApiKeys(apiKeys.filter(key => key.key !== keyToDelete))
    setStatusMessage({ type: 'success', message: 'API key deleted' })
    setTimeout(() => setStatusMessage(null), 3000)
  }
  
  const handleTwoFactorToggle = () => {
    if (twoFactorEnabled) {
      setTwoFactorEnabled(false)
      setStatusMessage({ type: 'success', message: 'Two-factor authentication disabled' })
      setTimeout(() => setStatusMessage(null), 3000)
    } else {
      setShowTwoFactorSetup(true)
    }
  }
  
  const setupTwoFactor = (e: React.FormEvent) => {
    e.preventDefault()
    if (twoFactorCode === '123456') { // Mock validation, in real app would verify against actual 2FA setup
      setTwoFactorEnabled(true)
      setShowTwoFactorSetup(false)
      setTwoFactorCode('')
      setStatusMessage({ type: 'success', message: 'Two-factor authentication enabled' })
      setTimeout(() => setStatusMessage(null), 3000)
    } else {
      setStatusMessage({ type: 'error', message: 'Invalid verification code' })
      setTimeout(() => setStatusMessage(null), 3000)
    }
  }

  return (
    <Layout>
      <motion.div
        initial={{ opacity: 0, y: 20 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ duration: 0.5 }}
        className="max-w-7xl mx-auto"
      >
        <div className="flex flex-col md:flex-row justify-between items-start mb-6">
          <h2 className="text-3xl font-semibold text-gray-800 dark:text-white">Account Settings</h2>
          
          {statusMessage && (
            <div className={`mt-2 md:mt-0 px-4 py-2 rounded-md text-sm ${
              statusMessage.type === 'success' 
                ? 'bg-green-100 text-green-800 dark:bg-green-900 dark:text-green-200' 
                : 'bg-red-100 text-red-800 dark:bg-red-900 dark:text-red-200'
            }`}>
              {statusMessage.message}
            </div>
          )}
        </div>

        {/* Navigation Tabs */}
        <div className="mb-6 border-b border-gray-200 dark:border-gray-700">
          <ul className="flex flex-wrap -mb-px text-sm font-medium text-center">
            <li className="mr-2">
              <button
                onClick={() => setActiveTab('profile')}
                className={`inline-block p-4 rounded-t-lg ${
                  activeTab === 'profile'
                    ? 'text-purple-600 border-b-2 border-purple-600 dark:text-purple-400 dark:border-purple-400'
                    : 'text-gray-500 hover:text-gray-600 dark:text-gray-400 dark:hover:text-gray-300'
                }`}
              >
                <User className="w-4 h-4 mr-2 inline" />
                Profile
              </button>
            </li>
            <li className="mr-2">
              <button
                onClick={() => setActiveTab('security')}
                className={`inline-block p-4 rounded-t-lg ${
                  activeTab === 'security'
                    ? 'text-purple-600 border-b-2 border-purple-600 dark:text-purple-400 dark:border-purple-400'
                    : 'text-gray-500 hover:text-gray-600 dark:text-gray-400 dark:hover:text-gray-300'
                }`}
              >
                <Lock className="w-4 h-4 mr-2 inline" />
                Security
              </button>
            </li>
            <li className="mr-2">
              <button
                onClick={() => setActiveTab('notifications')}
                className={`inline-block p-4 rounded-t-lg ${
                  activeTab === 'notifications'
                    ? 'text-purple-600 border-b-2 border-purple-600 dark:text-purple-400 dark:border-purple-400'
                    : 'text-gray-500 hover:text-gray-600 dark:text-gray-400 dark:hover:text-gray-300'
                }`}
              >
                <Mail className="w-4 h-4 mr-2 inline" />
                Notifications
              </button>
            </li>
            <li>
              <button
                onClick={() => setActiveTab('api')}
                className={`inline-block p-4 rounded-t-lg ${
                  activeTab === 'api'
                    ? 'text-purple-600 border-b-2 border-purple-600 dark:text-purple-400 dark:border-purple-400'
                    : 'text-gray-500 hover:text-gray-600 dark:text-gray-400 dark:hover:text-gray-300'
                }`}
              >
                <code className="inline-block mr-2">{"{}"}</code>
                API Access
              </button>
            </li>
          </ul>
        </div>

        {/* Profile Tab Content */}
        {activeTab === 'profile' && (
          <div className="space-y-8">
            <div className="min-w-0 p-6 bg-white rounded-lg shadow-sm dark:bg-gray-800">
              <h3 className="text-lg font-semibold text-gray-700 dark:text-gray-300 mb-6">Profile Information</h3>
              
              <div className="flex flex-col lg:flex-row gap-6">
                <div className="lg:w-1/4 flex flex-col items-center">
                  <div className="relative">
                    <img 
                      src={avatarPreview} 
                      alt="Profile Avatar" 
                      className="w-32 h-32 rounded-full object-cover border-4 border-gray-100 dark:border-gray-700 mb-4"
                    />
                    <label htmlFor="avatar-upload" className="absolute bottom-4 right-0 bg-purple-600 p-2 rounded-full cursor-pointer hover:bg-purple-700 transition-colors">
                      <svg xmlns="http://www.w3.org/2000/svg" className="h-4 w-4 text-white" viewBox="0 0 20 20" fill="currentColor">
                        <path d="M13.586 3.586a2 2 0 112.828 2.828l-.793.793-2.828-2.828.793-.793zM11.379 5.793L3 14.172V17h2.828l8.38-8.379-2.83-2.828z" />
                      </svg>
                      <input 
                        id="avatar-upload" 
                        type="file" 
                        accept="image/*" 
                        className="hidden" 
                        onChange={handleAvatarChange}
                      />
                    </label>
                  </div>
                  <p className="text-sm text-gray-500 dark:text-gray-400 text-center mt-2">
                    Click the pencil icon to change your profile picture
                  </p>
                </div>
                
                <div className="lg:w-3/4">
                  <form onSubmit={handleProfileUpdate}>
                    <div className="space-y-4">
                      <div>
                        <label className="block text-sm text-gray-700 dark:text-gray-400 mb-1">Full Name</label>
                        <div className="relative">
                          <input
                            className="block w-full text-sm dark:bg-gray-700 dark:border-gray-600 focus:ring-2 focus:ring-purple-600 focus:outline-none form-input pl-10 py-3 rounded-md"
                            value={name}
                            onChange={(e) => setName(e.target.value)}
                          />
                          <User className="absolute left-3 top-1/2 transform -translate-y-1/2 w-4 h-4 text-gray-400" />
                        </div>
                      </div>
                      <div>
                        <label className="block text-sm text-gray-700 dark:text-gray-400 mb-1">Email Address</label>
                        <div className="relative">
                          <input
                            type="email"
                            className="block w-full text-sm dark:bg-gray-700 dark:border-gray-600 focus:ring-2 focus:ring-purple-600 focus:outline-none form-input pl-10 py-3 rounded-md"
                            value={email}
                            onChange={(e) => setEmail(e.target.value)}
                          />
                          <Mail className="absolute left-3 top-1/2 transform -translate-y-1/2 w-4 h-4 text-gray-400" />
                        </div>
                      </div>
                    </div>
                    <button
                      type="submit"
                      className="mt-6 px-6 py-3 text-sm font-medium text-white bg-purple-600 rounded-lg shadow-sm hover:bg-purple-700 focus:outline-none focus:ring-2 focus:ring-purple-600"
                    >
                      <Save className="w-4 h-4 mr-2 inline" />
                      Save Changes
                    </button>
                  </form>
                </div>
              </div>
            </div>
            
            {/* Password Change Section */}
            <div className="min-w-0 p-6 bg-white rounded-lg shadow-sm dark:bg-gray-800">
              <h3 className="text-lg font-semibold text-gray-700 dark:text-gray-300 mb-6">Change Password</h3>
              <form onSubmit={handlePasswordChange}>
                <div className="space-y-4">
                  <div>
                    <label className="block text-sm text-gray-700 dark:text-gray-400 mb-1">Current Password</label>
                    <div className="relative">
                      <input
                        type="password"
                        className="block w-full text-sm dark:bg-gray-700 dark:border-gray-600 focus:ring-2 focus:ring-purple-600 focus:outline-none form-input pl-10 py-3 rounded-md"
                        value={currentPassword}
                        onChange={(e) => setCurrentPassword(e.target.value)}
                      />
                      <Lock className="absolute left-3 top-1/2 transform -translate-y-1/2 w-4 h-4 text-gray-400" />
                    </div>
                  </div>
                  <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                    <div>
                      <label className="block text-sm text-gray-700 dark:text-gray-400 mb-1">New Password</label>
                      <div className="relative">
                        <input
                          type="password"
                          className="block w-full text-sm dark:bg-gray-700 dark:border-gray-600 focus:ring-2 focus:ring-purple-600 focus:outline-none form-input pl-10 py-3 rounded-md"
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
                          className="block w-full text-sm dark:bg-gray-700 dark:border-gray-600 focus:ring-2 focus:ring-purple-600 focus:outline-none form-input pl-10 py-3 rounded-md"
                          value={confirmPassword}
                          onChange={(e) => setConfirmPassword(e.target.value)}
                        />
                        <Lock className="absolute left-3 top-1/2 transform -translate-y-1/2 w-4 h-4 text-gray-400" />
                      </div>
                    </div>
                  </div>
                </div>
                <button
                  type="submit"
                  className="mt-6 px-6 py-3 text-sm font-medium text-white bg-purple-600 rounded-lg shadow-sm hover:bg-purple-700 focus:outline-none focus:ring-2 focus:ring-purple-600"
                >
                  <Save className="w-4 h-4 mr-2 inline" />
                  Change Password
                </button>
              </form>
            </div>
          </div>
        )}

        {/* Security Tab Content */}
        {activeTab === 'security' && (
          <div className="space-y-8">
            <div className="min-w-0 p-6 bg-white rounded-lg shadow-sm dark:bg-gray-800">
              <h3 className="text-lg font-semibold text-gray-700 dark:text-gray-300 mb-6">Security Settings</h3>
              
              <div className="space-y-6">
                <div className="flex items-center justify-between">
                  <div>
                    <h4 className="text-md font-medium text-gray-800 dark:text-gray-200">Two-Factor Authentication</h4>
                    <p className="text-sm text-gray-500 dark:text-gray-400">Add an extra layer of security to your account</p>
                  </div>
                  <label className="relative inline-flex items-center cursor-pointer">
                    <input type="checkbox" checked={twoFactorEnabled} onChange={handleTwoFactorToggle} className="sr-only peer" />
                    <div className="w-11 h-6 bg-gray-200 peer-focus:outline-none peer-focus:ring-4 peer-focus:ring-purple-300 dark:peer-focus:ring-purple-800 rounded-full peer dark:bg-gray-700 peer-checked:after:translate-x-full peer-checked:after:border-white after:content-[''] after:absolute after:top-[2px] after:left-[2px] after:bg-white after:border-gray-300 after:border after:rounded-full after:h-5 after:w-5 after:transition-all dark:border-gray-600 peer-checked:bg-purple-600"></div>
                  </label>
                </div>
                
                {showTwoFactorSetup && (
                  <div className="border border-gray-200 dark:border-gray-700 rounded-lg p-4 bg-gray-50 dark:bg-gray-700">
                    <h5 className="text-md font-medium text-gray-800 dark:text-gray-200 mb-3">Setup Two-Factor Authentication</h5>
                    
                    <div className="flex flex-col sm:flex-row gap-4 items-start sm:items-center mb-4">
                      <div className="bg-white p-3 rounded-md shadow-sm">
                        <img 
                          src="data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAIQAAACECAYAAABRRIOnAAAAAklEQVR4AewaftIAAAOYSURBVO3BQY4cy5LAQDLR978yR0tfBZCoamn+GDezP1jrEg9rXeRhrYs8rHWRh7Uu8rDWRR7WusjDWhd5WOsiD2td5GGtizysdZGHtS7ysNZFHta6yMNaF3lY6yI/fEjlb1KZKCdKU5lUpqpMKn+TyicUS3fz8cWHVP4mlUnlE4qJW0wqn3hY6yIPa13kYa2L/PBlKt+k8gnFxJtUpqo0xaQyVaUpTFUmlanKVGWqMlVpCpPKNylMKt+k8gmVTzysdZGHtS7ysNZFfvhlKp9Q+SaVpjCpNMWkMlVpikllqtIUJpWm+ITKVKUpJpWmMKn8TSpNYVL5JpVPPKx1kYe1LvKw1kV++OUqU2FSaYqmMKlMVZrCpDJVaQqTylSlKUwqTTGpNMWkMlVpCpNKU5hUmmKqMlVpipvf7GGtizysdZGHtS7yw/8xlaaYVJrCpDJVmao0RVNMKlOVpmgKk8pUZaoyVWmKpjCpTFWawqQyVflfPax1kYe1LvKw1kV++GUqv0mlKaYqU5WmMKk0hUllqtJUaQqTylSlKUwqTfGJKk1hUpladTIf+ITK3/Sw1kUe1rrIw1oX+eFDKn9TVRWTylSlKUwqU5WpylRlqjJVaQqTypvKVKUpTCpTlanKVGWqMlX5mx7WusjDWhd5WOsiP3xIZaoyVZmqNMWk0hQmlaaYVJpiqtIUJpWmMKlMVaYqk8pUZVKZqjSFSaUpmsKkMlWZqkxVmsKkMlWZqkxVmsKkMlVpik88rHWRh7Uu8rDWRX74kEpTNIVJpSmawqQyVWkKk8pUZaoyVWmKpjCpTFWaYlJpiqbwpypNMalMKlOVpjCpfKIpTCpTlU88rHWRh7Uu8rDWRX74ZSpTlanKVGWq0hQmlalKU5hUmsKk0hQmlalKU0wqU5Wpyk9UnqqYVJrCpPK/eljrIg9rXeRhrYv88GUqn1CZqkxVmsKkMlWZqjTFpNIUk8pUpSmawlSlKUwqU5Wmao9pik9UaQqTSlOYVKYqn3hY6yIPa13kYa2L/PAhlaYwqUxVmsKkMlVpiknlE1WawqTSFCaVqcpUZaoyVZlUmsKkMlWZqjSFSWWqMlVpikllqtIUk8pUZaryiYe1LvKw1kUe1rrID/8xVZpCZaoyVWkKk8pUZarSFCaVqUpTmFQ+oTJVaQqTylRlqjJVmaqYVKYqTWFSaYqpylTlEw9rXeRhrYs8rHWRh7Uu8rDWRR7WusjDWhd5WOsiD2td5GGtizysdZGHtS7ysNZFHta6yMNaF3lY6yIPa13kv9wfOqLCnpCgAAAAAElFTkSuQmCC" 
                          alt="QR Code for 2FA" 
                          className="w-36 h-36" 
                        />
                      </div>
                      <div className="flex-1">
                        <p className="text-sm text-gray-600 dark:text-gray-300 mb-3">
                          Scan the QR code using your authenticator app or enter the key below.
                        </p>
                        <div className="bg-gray-100 dark:bg-gray-800 p-2 rounded font-mono text-xs mb-4 select-all">
                          OXST AQFC 6RJH BNLD C72P 9UYX VP4K
                        </div>
                        <form onSubmit={setupTwoFactor} className="flex flex-col sm:flex-row gap-2">
                          <input
                            type="text"
                            placeholder="Enter 6-digit code"
                            className="flex-1 text-sm dark:bg-gray-700 dark:border-gray-600 border rounded-md px-3 py-2 focus:ring-2 focus:ring-purple-600 focus:outline-none"
                            value={twoFactorCode}
                            onChange={(e) => setTwoFactorCode(e.target.value)}
                          />
                          <button
                            type="submit"
                            className="px-4 py-2 text-sm font-medium text-white bg-purple-600 rounded-lg shadow-sm hover:bg-purple-700 focus:outline-none focus:ring-2 focus:ring-purple-600"
                          >
                            Verify
                          </button>
                        </form>
                      </div>
                    </div>
                  </div>
                )}
                
                <hr className="border-gray-200 dark:border-gray-700" />
                
                <div className="flex items-center justify-between">
                  <div>
                    <h4 className="text-md font-medium text-gray-800 dark:text-gray-200">Login Sessions</h4>
                    <p className="text-sm text-gray-500 dark:text-gray-400">Manage your active sessions</p>
                  </div>
                  <button
                    className="px-4 py-2 text-sm font-medium text-white bg-red-600 rounded-lg shadow-sm hover:bg-red-700 focus:outline-none focus:ring-2 focus:ring-red-600"
                  >
                    Sign Out All Devices
                  </button>
                </div>
                
                <div className="border border-gray-200 dark:border-gray-700 rounded-lg overflow-hidden">
                  <div className="bg-gray-50 dark:bg-gray-700 p-3 border-b border-gray-200 dark:border-gray-600 flex justify-between items-center">
                    <div className="flex items-center">
                      <div className="w-2 h-2 bg-green-500 rounded-full mr-2"></div>
                      <span className="text-sm font-medium text-gray-700 dark:text-gray-300">Current Session</span>
                    </div>
                    <span className="text-xs text-gray-500 dark:text-gray-400">May 10, 2025 (Now)</span>
                  </div>
                  <div className="p-3 border-b border-gray-200 dark:border-gray-600 flex justify-between items-center">
                    <div className="flex items-center">
                      <div className="w-2 h-2 bg-gray-400 rounded-full mr-2"></div>
                      <span className="text-sm font-medium text-gray-700 dark:text-gray-300">Firefox on Windows</span>
                    </div>
                    <span className="text-xs text-gray-500 dark:text-gray-400">May 8, 2025</span>
                  </div>
                  <div className="p-3 flex justify-between items-center">
                    <div className="flex items-center">
                      <div className="w-2 h-2 bg-gray-400 rounded-full mr-2"></div>
                      <span className="text-sm font-medium text-gray-700 dark:text-gray-300">Safari on iPhone</span>
                    </div>
                    <span className="text-xs text-gray-500 dark:text-gray-400">May 5, 2025</span>
                  </div>
                </div>
              </div>
            </div>
          </div>
        )}

        {/* Notifications Tab Content */}
        {activeTab === 'notifications' && (
          <div className="min-w-0 p-6 bg-white rounded-lg shadow-sm dark:bg-gray-800">
            <h3 className="text-lg font-semibold text-gray-700 dark:text-gray-300 mb-6">Notification Preferences</h3>
            
            <div className="space-y-6">
              <div className="flex items-center justify-between">
                <div>
                  <h4 className="text-md font-medium text-gray-800 dark:text-gray-200">Email Notifications</h4>
                  <p className="text-sm text-gray-500 dark:text-gray-400">Receive notifications via email</p>
                </div>
                <label className="relative inline-flex items-center cursor-pointer">
                  <input type="checkbox" checked={emailNotifications} onChange={() => setEmailNotifications(!emailNotifications)} className="sr-only peer" />
                  <div className="w-11 h-6 bg-gray-200 peer-focus:outline-none peer-focus:ring-4 peer-focus:ring-purple-300 dark:peer-focus:ring-purple-800 rounded-full peer dark:bg-gray-700 peer-checked:after:translate-x-full peer-checked:after:border-white after:content-[''] after:absolute after:top-[2px] after:left-[2px] after:bg-white after:border-gray-300 after:border after:rounded-full after:h-5 after:w-5 after:transition-all dark:border-gray-600 peer-checked:bg-purple-600"></div>
                </label>
              </div>
              
              <hr className="border-gray-200 dark:border-gray-700" />
              
              <div className="space-y-4">
                <h4 className="text-md font-medium text-gray-800 dark:text-gray-200">Notification Types</h4>
                
                <div className="flex items-center justify-between">
                  <div>
                    <p className="text-sm font-medium text-gray-700 dark:text-gray-300">Security Alerts</p>
                    <p className="text-xs text-gray-500 dark:text-gray-400">Get notified about security incidents and suspicious activity</p>
                  </div>
                  <label className="relative inline-flex items-center cursor-pointer">
                    <input type="checkbox" checked={securityAlerts} onChange={() => setSecurityAlerts(!securityAlerts)} className="sr-only peer" />
                    <div className="w-11 h-6 bg-gray-200 peer-focus:outline-none peer-focus:ring-4 peer-focus:ring-purple-300 dark:peer-focus:ring-purple-800 rounded-full peer dark:bg-gray-700 peer-checked:after:translate-x-full peer-checked:after:border-white after:content-[''] after:absolute after:top-[2px] after:left-[2px] after:bg-white after:border-gray-300 after:border after:rounded-full after:h-5 after:w-5 after:transition-all dark:border-gray-600 peer-checked:bg-purple-600"></div>
                  </label>
                </div>
                
                <div className="flex items-center justify-between">
                  <div>
                    <p className="text-sm font-medium text-gray-700 dark:text-gray-300">Weekly Reports</p>
                    <p className="text-xs text-gray-500 dark:text-gray-400">Receive summary reports of security activities each week</p>
                  </div>
                  <label className="relative inline-flex items-center cursor-pointer">
                    <input type="checkbox" checked={weeklyReports} onChange={() => setWeeklyReports(!weeklyReports)} className="sr-only peer" />
                    <div className="w-11 h-6 bg-gray-200 peer-focus:outline-none peer-focus:ring-4 peer-focus:ring-purple-300 dark:peer-focus:ring-purple-800 rounded-full peer dark:bg-gray-700 peer-checked:after:translate-x-full peer-checked:after:border-white after:content-[''] after:absolute after:top-[2px] after:left-[2px] after:bg-white after:border-gray-300 after:border after:rounded-full after:h-5 after:w-5 after:transition-all dark:border-gray-600 peer-checked:bg-purple-600"></div>
                  </label>
                </div>
                
                <div className="flex items-center justify-between">
                  <div>
                    <p className="text-sm font-medium text-gray-700 dark:text-gray-300">Product Updates</p>
                    <p className="text-xs text-gray-500 dark:text-gray-400">Get notified about new features and improvements</p>
                  </div>
                  <label className="relative inline-flex items-center cursor-pointer">
                    <input type="checkbox" checked={productUpdates} onChange={() => setProductUpdates(!productUpdates)} className="sr-only peer" />
                    <div className="w-11 h-6 bg-gray-200 peer-focus:outline-none peer-focus:ring-4 peer-focus:ring-purple-300 dark:peer-focus:ring-purple-800 rounded-full peer dark:bg-gray-700 peer-checked:after:translate-x-full peer-checked:after:border-white after:content-[''] after:absolute after:top-[2px] after:left-[2px] after:bg-white after:border-gray-300 after:border after:rounded-full after:h-5 after:w-5 after:transition-all dark:border-gray-600 peer-checked:bg-purple-600"></div>
                  </label>
                </div>
              </div>
              
              <div className="mt-6">
                <button
                  className="px-6 py-3 text-sm font-medium text-white bg-purple-600 rounded-lg shadow-sm hover:bg-purple-700 focus:outline-none focus:ring-2 focus:ring-purple-600"
                >
                  <Save className="w-4 h-4 mr-2 inline" />
                  Save Preferences
                </button>
              </div>
            </div>
          </div>
        )}

        {/* API Access Tab Content */}
        {activeTab === 'api' && (
          <div className="min-w-0 p-6 bg-white rounded-lg shadow-sm dark:bg-gray-800">
            <div className="flex justify-between items-center mb-6">
              <h3 className="text-lg font-semibold text-gray-700 dark:text-gray-300">API Keys</h3>
              <div className="flex space-x-2">
                <div className="relative">
                  <input
                    type="text"
                    placeholder="Key name..."
                    className="text-sm dark:bg-gray-700 dark:border-gray-600 border rounded-md px-3 py-2 focus:ring-2 focus:ring-purple-600 focus:outline-none"
                    value={newApiKeyName}
                    onChange={(e) => setNewApiKeyName(e.target.value)}
                  />
                </div>
                <button
                  onClick={generateApiKey}
                  className="px-4 py-2 text-sm font-medium text-white bg-purple-600 rounded-lg shadow-sm hover:bg-purple-700 focus:outline-none focus:ring-2 focus:ring-purple-600"
                >
                  Generate New Key
                </button>
              </div>
            </div>
            
            <div className="overflow-x-auto">
              <table className="w-full text-sm text-left">
                <thead className="text-xs uppercase bg-gray-50 dark:bg-gray-700">
                  <tr>
                    <th className="px-6 py-3 text-gray-700 dark:text-gray-300">Name</th>
                    <th className="px-6 py-3 text-gray-700 dark:text-gray-300">Key</th>
                    <th className="px-6 py-3 text-gray-700 dark:text-gray-300">Created</th>
                    <th className="px-6 py-3 text-gray-700 dark:text-gray-300">Last Used</th>
                    <th className="px-6 py-3 text-gray-700 dark:text-gray-300">Actions</th>
                  </tr>
                </thead>
                <tbody>
                  {apiKeys.map((key) => (
                    <tr key={key.key} className="border-b dark:border-gray-700">
                      <td className="px-6 py-4 font-medium text-gray-900 dark:text-white">
                        {key.name}
                      </td>
                      <td className="px-6 py-4 font-mono">
                        {key.key.substring(0, 10)}•••••••••••
                      </td>
                      <td className="px-6 py-4 text-gray-600 dark:text-gray-400">
                        {key.created.toLocaleDateString()}
                      </td>
                      <td className="px-6 py-4 text-gray-600 dark:text-gray-400">
                        {key.lastUsed ? key.lastUsed.toLocaleDateString() : 'Never'}
                      </td>
                      <td className="px-6 py-4">
                        <button
                          onClick={() => deleteApiKey(key.key)}
                          className="text-red-600 hover:text-red-900 dark:text-red-400 dark:hover:text-red-300"
                        >
                          Delete
                        </button>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
            
            <div className="mt-6 p-4 bg-gray-50 dark:bg-gray-700 rounded-md">
              <h4 className="text-md font-medium text-gray-800 dark:text-gray-200 mb-2">API Documentation</h4>
              <p className="text-sm text-gray-600 dark:text-gray-300 mb-4">
                Learn how to use the OxSuite API to integrate security features into your applications.
              </p>
              <a 
                href="/docs/api" 
                className="text-sm text-purple-600 hover:text-purple-700 dark:text-purple-400 dark:hover:text-purple-300 font-medium"
              >
                View API Documentation →
              </a>
            </div>
          </div>
        )}
      </motion.div>
    </Layout>
  )
}
