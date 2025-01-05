'use client'

import React, { useState } from 'react'
import Layout from '../../components/Layout'
import { motion } from 'framer-motion'
import { Search, Shield, AlertTriangle, CheckCircle } from 'lucide-react'
import { analyzeQuery } from '@/lib/api'

const OxIntell: React.FC = () => {
  const [query, setQuery] = useState('')
  const [result, setResult] = useState<string | null>(null)
  const [loading, setLoading] = useState(false)

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault()
    setLoading(true)
    try {
      const analysisResult = await analyzeQuery(query)
      setResult(analysisResult)
    } catch (error) {
      console.error('Error analyzing query:', error)
      setResult('An error occurred while analyzing the query.')
    }
    setLoading(false)
  }

  return (
    <Layout>
      <motion.div
        initial={{ opacity: 0, y: 20 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ duration: 0.5 }}
        className="bg-white dark:bg-gray-800 rounded-lg shadow-lg p-6"
      >
        <h1 className="text-3xl font-bold mb-6 text-blue-400">OxIntell 🧠</h1>
        <form onSubmit={handleSubmit} className="mb-8">
          <div className="relative">
            <input
              type="text"
              value={query}
              onChange={(e) => setQuery(e.target.value)}
              placeholder="Enter your security query..."
              className="w-full bg-gray-100 dark:bg-gray-700 text-gray-800 dark:text-white border border-gray-300 dark:border-gray-600 rounded-lg py-3 px-4 pl-12 focus:outline-none focus:border-blue-500"
            />
            <Search className="absolute left-4 top-3.5 text-gray-400" size={20} />
          </div>
          <button
            type="submit"
            disabled={loading}
            className="mt-4 bg-blue-500 hover:bg-blue-600 text-white font-bold py-2 px-4 rounded-lg transition-colors duration-200"
          >
            {loading ? 'Analyzing...' : 'Analyze'}
          </button>
        </form>
        {result && (
          <motion.div
            initial={{ opacity: 0, y: 20 }}
            animate={{ opacity: 1, y: 0 }}
            className="bg-gray-100 dark:bg-gray-700 rounded-lg p-4"
          >
            <h2 className="text-xl font-semibold mb-2 flex items-center">
              <Shield className="mr-2 text-green-400" size={24} />
              Analysis Result
            </h2>
            <p>{result}</p>
          </motion.div>
        )}
      </motion.div>
      <motion.div
        initial={{ opacity: 0, y: 20 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ delay: 0.2, duration: 0.5 }}
        className="mt-8 grid grid-cols-1 md:grid-cols-2 gap-6"
      >
        <div className="bg-white dark:bg-gray-800 rounded-lg shadow-lg p-6">
          <h2 className="text-xl font-semibold mb-4 flex items-center">
            <AlertTriangle className="mr-2 text-yellow-400" size={24} />
            Threat Alerts
          </h2>
          <ul className="space-y-2">
            <li className="flex items-center text-yellow-300">
              <AlertTriangle size={16} className="mr-2" />
              Potential phishing attempt detected
            </li>
            <li className="flex items-center text-green-300">
              <CheckCircle size={16} className="mr-2" />
              Network firewall up-to-date
            </li>
          </ul>
        </div>
        <div className="bg-white dark:bg-gray-800 rounded-lg shadow-lg p-6">
          <h2 className="text-xl font-semibold mb-4">Security Stats</h2>
          <div className="grid grid-cols-2 gap-4">
            <div className="text-center">
              <p className="text-3xl font-bold text-blue-400">99.9%</p>
              <p className="text-sm text-gray-400">Uptime</p>
            </div>
            <div className="text-center">
              <p className="text-3xl font-bold text-green-400">0</p>
              <p className="text-sm text-gray-400">Active Threats</p>
            </div>
          </div>
        </div>
      </motion.div>
    </Layout>
  )
}

export default OxIntell

