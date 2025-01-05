// File: app/docs/oxsuite/page.tsx

'use client'

import React from 'react'
import Layout from '../../../components/Layout'
import { motion } from 'framer-motion'
import { Info, Settings, Search, FileText, Box } from 'lucide-react'

export default function OxSuiteDocs() {
  return (
    <Layout>
      <motion.div
        initial={{ opacity: 0, y: 20 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ duration: 0.5 }}
        className="max-w-4xl mx-auto"
      >
        <h2 className="text-3xl font-semibold text-gray-800 dark:text-white mb-6">OxSuite Documentation</h2>

        {/* Getting Started Section */}
        <section className="mb-8">
          <h3 className="text-2xl font-semibold text-gray-700 dark:text-gray-300 mb-4 flex items-center">
            <Info className="mr-2 w-5 h-5 text-gray-600 dark:text-gray-400" />
            Getting Started
          </h3>
          <p className="text-gray-600 dark:text-gray-400 mb-4">
            Welcome to OxSuite, an integrated suite for cybersecurity, AI-driven research, and automation. This guide will walk you through the process of getting started and utilizing the various tools in OxSuite.
          </p>
        </section>

        {/* How to Access OxSuite */}
        <section className="mb-8">
          <h3 className="text-2xl font-semibold text-gray-700 dark:text-gray-300 mb-4 flex items-center">
            <Search className="mr-2 w-5 h-5 text-gray-600 dark:text-gray-400" />
            How to Access OxSuite
          </h3>
          <ol className="list-decimal list-inside text-gray-600 dark:text-gray-400 space-y-4">
            <li><strong>Login:</strong> Access OxSuite by logging into your account using your credentials.</li>
            <li><strong>Dashboard:</strong> Once logged in, you will be directed to the OxSuite dashboard where all tools and features are available.</li>
            <li><strong>Profile Setup:</strong> Customize your profile by updating your details in the settings menu.</li>
          </ol>
        </section>

        {/* Using OxSuite */}
        <section className="mb-8">
          <h3 className="text-2xl font-semibold text-gray-700 dark:text-gray-300 mb-4 flex items-center">
            <Box className="mr-2 w-5 h-5 text-gray-600 dark:text-gray-400" />
            Using OxSuite
          </h3>
          <p className="text-gray-600 dark:text-gray-400 mb-4">
            OxSuite provides several powerful tools. Below is an overview of how to use each of the components in the platform.
          </p>

          <h4 className="text-xl font-semibold text-gray-700 dark:text-gray-300 mt-6">1. OxImaGen</h4>
          <p className="text-gray-600 dark:text-gray-400 mb-4">
            Generate and analyze images using AI-powered algorithms. To get started, select OxImaGen from the dashboard, input your desired text prompts, and view the generated images.
          </p>

          <h4 className="text-xl font-semibold text-gray-700 dark:text-gray-300 mt-6">2. OxIntell</h4>
          <p className="text-gray-600 dark:text-gray-400 mb-4">
            Analyze cybersecurity threats and receive insights into potential vulnerabilities. Input your query or upload files to begin the analysis.
          </p>

          <h4 className="text-xl font-semibold text-gray-700 dark:text-gray-300 mt-6">3. OxRAG</h4>
          <p className="text-gray-600 dark:text-gray-400 mb-4">
            Conduct research and gather actionable intelligence about potential risks. Use the research tools and view reports for a detailed analysis.
          </p>
        </section>

        {/* Tools Overview */}
        <section className="mb-8">
          <h3 className="text-2xl font-semibold text-gray-700 dark:text-gray-300 mb-4 flex items-center">
            <FileText className="mr-2 w-5 h-5 text-gray-600 dark:text-gray-400" />
            Tools Overview
          </h3>
          <ul className="list-disc list-inside text-gray-600 dark:text-gray-400 space-y-2">
            <li><strong>OxImaGen:</strong> AI-powered image generation and analysis tool.</li>
            <li><strong>OxIntell:</strong> Threat intelligence platform for real-time analysis of cybersecurity threats.</li>
            <li><strong>OxRAG:</strong> Risk analysis generator for investigating vulnerabilities and security threats.</li>
          </ul>
        </section>

        {/* Troubleshooting */}
        <section className="mb-8">
          <h3 className="text-2xl font-semibold text-gray-700 dark:text-gray-300 mb-4 flex items-center">
            <Settings className="mr-2 w-5 h-5 text-gray-600 dark:text-gray-400" />
            Troubleshooting
          </h3>
          <p className="text-gray-600 dark:text-gray-400 mb-4">
            If you experience any issues with OxSuite, follow these steps to resolve common problems:
          </p>
          <ul className="list-disc list-inside text-gray-600 dark:text-gray-400 space-y-2">
            <li>Ensure all tools are up to date with the latest version.</li>
            <li>Check your internet connection for any instability.</li>
            <li>If experiencing tool errors, try clearing your cache or refreshing the page.</li>
            <li>Contact support with error logs if issues persist.</li>
          </ul>
        </section>

      </motion.div>
    </Layout>
  )
}
