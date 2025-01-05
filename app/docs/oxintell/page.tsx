'use client'

import React from 'react'
import Layout from '../../../components/Layout'
import { motion } from 'framer-motion'
import { Brain, Shield, AlertTriangle, Search, Info, Settings } from 'lucide-react'

export default function OxIntellDocs() {
  return (
    <Layout>
      <motion.div
        initial={{ opacity: 0, y: 20 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ duration: 0.5 }}
        className="max-w-4xl mx-auto"
      >
        <h2 className="text-3xl font-semibold text-gray-800 dark:text-white mb-6">OxIntell Documentation</h2>

        {/* Overview Section */}
        <section className="mb-8">
          <h3 className="text-2xl font-semibold text-gray-700 dark:text-gray-300 mb-4 flex items-center">
            <Info className="mr-2 w-5 h-5 text-gray-600 dark:text-gray-400" />
            Overview
          </h3>
          <p className="text-gray-600 dark:text-gray-400 mb-4">
            OxIntell is an advanced threat intelligence and analysis platform powered by AI. It provides real-time insights into potential security threats and helps organizations stay ahead of cyber attacks. The platform integrates seamlessly with existing security infrastructures to provide actionable insights.
          </p>
        </section>

        {/* Key Features Section */}
        <section className="mb-8">
          <h3 className="text-2xl font-semibold text-gray-700 dark:text-gray-300 mb-4 flex items-center">
            <Brain className="mr-2 w-5 h-5 text-gray-600 dark:text-gray-400" />
            Key Features
          </h3>
          <ul className="list-disc list-inside text-gray-600 dark:text-gray-400 space-y-2">
            <li>Real-time threat detection and analysis</li>
            <li>AI-powered risk assessment and insights</li>
            <li>Comprehensive threat intelligence database</li>
            <li>Customizable alerts and notifications</li>
            <li>Integration with existing security infrastructure</li>
          </ul>
        </section>

        {/* Technical Details Section */}
        <section className="mb-8">
          <h3 className="text-2xl font-semibold text-gray-700 dark:text-gray-300 mb-4 flex items-center">
            <Shield className="mr-2 w-5 h-5 text-gray-600 dark:text-gray-400" />
            Technical Specifications
          </h3>
          <table className="min-w-full table-auto border-collapse text-sm text-left text-gray-600 dark:text-gray-400">
            <thead>
              <tr className="border-b border-gray-200 dark:border-gray-600">
                <th className="py-2 px-4">Feature</th>
                <th className="py-2 px-4">Description</th>
              </tr>
            </thead>
            <tbody>
              <tr className="border-b border-gray-200 dark:border-gray-600">
                <td className="py-2 px-4 font-semibold">Threat Detection</td>
                <td className="py-2 px-4">Uses AI to detect real-time threats and classify them by risk level.</td>
              </tr>
              <tr className="border-b border-gray-200 dark:border-gray-600">
                <td className="py-2 px-4 font-semibold">Risk Assessment</td>
                <td className="py-2 px-4">AI-powered insights to assess risk levels and potential impact of identified threats.</td>
              </tr>
              <tr className="border-b border-gray-200 dark:border-gray-600">
                <td className="py-2 px-4 font-semibold">Custom Alerts</td>
                <td className="py-2 px-4">Set up customized alerts based on specific security concerns and threat levels.</td>
              </tr>
              <tr className="border-b border-gray-200 dark:border-gray-600">
                <td className="py-2 px-4 font-semibold">Database Integration</td>
                <td className="py-2 px-4">Integrates seamlessly with existing databases to enhance threat intelligence capabilities.</td>
              </tr>
            </tbody>
          </table>
        </section>

        {/* How to Use Section */}
        <section className="mb-8">
          <h3 className="text-2xl font-semibold text-gray-700 dark:text-gray-300 mb-4 flex items-center">
            <Search className="mr-2 w-5 h-5 text-gray-600 dark:text-gray-400" />
            How to Use OxIntell
          </h3>
          <ol className="list-decimal list-inside text-gray-600 dark:text-gray-400 space-y-4">
            <li>
              <span className="font-semibold">Access the OxIntell dashboard:</span> Navigate to the OxIntell section in your OxSuite application and log in.
            </li>
            <li>
              <span className="font-semibold">Enter your security query:</span> Use the search bar to input your specific security concern or threat you want to analyze.
            </li>
            <li>
              <span className="font-semibold">Review the analysis results:</span> OxIntell will provide a detailed analysis of the potential threat, including risk level, potential impact, and recommended actions.
            </li>
            <li>
              <span className="font-semibold">Monitor threat alerts:</span> Keep an eye on the Threat Alerts section for real-time updates on potential security issues.
            </li>
            <li>
              <span className="font-semibold">Check security stats:</span> Review the Security Stats section for an overview of your system's current security status and trends.
            </li>
          </ol>
        </section>

        {/* Best Practices Section */}
        <section className="mb-8">
          <h3 className="text-2xl font-semibold text-gray-700 dark:text-gray-300 mb-4 flex items-center">
            <AlertTriangle className="mr-2 w-5 h-5 text-gray-600 dark:text-gray-400" />
            Best Practices
          </h3>
          <ul className="list-disc list-inside text-gray-600 dark:text-gray-400 space-y-2">
            <li>Regularly update your threat intelligence database for the latest insights.</li>
            <li>Set up custom alerts for your organization's specific security concerns.</li>
            <li>Integrate OxIntell with your existing security tools for comprehensive protection.</li>
            <li>Train your team on how to interpret and act on OxIntell's analysis results.</li>
            <li>Periodically review and adjust your security policies based on OxIntell's insights and recommendations.</li>
          </ul>
        </section>

        {/* Troubleshooting Section */}
        <section className="mb-8">
          <h3 className="text-2xl font-semibold text-gray-700 dark:text-gray-300 mb-4 flex items-center">
            <Settings className="mr-2 w-5 h-5 text-gray-600 dark:text-gray-400" />
            Troubleshooting
          </h3>
          <p className="text-gray-600 dark:text-gray-400 mb-4">
            If you encounter issues while using OxIntell, please follow these steps:
          </p>
          <ul className="list-disc list-inside text-gray-600 dark:text-gray-400 space-y-2">
            <li>Ensure that your security database is up to date.</li>
            <li>Check your internet connection for any connectivity issues.</li>
            <li>If you encounter a specific threat detection issue, try clearing the cache or refreshing your session.</li>
            <li>Contact our support team with detailed error logs for faster resolution.</li>
          </ul>
        </section>

        {/* Key Modules Section */}
        <section className="mb-8">
          <h3 className="text-2xl font-semibold text-gray-700 dark:text-gray-300 mb-4 flex items-center">
            <Info className="mr-2 w-5 h-5 text-gray-600 dark:text-gray-400" />
            Key Modules of OxIntell
          </h3>
          <p className="text-gray-600 dark:text-gray-400 mb-4">
            OxIntell offers several powerful modules designed to address various cybersecurity needs:
          </p>
          <ul className="list-disc list-inside text-gray-600 dark:text-gray-400 space-y-4">
            <li><strong>OxSecure Chat </strong>: A dedicated AI-driven chat interface for cybersecurity-related questions. Engage in discussions and get expert-level answers.</li>
            <li><strong>Imagen – Advanced Image Analysis </strong>: Analyze images using Gemini Multimodal. Extract contextual data and insights for security assessments.</li>
            <li><strong>File Analysis with VirusTotal </strong>: Upload files for detailed analysis. Extract hash values and metadata, scan files using VirusTotal API, and visualize results with Seaborn.</li>
            <li><strong>Full Domain Analysis </strong>: Perform end-to-end domain analysis with WHOIS API, IP conversion, and Scapy port scanning. Get enriched insights via Gemini LLM.</li>
            <li><strong>CVE Analysis </strong>: Stay updated on critical CVEs. Analyze CVE data and receive detailed reports based on the latest vulnerabilities.</li>
            <li><strong>Code Analysis and Security </strong>: Perform deep analysis of Python, PHP, JavaScript, and other code snippets. Get feedback on security risks and best practices.</li>
          </ul>
        </section>
      </motion.div>
    </Layout>
  )
}
