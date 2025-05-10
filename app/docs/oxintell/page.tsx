'use client'

import React from 'react'
import Layout from '../../../components/Layout'
import { motion } from 'framer-motion'
import { 
  Brain, Shield, AlertTriangle, Search, Info, Settings, 
  Globe, FileText, Database, Code, MessageSquare, ExternalLink, Server
} from 'lucide-react'
import Link from 'next/link'

export default function OxIntellDocs() {
  return (
    <Layout>
      <motion.div
        initial={{ opacity: 0, y: 20 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ duration: 0.5 }}
        className="max-w-4xl mx-auto"
      >
        <div className="flex items-center justify-between mb-6">
          <h2 className="text-3xl font-semibold text-gray-800 dark:text-white">OxIntell Documentation</h2>
          <Link 
            href="/oxintell" 
            className="flex items-center px-4 py-2 bg-blue-500 text-white rounded-lg hover:bg-blue-600 transition-colors"
          >
            <Brain className="mr-2 w-5 h-5" />
            Open OxIntell
          </Link>
        </div>

        {/* Overview Section */}
        <section className="mb-8 bg-white dark:bg-gray-800 p-6 rounded-lg shadow-md">
          <h3 className="text-2xl font-semibold text-gray-700 dark:text-gray-300 mb-4 flex items-center">
            <Info className="mr-2 w-5 h-5 text-gray-600 dark:text-gray-400" />
            Overview
          </h3>
          <p className="text-gray-600 dark:text-gray-400 mb-4">
            OxIntell is an advanced cybersecurity analysis and threat intelligence platform powered by AI. It provides comprehensive security insights through domain analysis, file scanning, CVE tracking, code security scanning, and AI-assisted security chat. The platform helps organizations identify, assess, and mitigate security threats proactively.
          </p>
        </section>

        {/* Key Features Section */}
        <section className="mb-8 bg-white dark:bg-gray-800 p-6 rounded-lg shadow-md">
          <h3 className="text-2xl font-semibold text-gray-700 dark:text-gray-300 mb-4 flex items-center">
            <Brain className="mr-2 w-5 h-5 text-gray-600 dark:text-gray-400" />
            Key Features
          </h3>
          <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
            <div className="border border-gray-200 dark:border-gray-700 rounded-lg p-4">
              <div className="flex items-center mb-2">
                <Globe className="w-5 h-5 text-blue-500 mr-2" />
                <h4 className="font-medium text-gray-700 dark:text-gray-300">Domain Analysis</h4>
              </div>
              <p className="text-sm text-gray-600 dark:text-gray-400">
                Analyze domain reputation, WHOIS information, DNS records, and open ports to identify potential security risks and vulnerabilities.
              </p>
            </div>
            
            <div className="border border-gray-200 dark:border-gray-700 rounded-lg p-4">
              <div className="flex items-center mb-2">
                <FileText className="w-5 h-5 text-red-500 mr-2" />
                <h4 className="font-medium text-gray-700 dark:text-gray-300">File Analysis</h4>
              </div>
              <p className="text-sm text-gray-600 dark:text-gray-400">
                Scan files for malware, trojans, and other malicious content using advanced threat detection engines and machine learning.
              </p>
            </div>
            
            <div className="border border-gray-200 dark:border-gray-700 rounded-lg p-4">
              <div className="flex items-center mb-2">
                <Database className="w-5 h-5 text-yellow-500 mr-2" />
                <h4 className="font-medium text-gray-700 dark:text-gray-300">CVE Tracking</h4>
              </div>
              <p className="text-sm text-gray-600 dark:text-gray-400">
                Monitor and analyze Common Vulnerabilities and Exposures (CVEs) with detailed information about severity, affected systems, and remediation steps.
              </p>
            </div>
            
            <div className="border border-gray-200 dark:border-gray-700 rounded-lg p-4">
              <div className="flex items-center mb-2">
                <Code className="w-5 h-5 text-green-500 mr-2" />
                <h4 className="font-medium text-gray-700 dark:text-gray-300">Code Security Scanning</h4>
              </div>
              <p className="text-sm text-gray-600 dark:text-gray-400">
                Identify security vulnerabilities, bugs, and best practice violations in source code across multiple programming languages.
              </p>
            </div>
            
            <div className="border border-gray-200 dark:border-gray-700 rounded-lg p-4">
              <div className="flex items-center mb-2">
                <MessageSquare className="w-5 h-5 text-purple-500 mr-2" />
                <h4 className="font-medium text-gray-700 dark:text-gray-300">Security Chat</h4>
              </div>
              <p className="text-sm text-gray-600 dark:text-gray-400">
                Get expert security advice and answers to cybersecurity questions through an AI-powered security assistant.
              </p>
            </div>
            
            <div className="border border-gray-200 dark:border-gray-700 rounded-lg p-4">
              <div className="flex items-center mb-2">
                <Shield className="w-5 h-5 text-indigo-500 mr-2" />
                <h4 className="font-medium text-gray-700 dark:text-gray-300">Real-time Monitoring</h4>
              </div>
              <p className="text-sm text-gray-600 dark:text-gray-400">
                Track the latest security threats, vulnerabilities, and updates with real-time monitoring and alerts.
              </p>
            </div>
          </div>
        </section>

        {/* Automated Security Scanning Section */}
        <section className="mb-8 bg-white dark:bg-gray-800 p-6 rounded-lg shadow-md">
          <h3 className="text-2xl font-semibold text-gray-700 dark:text-gray-300 mb-4 flex items-center">
            <Server className="mr-2 w-5 h-5 text-gray-600 dark:text-gray-400" />
            Automated Security Scanning
          </h3>
          <p className="text-gray-600 dark:text-gray-400 mb-4">
            OxInteLL provides automated security scanning functionality that allows you to schedule regular security scans for domains, code repositories, and systems. This helps you proactively identify and address security vulnerabilities before they can be exploited.
          </p>
          
          <div className="space-y-4 mt-6">
            <div className="border border-gray-200 dark:border-gray-700 rounded-lg p-4">
              <h4 className="font-medium text-gray-700 dark:text-gray-300 mb-2">Scheduling Options</h4>
              <ul className="list-disc list-inside text-gray-600 dark:text-gray-400 space-y-2">
                <li>Hourly scans for critical infrastructure</li>
                <li>Daily scans for production environments</li>
                <li>Weekly scans for development environments</li>
                <li>Monthly comprehensive security audits</li>
              </ul>
            </div>
            
            <div className="border border-gray-200 dark:border-gray-700 rounded-lg p-4">
              <h4 className="font-medium text-gray-700 dark:text-gray-300 mb-2">Scan Types</h4>
              <ul className="list-disc list-inside text-gray-600 dark:text-gray-400 space-y-2">
                <li><strong>Domain Scans</strong>: Monitor domain reputation, check for security misconfigurations, and identify potential threats</li>
                <li><strong>Code Repository Scans</strong>: Analyze code for security vulnerabilities, bugs, and compliance issues</li>
                <li><strong>System Vulnerability Scans</strong>: Identify vulnerabilities in systems, networks, and applications</li>
              </ul>
            </div>
            
            <div className="border border-gray-200 dark:border-gray-700 rounded-lg p-4">
              <h4 className="font-medium text-gray-700 dark:text-gray-300 mb-2">Features</h4>
              <ul className="list-disc list-inside text-gray-600 dark:text-gray-400 space-y-2">
                <li>Email notifications for scan results</li>
                <li>Detailed security reports with severity ratings</li>
                <li>Historical scan data for trend analysis</li>
                <li>Integration with incident response workflows</li>
                <li>Custom scan parameters for specific security requirements</li>
              </ul>
            </div>
          </div>
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
