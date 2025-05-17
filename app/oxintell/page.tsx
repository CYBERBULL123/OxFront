'use client'

import React, { useState, useEffect } from 'react'
import Layout from '../../components/Layout'
import RecentCVEsWidget from '../../components/RecentCVEsWidget'
import SecurityScansManager from '../../components/SecurityScansManager'
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs'
import { Dialog, DialogContent, DialogHeader, DialogTitle, DialogTrigger } from '@/components/ui/dialog'
import { toast } from 'sonner'
import { motion } from 'framer-motion'
import { 
  Search, Shield, AlertTriangle, CheckCircle, Globe, FileText, 
  Code, MessageSquare, Database, Upload, ArrowRight, Info, 
  ChevronDown, ChevronUp, ExternalLink, Server, Lock, History
} from 'lucide-react'
import { 
  analyzeQuery, analyzeDomain, scanFile, getCVEInfo, 
  scanCode, securityChat 
} from '@/lib/api'

// Types
interface ChatMessage {
  role: 'user' | 'assistant'
  content: string
  timestamp: Date
}

interface DomainResult {
  domain: string
  whois_info: {
    registrar: string
    creation_date: string
    expiration_date: string
    domain_age?: number
    registrant_country?: string
  }
  dns_records: {
    a: string[]
    mx: string[]
    ns?: string[]
    txt: string[]
  }
  ssl_info?: {
    valid_from: string
    valid_to: string
    issuer: string
    subject: string
  } | null
  open_ports: {
    port: number
    protocol: string
    service: string
    is_secure: boolean
    description: string
    security_risk: string
  }[]
  security_score: number
  is_malicious: boolean
  recommendations: string[]
  raw_data?: any
}

interface FileResult {
  filename: string
  hash: string
  file_type: string
  scan_results: {
    malicious: number
    suspicious: number
    clean: number
    sources: {
      source: string
      result: string
      detection: 'malicious' | 'suspicious' | 'clean'
    }[]
  }
  is_malicious: boolean
  recommendations: string[]
}

interface CVEResult {
  cve_id: string
  description: string
  severity: string
  cvss_score: number
  published_date: string
  affected_products: string[]
  references: string[]
  mitigations: string[]
}

interface CodeResult {
  filename: string
  language: string
  issues: {
    line: number
    code: string
    issue: string
    severity: 'critical' | 'high' | 'medium' | 'low'
    recommendation: string
  }[]
  summary: string
  score: number
}

const OxIntell: React.FC = () => {
  // Common states
  const [activeTab, setActiveTab] = useState('domain')
  const [loading, setLoading] = useState(false)
  
  // Domain analysis states
  const [domain, setDomain] = useState('')
  const [domainResult, setDomainResult] = useState<DomainResult | null>(null)
  const [expandedPort, setExpandedPort] = useState<number | null>(null)
  const [domainHistory, setDomainHistory] = useState<{domain: string, timestamp: string, result: DomainResult}[]>([])
  
  // Load domain history from session storage
  useEffect(() => {
    if (typeof window !== 'undefined') {
      const savedHistory = sessionStorage.getItem('domainAnalysisHistory')
      if (savedHistory) {
        try {
          setDomainHistory(JSON.parse(savedHistory))
        } catch (e) {
          console.error('Error parsing domain history:', e)
        }
      }
    }
  }, [])
  
  // File analysis states
  const [file, setFile] = useState<File | null>(null)
  const [fileResult, setFileResult] = useState<FileResult | null>(null)
  
  // CVE tracking states
  const [cveId, setCveId] = useState('')
  const [cveResult, setCveResult] = useState<CVEResult | null>(null)
  
  // Code analysis states
  const [codeFile, setCodeFile] = useState<File | null>(null)
  const [codeResult, setCodeResult] = useState<CodeResult | null>(null)
  
  // Security chat states
  const [message, setMessage] = useState('')
  const [chatHistory, setChatHistory] = useState<ChatMessage[]>([])
  const [chatLoading, setChatLoading] = useState(false)

  // Domain analysis function
  const handleDomainAnalysis = async (e: React.FormEvent) => {
    e.preventDefault()
    if (!domain) return
    
    setLoading(true)
    try {
      const result = await analyzeDomain(domain)
      
      // Calculate security score based on various factors
      let securityScore = 75; // Default score
      
      // Adjust score based on SSL certificate presence
      if (result.raw_data?.ssl_info) {
        securityScore += 10;
      } else {
        securityScore -= 15;
      }
      
      // Adjust score based on open ports
      const portCount = Object.keys(result.raw_data?.port_scan || {}).length;
      if (portCount > 5) {
        securityScore -= 10;
      } else if (result.raw_data?.port_scan?.['443']) {
        securityScore += 5; // HTTPS is good
      }
      
      // Keep score in valid range
      securityScore = Math.min(100, Math.max(0, securityScore));
      
      // Determine if site is potentially malicious based on score
      const isMalicious = securityScore < 50;
      
      // Generate security recommendations based on findings
      const recommendations = [];
      
      if (!result.raw_data?.ssl_info) {
        recommendations.push('Implement SSL/TLS for secure connections');
      } else {
        const notAfterDate = new Date(result.raw_data.ssl_info.notAfter);
        const now = new Date();
        const daysDifference = Math.floor((notAfterDate.getTime() - now.getTime()) / (1000 * 60 * 60 * 24));
        
        if (daysDifference < 30) {
          recommendations.push(`Renew SSL certificate soon (expires in ${daysDifference} days)`);
        }
      }
      
      if (result.raw_data?.port_scan?.['80'] && !result.raw_data?.port_scan?.['443']) {
        recommendations.push('Enable HTTPS for all web traffic');
      }
      
      if (Object.keys(result.raw_data?.port_scan || {}).length > 0) {
        recommendations.push('Review open ports and close unnecessary services');
        recommendations.push('Implement a firewall to restrict access to essential services only');
      }
      
      recommendations.push('Regularly monitor for suspicious activity');
      
      // Extract registrar information from the nested WhoisRecord structure
      let registrar = result.raw_data?.whois?.WhoisRecord?.registrarName || 
                       result.raw_data?.whois?.WhoisRecord?.registryData?.registrarName ||
                       'Unknown';
                       
      // Extract creation and expiration dates
      let creationDate = result.raw_data?.whois?.WhoisRecord?.registryData?.createdDate || 
                         result.raw_data?.whois?.WhoisRecord?.createdDate ||
                         '';
                         
      let expirationDate = result.raw_data?.whois?.WhoisRecord?.registryData?.expiresDate || 
                           result.raw_data?.whois?.WhoisRecord?.expiresDate ||
                           '';
      
      // Transform DNS record data for display
      const cleanDnsRecords = (records: string[] | undefined) => {
        if (!records) return [];
        return records.filter(record => !record.startsWith('  - IP:') && record);
      };
      
      // Transform the backend response to match our frontend's expected structure
      const transformedResult: DomainResult = {
        domain: result.domain,
        whois_info: {
          registrar: registrar,
          creation_date: creationDate,
          expiration_date: expirationDate,
          domain_age: result.raw_data?.whois?.WhoisRecord?.estimatedDomainAge || 0,
          registrant_country: result.raw_data?.whois?.WhoisRecord?.registryData?.registrant?.country || 'Unknown',
        },
        dns_records: {
          a: result.raw_data?.ip_info?.A_Records || [],
          mx: cleanDnsRecords(result.raw_data?.ip_info?.MX_Records) || [],
          ns: cleanDnsRecords(result.raw_data?.ip_info?.NS_Records) || [],
          txt: result.raw_data?.ip_info?.TXT_Records || [],
        },
        ssl_info: result.raw_data?.ssl_info ? {
          valid_from: result.raw_data.ssl_info.notBefore || '',
          valid_to: result.raw_data.ssl_info.notAfter || '',
          issuer: result.raw_data.ssl_info.issuer?.organizationName || 'Unknown',
          subject: result.raw_data.ssl_info.subject?.commonName || '',
        } : null,
        open_ports: Object.entries(result.raw_data?.port_scan || {}).map(([port, info]: [string, any]) => ({
          port: parseInt(port),
          protocol: info.protocol || 'Unknown',
          service: info.name || 'Unknown',
          is_secure: port === '443',
          description: info.description || '',
          security_risk: info.vulnerabilities || info.causes || '',
        })),
        security_score: securityScore,
        is_malicious: isMalicious,
        recommendations: recommendations,
        raw_data: result.raw_data, // Keep raw data for debugging or advanced info
      };
      
      // Store the domain analysis in session storage for history
      const domainHistory = JSON.parse(sessionStorage.getItem('domainAnalysisHistory') || '[]');
      domainHistory.unshift({ 
        domain: domain, 
        timestamp: new Date().toISOString(),
        result: transformedResult
      });
      // Keep only the last 10 records
      if (domainHistory.length > 10) domainHistory.pop();
      sessionStorage.setItem('domainAnalysisHistory', JSON.stringify(domainHistory));
      
      setDomainResult(transformedResult)
      toast.success('Domain analysis completed')
    } catch (error) {
      console.error('Error analyzing domain:', error)
      toast.error('Failed to analyze domain')
    }
    setLoading(false)
  }
  
  // File analysis function
  const handleFileAnalysis = async (e: React.FormEvent) => {
    e.preventDefault()
    if (!file) return
    
    setLoading(true)
    try {
      const result = await scanFile(file)
      setFileResult(result)
      toast.success('File analysis completed')
    } catch (error) {
      console.error('Error analyzing file:', error)
      toast.error('Failed to analyze file')
    }
    setLoading(false)
  }
  
  // CVE tracking function
  const handleCVEAnalysis = async (e: React.FormEvent) => {
    e.preventDefault()
    if (!cveId) return
    
    setLoading(true)
    try {
      const result = await getCVEInfo(cveId)
      setCveResult(result)
      toast.success('CVE information retrieved')
    } catch (error) {
      console.error('Error getting CVE info:', error)
      toast.error('Failed to get CVE information')
    }
    setLoading(false)
  }
  
  // Code analysis function
  const handleCodeAnalysis = async (e: React.FormEvent) => {
    e.preventDefault()
    if (!codeFile) return
    
    setLoading(true)
    try {
      const result = await scanCode(codeFile)
      setCodeResult(result)
      toast.success('Code analysis completed')
    } catch (error) {
      console.error('Error analyzing code:', error)
      toast.error('Failed to analyze code')
    }
    setLoading(false)
  }
  
  // Security chat function
  const handleSendMessage = async (e: React.FormEvent) => {
    e.preventDefault()
    if (!message.trim()) return
    
    // Add user message to chat
    const userMessage: ChatMessage = {
      role: 'user',
      content: message,
      timestamp: new Date()
    }
    
    const updatedHistory = [...chatHistory, userMessage]
    setChatHistory(updatedHistory)
    setChatLoading(true)
    setMessage('')
    
    try {
      // Convert chat history to format expected by API
      const apiChatHistory = updatedHistory.map(msg => ({
        role: msg.role,
        content: msg.content
      }))
      
      const response = await securityChat(message, apiChatHistory)
      
      // Add assistant response to chat
      setChatHistory([
        ...updatedHistory,
        {
          role: 'assistant',
          content: response.response,
          timestamp: new Date()
        }
      ])
    } catch (error) {
      console.error('Error in security chat:', error)
      toast.error('Failed to get response from security assistant')
    }
    setChatLoading(false)
  }

  // Handle file input changes
  const handleFileChange = (e: React.ChangeEvent<HTMLInputElement>, setFileFunc: React.Dispatch<React.SetStateAction<File | null>>) => {
    if (e.target.files && e.target.files[0]) {
      setFileFunc(e.target.files[0])
    }
  }

  // Format date strings
  const formatDate = (dateString: string) => {
    return new Date(dateString).toLocaleDateString('en-US', {
      year: 'numeric',
      month: 'short',
      day: 'numeric'
    })
  }

  // Severity to color mapping
  const getSeverityColor = (severity: string) => {
    switch (severity.toLowerCase()) {
      case 'critical': return 'text-red-600 bg-red-100 dark:bg-red-900 dark:text-red-200'
      case 'high': return 'text-orange-600 bg-orange-100 dark:bg-orange-900 dark:text-orange-200'
      case 'medium': return 'text-yellow-600 bg-yellow-100 dark:bg-yellow-900 dark:text-yellow-200'
      case 'low': return 'text-green-600 bg-green-100 dark:bg-green-900 dark:text-green-200'
      default: return 'text-blue-600 bg-blue-100 dark:bg-blue-900 dark:text-blue-200'
    }
  }

  return (
    <Layout>
      <motion.div
        initial={{ opacity: 0, y: 20 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ duration: 0.5 }}
        className="bg-white dark:bg-gray-900 rounded-lg shadow-lg p-4 md:p-6 max-w-[1200px] mx-auto"
      >
        <div className="flex items-center mb-6">
          <div className="bg-blue-500 text-white p-2 rounded-lg mr-3">
            <Shield size={28} />
          </div>
          <h1 className="text-2xl font-bold text-gray-800 dark:text-blue-400">
            OxInteLL Cybersecurity Suite
          </h1>
        </div>
        <h1 className="text-3xl font-bold mb-6 text-blue-400 flex items-center">
          <Shield className="mr-3" size={32} />
          OxInteLL Cybersecurity Suite
        </h1>
        
        <Tabs value={activeTab} onValueChange={setActiveTab} className="w-full">
          <TabsList className="flex flex-row flex-nowrap md:flex-wrap overflow-x-auto bg-transparent dark:bg-slate-800/30 p-1 mb-8 rounded-lg gap-1">
            <TabsTrigger value="domain" className="flex items-center px-3 py-2 whitespace-nowrap data-[state=active]:bg-blue-500 data-[state=active]:text-white">
              <Globe className="mr-2" size={18} />
              <span className="text-sm">Domain</span>
            </TabsTrigger>
            <TabsTrigger value="history" className="flex items-center px-3 py-2 whitespace-nowrap">
              <History className="mr-2" size={18} />
              <span className="text-sm">History</span>
            </TabsTrigger>
            <TabsTrigger value="file" className="flex items-center px-3 py-2 whitespace-nowrap">
              <FileText className="mr-2" size={18} />
              <span className="text-sm">File</span>
            </TabsTrigger>
            <TabsTrigger value="cve" className="flex items-center px-3 py-2 whitespace-nowrap">
              <Database className="mr-2" size={18} />
              <span className="text-sm">CVE</span>
            </TabsTrigger>
            <TabsTrigger value="code" className="flex items-center px-3 py-2 whitespace-nowrap">
              <Code className="mr-2" size={18} />
              <span className="text-sm">Code</span>
            </TabsTrigger>
            <TabsTrigger value="scans" className="flex items-center px-3 py-2 whitespace-nowrap">
              <Server className="mr-2" size={18} />
              <span className="text-sm">Scans</span>
            </TabsTrigger>
            <TabsTrigger value="chat" className="flex items-center px-3 py-2 whitespace-nowrap">
              <MessageSquare className="mr-2" size={18} />
              <span className="text-sm">Chat</span>
            </TabsTrigger>
          </TabsList>
          
          {/* Domain Analysis Tab */}
          <TabsContent value="domain">
            <form onSubmit={handleDomainAnalysis} className="mb-8 p-4">
              <div className="flex items-stretch">
                <div className="relative flex-grow">
                  <input
                    type="text"
                    value={domain}
                    onChange={(e) => setDomain(e.target.value)}
                    placeholder="Enter domain name (e.g., example.com)"
                    className="w-full bg-gray-100 dark:bg-gray-700 text-gray-800 dark:text-white border border-gray-300 dark:border-gray-600 rounded-l-lg py-3 px-4 pl-12 focus:outline-none focus:border-blue-500"
                  />
                  <Globe className="absolute left-4 top-3.5 text-gray-400" size={20} />
                </div>
                <button
                  type="submit"
                  disabled={loading || !domain}
                  className="flex-shrink-0 whitespace-nowrap bg-blue-500 hover:bg-blue-600 text-white font-bold py-2 px-4 sm:px-6 rounded-r-lg transition-colors duration-200 disabled:bg-blue-300"
                >
                  <span className="hidden xs:inline">{loading ? 'Analyzing...' : 'Analyze'}</span>
                  <span className="xs:hidden">{loading ? '...' : 'Go'}</span>
                </button>
              </div>
            </form>
            
            {domainResult && (
              <motion.div
                initial={{ opacity: 0, y: 20 }}
                animate={{ opacity: 1, y: 0 }}
                className="bg-gray-100 dark:bg-gray-700 rounded-lg p-6"
              >
                <div className="flex justify-between items-center mb-6">
                  <h2 className="text-xl font-semibold flex items-center">
                    <Server className="mr-2 text-blue-400" size={24} />
                    Domain Analysis: {domainResult.domain}
                  </h2>
                  <div className="flex items-center">
                    <span className={`px-3 py-1 rounded-full text-sm font-medium ${domainResult.is_malicious ? 'bg-red-100 text-red-600 dark:bg-red-900 dark:text-red-200' : 'bg-green-100 text-green-600 dark:bg-green-900 dark:text-green-200'}`}>
                      {domainResult.is_malicious ? 'Potentially Malicious' : 'Safe'}
                    </span>
                    <div className="ml-3 flex items-center">
                      <span className="text-gray-600 dark:text-gray-300 text-sm mr-2">Security Score:</span>
                      <span className={`text-lg font-bold ${domainResult.security_score > 70 ? 'text-green-500' : domainResult.security_score > 40 ? 'text-yellow-500' : 'text-red-500'}`}>
                        {domainResult.security_score}/100
                      </span>
                    </div>
                  </div>
                </div>
                
                <div className="grid grid-cols-1 md:grid-cols-2 gap-6 mb-6">
                  {/* WHOIS Information */}
                  <div className="bg-white dark:bg-gray-800 rounded-lg p-4 shadow">
                    <h3 className="text-lg font-semibold mb-3">WHOIS Information</h3>
                    <div className="space-y-2">
                      {domainResult.whois_info.registrar && (
                        <div>
                          <span className="text-gray-600 dark:text-gray-400">Registrar:</span>{' '}
                          <span className="font-medium">{domainResult.whois_info.registrar}</span>
                        </div>
                      )}
                      {domainResult.whois_info.creation_date && (
                        <div>
                          <span className="text-gray-600 dark:text-gray-400">Created:</span>{' '}
                          <span className="font-medium">{new Date(domainResult.whois_info.creation_date).toLocaleDateString()}</span>
                        </div>
                      )}
                      {domainResult.whois_info.expiration_date && (
                        <div>
                          <span className="text-gray-600 dark:text-gray-400">Expires:</span>{' '}
                          <span className="font-medium">{new Date(domainResult.whois_info.expiration_date).toLocaleDateString()}</span>
                        </div>
                      )}
                      {domainResult.whois_info.domain_age !== undefined && (
                        <div>
                          <span className="text-gray-600 dark:text-gray-400">Domain Age:</span>{' '}
                          <span className="font-medium">{domainResult.whois_info.domain_age} days</span>
                        </div>
                      )}
                      {domainResult.whois_info.registrant_country && (
                        <div>
                          <span className="text-gray-600 dark:text-gray-400">Registrant Country:</span>{' '}
                          <span className="font-medium">{domainResult.whois_info.registrant_country}</span>
                        </div>
                      )}
                    </div>
                  </div>
                  
                  {/* DNS Records */}
                  <div className="bg-white dark:bg-gray-800 rounded-lg p-4 shadow">
                    <h3 className="text-lg font-semibold mb-3">DNS Records</h3>
                    <div className="space-y-2">
                      {domainResult.dns_records.a && domainResult.dns_records.a.length > 0 && (
                        <div>
                          <span className="text-gray-600 dark:text-gray-400">A Record:</span>{' '}
                          <span className="font-medium">{domainResult.dns_records.a.join(', ')}</span>
                        </div>
                      )}
                      {domainResult.dns_records.mx && domainResult.dns_records.mx.length > 0 && (
                        <div>
                          <span className="text-gray-600 dark:text-gray-400">MX Record:</span>{' '}
                          <span className="font-medium">{domainResult.dns_records.mx.join(', ')}</span>
                        </div>
                      )}
                      {domainResult.dns_records.ns && domainResult.dns_records.ns.length > 0 && (
                        <div>
                          <span className="text-gray-600 dark:text-gray-400">NS Record:</span>{' '}
                          <span className="font-medium">{domainResult.dns_records.ns.join(', ')}</span>
                        </div>
                      )}
                      {domainResult.dns_records.txt && domainResult.dns_records.txt.length > 0 && (
                        <div>
                          <span className="text-gray-600 dark:text-gray-400">TXT Record:</span>{' '}
                          <span className="font-medium">{domainResult.dns_records.txt.join(', ')}</span>
                        </div>
                      )}
                    </div>
                  </div>
                </div>
                
                {domainResult.ssl_info && (
                  <div className="bg-white dark:bg-gray-800 rounded-lg p-4 shadow col-span-1 md:col-span-2 mb-6">
                    <h3 className="text-lg font-semibold mb-3 flex items-center">
                      <span className="inline-block w-6 h-6 rounded-full bg-green-500 mr-2 flex items-center justify-center">
                        <svg xmlns="http://www.w3.org/2000/svg" className="h-4 w-4 text-white" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                          <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 15v2m-6 4h12a2 2 0 002-2v-6a2 2 0 00-2-2H6a2 2 0 00-2 2v6a2 2 0 002 2zm10-10V7a4 4 0 00-8 0v4h8z" />
                        </svg>
                      </span>
                      SSL Certificate Information
                    </h3>
                    <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                      <div>
                        <p className="text-gray-600 dark:text-gray-400 text-sm">Subject:</p>
                        <p className="font-medium">{domainResult.ssl_info.subject}</p>
                      </div>
                      <div>
                        <p className="text-gray-600 dark:text-gray-400 text-sm">Issuer:</p>
                        <p className="font-medium">{domainResult.ssl_info.issuer}</p>
                      </div>
                      <div>
                        <p className="text-gray-600 dark:text-gray-400 text-sm">Valid From:</p>
                        <p className="font-medium">{new Date(domainResult.ssl_info.valid_from).toLocaleDateString()}</p>
                      </div>
                      <div>
                        <p className="text-gray-600 dark:text-gray-400 text-sm">Valid Until:</p>
                        <p className="font-medium">{new Date(domainResult.ssl_info.valid_to).toLocaleDateString()}</p>
                      </div>
                    </div>
                  </div>
                )}
                
                {/* Open Ports */}
                <div className="bg-white dark:bg-gray-800 rounded-lg p-4 shadow mb-6">
                  <h3 className="text-lg font-semibold mb-3">Open Ports</h3>
                  {domainResult.open_ports.length === 0 ? (
                    <div className="text-center py-4 text-gray-500 dark:text-gray-400">
                      No open ports detected
                    </div>
                  ) : (
                    <div className="space-y-3">
                      {domainResult.open_ports.map((port) => (
                        <div key={port.port} className="border border-gray-200 dark:border-gray-600 rounded-lg p-3">
                          <div 
                            className="flex justify-between items-center cursor-pointer"
                            onClick={() => setExpandedPort(expandedPort === port.port ? null : port.port)}
                          >
                            <div className="flex items-center">
                              <span className={`inline-block w-3 h-3 rounded-full mr-3 ${port.is_secure ? 'bg-green-500' : 'bg-red-500'}`}></span>
                              <span className="font-medium">{port.port} / {port.protocol}</span>
                              <span className="ml-3 text-gray-600 dark:text-gray-400">{port.service}</span>
                            </div>
                            <div className="flex items-center">
                              <span className={`text-xs px-2 py-0.5 rounded-full mr-2 ${
                                port.is_secure ? 'bg-green-100 text-green-700 dark:bg-green-900 dark:text-green-300' : 'bg-yellow-100 text-yellow-700 dark:bg-yellow-900 dark:text-yellow-300'
                              }`}>
                                {port.is_secure ? 'Secure' : 'Standard'}
                              </span>
                              {expandedPort === port.port ? <ChevronUp size={16} /> : <ChevronDown size={16} />}
                            </div>
                          </div>
                          
                          {expandedPort === port.port && (
                            <div className="mt-3 pl-6 border-l-2 border-gray-200 dark:border-gray-600">
                              {port.description && <p className="mb-2 text-gray-700 dark:text-gray-300">{port.description}</p>}
                              {port.security_risk && (
                                <div className="mt-2">
                                  <span className="text-red-500 font-medium">Security Risk:</span>
                                  <p className="text-gray-700 dark:text-gray-300">{port.security_risk}</p>
                                </div>
                              )}
                            </div>
                          )}
                        </div>
                      ))}
                    </div>
                  )}
                </div>
                
                {/* Recommendations */}
                {domainResult.recommendations && domainResult.recommendations.length > 0 && (
                  <div className="bg-blue-50 dark:bg-blue-900 border-l-4 border-blue-500 p-4 rounded-r-lg">
                    <h3 className="text-lg font-semibold mb-2 text-blue-700 dark:text-blue-300">Security Recommendations</h3>
                    <ul className="list-disc pl-5 space-y-1">
                      {domainResult.recommendations.map((rec, index) => (
                        <li key={index} className="text-gray-700 dark:text-gray-300">{rec}</li>
                      ))}
                    </ul>
                  </div>
                )}
              </motion.div>
            )}
          </TabsContent>
          
          {/* Domain Analysis History Tab */}
          <TabsContent value="history">
            <div className="p-4">
              <h2 className="text-xl font-semibold mb-4 flex items-center">
                <History className="mr-2 text-blue-400" size={24} />
                Domain Analysis History
              </h2>
              
              {domainHistory.length === 0 ? (
                <div className="bg-gray-100 dark:bg-gray-700 p-6 rounded-lg text-center">
                  <p className="text-gray-500 dark:text-gray-400">No domain analysis history available</p>
                </div>
              ) : (
                <div className="space-y-4">
                  {domainHistory.map((item, index) => (
                    <div 
                      key={index} 
                      className="bg-white dark:bg-gray-800 rounded-lg shadow-md p-4 hover:shadow-lg transition-shadow duration-200 cursor-pointer"
                      onClick={() => {
                        setDomain(item.domain);
                        setDomainResult(item.result);
                        setActiveTab('domain');
                      }}
                    >
                      <div className="flex justify-between items-center mb-2">
                        <div>
                          <h3 className="font-medium text-blue-500 text-lg">{item.domain}</h3>
                          <p className="text-sm text-gray-500 dark:text-gray-400">
                            Analyzed on {new Date(item.timestamp).toLocaleString()}
                          </p>
                        </div>
                        <div className="flex flex-col items-end">
                          <span className={`px-3 py-1 rounded-full text-sm font-medium mb-1 ${
                            item.result.is_malicious 
                              ? 'bg-red-100 text-red-600 dark:bg-red-900 dark:text-red-200' 
                              : 'bg-green-100 text-green-600 dark:bg-green-900 dark:text-green-200'
                          }`}>
                            {item.result.is_malicious ? 'Potentially Malicious' : 'Safe'}
                          </span>
                          <span className="text-sm font-medium">
                            Score: <span className={
                              item.result.security_score > 70 ? 'text-green-500' : 
                              item.result.security_score > 40 ? 'text-yellow-500' : 
                              'text-red-500'
                            }>{item.result.security_score}/100</span>
                          </span>
                        </div>
                      </div>
                      
                      <div className="grid grid-cols-2 gap-2 mt-3 text-sm">
                        <div>
                          <span className="text-gray-600 dark:text-gray-400">Registrar:</span>{' '}
                          <span className="text-gray-800 dark:text-gray-200">{item.result.whois_info.registrar || 'N/A'}</span>
                        </div>
                        <div>
                          <span className="text-gray-600 dark:text-gray-400">SSL:</span>{' '}
                          <span className="text-gray-800 dark:text-gray-200">{item.result.ssl_info ? 'Valid' : 'Not detected'}</span>
                        </div>
                        <div>
                          <span className="text-gray-600 dark:text-gray-400">Open Ports:</span>{' '}
                          <span className="text-gray-800 dark:text-gray-200">{item.result.open_ports.length}</span>
                        </div>
                        <div>
                          <span className="text-gray-600 dark:text-gray-400">Created:</span>{' '}
                          <span className="text-gray-800 dark:text-gray-200">
                            {item.result.whois_info.creation_date ? new Date(item.result.whois_info.creation_date).toLocaleDateString() : 'N/A'}
                          </span>
                        </div>
                      </div>
                    </div>
                  ))}
                </div>
              )}
            </div>
          </TabsContent>
          
          {/* File Analysis Tab */}
          <TabsContent value="file">
            <form onSubmit={handleFileAnalysis} className="mb-8 p-4">
              <div className="mb-4">
                <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-2">
                  Upload file for malware/security analysis
                </label>
                <div className="flex items-center justify-center w-full">
                  <label className="flex flex-col w-full h-32 border-2 border-dashed border-gray-300 dark:border-gray-600 rounded-lg cursor-pointer hover:bg-gray-50 dark:hover:bg-gray-700">
                    <div className="flex flex-col items-center justify-center pt-5 pb-6">
                      <Upload className="w-10 h-10 text-gray-400" />
                      <p className="mb-2 text-sm text-gray-500 dark:text-gray-400">
                        <span className="font-semibold">Click to upload</span> or drag and drop
                      </p>
                      <p className="text-xs text-gray-500 dark:text-gray-400">Maximum file size: 50MB</p>
                    </div>
                    <input 
                      id="file-upload" 
                      type="file" 
                      className="hidden" 
                      onChange={(e) => handleFileChange(e, setFile)}
                    />
                  </label>
                </div>
                {file && (
                  <div className="mt-2 text-sm text-gray-600 dark:text-gray-400">
                    Selected file: {file.name} ({(file.size / 1024 / 1024).toFixed(2)} MB)
                  </div>
                )}
              </div>
              <button
                type="submit"
                disabled={loading || !file}
                className="w-full bg-blue-500 hover:bg-blue-600 text-white font-bold py-3 px-4 rounded-lg transition-colors duration-200 disabled:bg-blue-300"
              >
                {loading ? 'Analyzing file...' : 'Analyze File'}
              </button>
            </form>
            
            {fileResult && (
              <motion.div
                initial={{ opacity: 0, y: 20 }}
                animate={{ opacity: 1, y: 0 }}
                className="bg-gray-100 dark:bg-gray-700 rounded-lg p-6"
              >
                <div className="flex justify-between items-center mb-6">
                  <h2 className="text-xl font-semibold flex items-center">
                    <FileText className="mr-2 text-blue-400" size={24} />
                    File Analysis: {fileResult.filename}
                  </h2>
                  <div className="flex items-center">
                    <span className={`px-3 py-1 rounded-full text-sm font-medium ${fileResult.is_malicious ? 'bg-red-100 text-red-600 dark:bg-red-900 dark:text-red-200' : 'bg-green-100 text-green-600 dark:bg-green-900 dark:text-green-200'}`}>
                      {fileResult.is_malicious ? 'Potentially Malicious' : 'Safe'}
                    </span>
                  </div>
                </div>
                
                <div className="grid grid-cols-1 md:grid-cols-2 gap-6 mb-6">
                  {/* File information */}
                  <div className="bg-white dark:bg-gray-800 rounded-lg p-4 shadow">
                    <h3 className="text-lg font-semibold mb-3">File Information</h3>
                    <div className="space-y-2">
                      <div>
                        <span className="text-gray-600 dark:text-gray-400">File type:</span>{' '}
                        <span className="font-medium">{fileResult.file_type}</span>
                      </div>
                      <div>
                        <span className="text-gray-600 dark:text-gray-400">Hash (SHA-256):</span>{' '}
                        <span className="font-mono text-sm break-all">{fileResult.hash}</span>
                      </div>
                    </div>
                  </div>
                  
                  {/* Scan Summary */}
                  <div className="bg-white dark:bg-gray-800 rounded-lg p-4 shadow">
                    <h3 className="text-lg font-semibold mb-3">Scan Summary</h3>
                    <div className="grid grid-cols-3 gap-3">
                      <div className="bg-red-50 dark:bg-red-900 p-3 rounded-lg text-center">
                        <span className="block text-2xl font-bold text-red-600 dark:text-red-300">{fileResult.scan_results.malicious}</span>
                        <span className="text-sm text-red-600 dark:text-red-300">Malicious</span>
                      </div>
                      <div className="bg-yellow-50 dark:bg-yellow-900 p-3 rounded-lg text-center">
                        <span className="block text-2xl font-bold text-yellow-600 dark:text-yellow-300">{fileResult.scan_results.suspicious}</span>
                        <span className="text-sm text-yellow-600 dark:text-yellow-300">Suspicious</span>
                      </div>
                      <div className="bg-green-50 dark:bg-green-900 p-3 rounded-lg text-center">
                        <span className="block text-2xl font-bold text-green-600 dark:text-green-300">{fileResult.scan_results.clean}</span>
                        <span className="text-sm text-green-600 dark:text-green-300">Clean</span>
                      </div>
                    </div>
                  </div>
                </div>
                
                {/* Scan Details */}
                <div className="bg-white dark:bg-gray-800 rounded-lg p-4 shadow mb-6">
                  <h3 className="text-lg font-semibold mb-3">Scan Details</h3>
                  <div className="overflow-x-auto">
                    <table className="min-w-full divide-y divide-gray-200 dark:divide-gray-700">
                      <thead>
                        <tr>
                          <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-400 uppercase tracking-wider">Source</th>
                          <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-400 uppercase tracking-wider">Result</th>
                          <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-400 uppercase tracking-wider">Detection</th>
                        </tr>
                      </thead>
                      <tbody className="divide-y divide-gray-200 dark:divide-gray-700">
                        {fileResult.scan_results.sources.map((source, idx) => (
                          <tr key={idx} className={idx % 2 === 0 ? 'bg-gray-50 dark:bg-gray-900' : ''}>
                            <td className="px-6 py-4 whitespace-nowrap text-sm font-medium">{source.source}</td>
                            <td className="px-6 py-4 whitespace-nowrap text-sm">{source.result}</td>
                            <td className="px-6 py-4 whitespace-nowrap">
                              <span className={`px-2 py-1 text-xs rounded-full ${
                                source.detection === 'malicious' 
                                  ? 'bg-red-100 text-red-800 dark:bg-red-900 dark:text-red-200' 
                                  : source.detection === 'suspicious' 
                                    ? 'bg-yellow-100 text-yellow-800 dark:bg-yellow-900 dark:text-yellow-200' 
                                    : 'bg-green-100 text-green-800 dark:bg-green-900 dark:text-green-200'
                              }`}>
                                {source.detection}
                              </span>
                            </td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>
                </div>
                
                {/* Recommendations */}
                {fileResult.recommendations && fileResult.recommendations.length > 0 && (
                  <div className="bg-blue-50 dark:bg-blue-900 border-l-4 border-blue-500 p-4 rounded-r-lg">
                    <h3 className="text-lg font-semibold mb-2 text-blue-700 dark:text-blue-300">Security Recommendations</h3>
                    <ul className="list-disc pl-5 space-y-1">
                      {fileResult.recommendations.map((rec, index) => (
                        <li key={index} className="text-gray-700 dark:text-gray-300">{rec}</li>
                      ))}
                    </ul>
                  </div>
                )}
              </motion.div>
            )}
          </TabsContent>
          
          {/* CVE Tracking Tab */}
          <TabsContent value="cve">
            <form onSubmit={handleCVEAnalysis} className="mb-8 p-4">
              <div className="flex items-stretch">
                <div className="relative flex-grow">
                  <input
                    type="text"
                    value={cveId}
                    onChange={(e) => setCveId(e.target.value)}
                    placeholder="Enter CVE ID (e.g., CVE-2021-44228)"
                    className="w-full bg-gray-100 dark:bg-gray-700 text-gray-800 dark:text-white border border-gray-300 dark:border-gray-600 rounded-l-lg py-3 px-4 pl-12 focus:outline-none focus:border-blue-500"
                  />
                  <Database className="absolute left-4 top-3.5 text-gray-400" size={20} />
                </div>
                <button
                  type="submit"
                  disabled={loading || !cveId}
                  className="flex-shrink-0 whitespace-nowrap bg-blue-500 hover:bg-blue-600 text-white font-bold py-2 px-4 sm:px-6 rounded-r-lg transition-colors duration-200 disabled:bg-blue-300"
                >
                  <span className="hidden xs:inline">{loading ? 'Retrieving...' : 'Get Info'}</span>
                  <span className="xs:hidden">{loading ? '...' : 'Go'}</span>
                </button>
              </div>
            </form>
            
            {cveResult && (
              <motion.div
                initial={{ opacity: 0, y: 20 }}
                animate={{ opacity: 1, y: 0 }}
                className="bg-gray-100 dark:bg-gray-700 rounded-lg p-6"
              >
                <div className="flex justify-between items-center mb-6">
                  <h2 className="text-xl font-semibold flex items-center">
                    <Shield className="mr-2 text-blue-400" size={24} />
                    {cveResult.cve_id}
                  </h2>
                  <div className="flex items-center">
                    <span className={`px-3 py-1 rounded-full text-sm font-medium ${
                      cveResult.severity === 'CRITICAL' 
                        ? 'bg-red-100 text-red-600 dark:bg-red-900 dark:text-red-200' 
                        : cveResult.severity === 'HIGH' 
                          ? 'bg-orange-100 text-orange-600 dark:bg-orange-900 dark:text-orange-200' 
                          : cveResult.severity === 'MEDIUM' 
                            ? 'bg-yellow-100 text-yellow-600 dark:bg-yellow-900 dark:text-yellow-200' 
                            : 'bg-green-100 text-green-600 dark:bg-green-900 dark:text-green-200'
                    }`}>
                      {cveResult.severity}
                    </span>
                    <div className="ml-3 flex items-center">
                      <span className="text-gray-600 dark:text-gray-300 text-sm mr-2">CVSS Score:</span>
                      <span className={`text-lg font-bold ${
                        cveResult.cvss_score > 8 ? 'text-red-500' : cveResult.cvss_score > 4 ? 'text-yellow-500' : 'text-green-500'
                      }`}>
                        {cveResult.cvss_score.toFixed(1)}
                      </span>
                    </div>
                  </div>
                </div>
                
                <div className="bg-white dark:bg-gray-800 rounded-lg p-4 shadow mb-6">
                  <h3 className="text-lg font-semibold mb-2">Description</h3>
                  <p className="text-gray-700 dark:text-gray-300">{cveResult.description}</p>
                  <div className="mt-3 text-sm text-gray-500 dark:text-gray-400">
                    Published: {formatDate(cveResult.published_date)}
                  </div>
                </div>
                
                <div className="grid grid-cols-1 md:grid-cols-2 gap-6 mb-6">
                  {/* Affected Products */}
                  <div className="bg-white dark:bg-gray-800 rounded-lg p-4 shadow">
                    <h3 className="text-lg font-semibold mb-3">Affected Products</h3>
                    <ul className="list-disc pl-5 space-y-1">
                      {cveResult.affected_products.map((product, index) => (
                        <li key={index} className="text-gray-700 dark:text-gray-300">{product}</li>
                      ))}
                    </ul>
                  </div>
                  
                  {/* Mitigations */}
                  <div className="bg-white dark:bg-gray-800 rounded-lg p-4 shadow">
                    <h3 className="text-lg font-semibold mb-3">Mitigations</h3>
                    <ul className="list-disc pl-5 space-y-1">
                      {cveResult.mitigations.map((mitigation, index) => (
                        <li key={index} className="text-gray-700 dark:text-gray-300">{mitigation}</li>
                      ))}
                    </ul>
                  </div>
                </div>
                
                {/* References */}
                <div className="bg-white dark:bg-gray-800 rounded-lg p-4 shadow">
                  <h3 className="text-lg font-semibold mb-3">References</h3>
                  <ul className="space-y-2">
                    {cveResult.references.map((ref, index) => (
                      <li key={index} className="flex items-center">
                        <ExternalLink size={14} className="mr-2 text-blue-400" />
                        <a 
                          href={ref} 
                          target="_blank" 
                          rel="noopener noreferrer" 
                          className="text-blue-500 hover:text-blue-600 dark:text-blue-400 dark:hover:text-blue-300 break-all"
                        >
                          {ref}
                        </a>
                      </li>
                    ))}
                  </ul>
                </div>
              </motion.div>
            )}
          </TabsContent>
          
          {/* Code Scanning Tab */}
          <TabsContent value="code">
            <form onSubmit={handleCodeAnalysis} className="mb-8 p-4">
              <div className="mb-4">
                <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-2">
                  Upload code file for security analysis
                </label>
                <div className="flex items-center justify-center w-full">
                  <label className="flex flex-col w-full h-32 border-2 border-dashed border-gray-300 dark:border-gray-600 rounded-lg cursor-pointer hover:bg-gray-50 dark:hover:bg-gray-700">
                    <div className="flex flex-col items-center justify-center pt-5 pb-6">
                      <Upload className="w-10 h-10 text-gray-400" />
                      <p className="mb-2 text-sm text-gray-500 dark:text-gray-400">
                        <span className="font-semibold">Click to upload</span> or drag and drop
                      </p>
                      <p className="text-xs text-gray-500 dark:text-gray-400">
                        Supports: .js, .py, .java, .php, .go, .c, .cpp, etc.
                      </p>
                    </div>
                    <input 
                      id="code-upload" 
                      type="file" 
                      className="hidden" 
                      onChange={(e) => handleFileChange(e, setCodeFile)}
                    />
                  </label>
                </div>
                {codeFile && (
                  <div className="mt-2 text-sm text-gray-600 dark:text-gray-400">
                    Selected file: {codeFile.name} ({(codeFile.size / 1024).toFixed(2)} KB)
                  </div>
                )}
              </div>
              <button
                type="submit"
                disabled={loading || !codeFile}
                className="w-full bg-blue-500 hover:bg-blue-600 text-white font-bold py-3 px-4 rounded-lg transition-colors duration-200 disabled:bg-blue-300"
              >
                {loading ? 'Scanning code...' : 'Scan Code'}
              </button>
            </form>
            
            {codeResult && (
              <motion.div
                initial={{ opacity: 0, y: 20 }}
                animate={{ opacity: 1, y: 0 }}
                className="bg-gray-100 dark:bg-gray-700 rounded-lg p-6"
              >
                <div className="flex justify-between items-center mb-6">
                  <h2 className="text-xl font-semibold flex items-center">
                    <Code className="mr-2 text-blue-400" size={24} />
                    Code Analysis: {codeResult.filename}
                  </h2>
                  <div className="flex items-center">
                    <span className="text-gray-600 dark:text-gray-300 text-sm mr-2">Security Score:</span>
                    <span className={`text-lg font-bold ${
                      codeResult.score > 80 ? 'text-green-500' : codeResult.score > 60 ? 'text-yellow-500' : 'text-red-500'
                    }`}>
                      {codeResult.score}/100
                    </span>
                  </div>
                </div>
                
                <div className="bg-white dark:bg-gray-800 rounded-lg p-4 shadow mb-6">
                  <h3 className="text-lg font-semibold mb-2">Summary</h3>
                  <p className="text-gray-700 dark:text-gray-300">{codeResult.summary}</p>
                </div>
                
                {/* Issues List */}
                <div className="bg-white dark:bg-gray-800 rounded-lg p-4 shadow mb-6">
                  <h3 className="text-lg font-semibold mb-3">Security Issues ({codeResult.issues.length})</h3>
                  <div className="space-y-4">
                    {codeResult.issues.map((issue, index) => (
                      <div key={index} className={`border-l-4 rounded p-3 ${
                        issue.severity === 'critical' 
                          ? 'border-red-500 bg-red-50 dark:bg-red-900/20' 
                          : issue.severity === 'high' 
                            ? 'border-orange-500 bg-orange-50 dark:bg-orange-900/20' 
                            : issue.severity === 'medium' 
                              ? 'border-yellow-500 bg-yellow-50 dark:bg-yellow-900/20' 
                              : 'border-green-500 bg-green-50 dark:bg-green-900/20'
                      }`}>
                        <div className="flex justify-between items-start">
                          <div>
                            <div className="flex items-center">
                              <span className={`px-2 py-0.5 text-xs rounded-full ${getSeverityColor(issue.severity)}`}>
                                {issue.severity.toUpperCase()}
                              </span>
                              <span className="ml-2 text-gray-600 dark:text-gray-400">
                                Line {issue.line}
                              </span>
                            </div>
                            <p className="mt-1 text-gray-800 dark:text-gray-200 font-medium">{issue.issue}</p>
                          </div>
                        </div>
                        <pre className="mt-2 p-2 bg-gray-800 text-white text-xs rounded overflow-x-auto">{issue.code}</pre>
                        <div className="mt-2">
                          <span className="text-blue-600 dark:text-blue-400 text-sm font-medium">Recommendation:</span>
                          <p className="text-gray-700 dark:text-gray-300 text-sm">{issue.recommendation}</p>
                        </div>
                      </div>
                    ))}
                  </div>
                </div>
              </motion.div>
            )}
          </TabsContent>
          
          {/* Automated Security Scans Tab */}
          <TabsContent value="scans">
            <SecurityScansManager />
          </TabsContent>
          
          {/* Security Chat Tab */}
          <TabsContent value="chat">
            <div className="bg-white dark:bg-gray-800 rounded-lg shadow-lg p-4 h-[600px] flex flex-col">
              <div className="flex items-center mb-4 p-2 bg-blue-50 dark:bg-blue-900/50 rounded-lg">
                <Lock className="text-blue-500 mr-2" size={20} />
                <div>
                  <h3 className="font-medium text-blue-700 dark:text-blue-300">Security Assistant</h3>
                  <p className="text-xs text-gray-500 dark:text-gray-400">
                    Ask questions about cybersecurity, threat analysis, and best practices
                  </p>
                </div>
              </div>
              
              <div className="flex-grow overflow-auto px-2 mb-4 space-y-4">
                {chatHistory.length === 0 ? (
                  <div className="h-full flex flex-col items-center justify-center text-gray-400">
                    <MessageSquare size={48} className="mb-3 opacity-40" />
                    <p className="text-center">No messages yet. Start the conversation by asking a security question.</p>
                  </div>
                ) : (
                  chatHistory.map((msg, index) => (
                    <div 
                      key={index} 
                      className={`flex ${msg.role === 'user' ? 'justify-end' : 'justify-start'}`}
                    >
                      <div className={`max-w-[80%] rounded-lg p-3 ${
                        msg.role === 'user' 
                          ? 'bg-blue-500 text-white' 
                          : 'bg-gray-100 dark:bg-gray-700 text-gray-800 dark:text-white'
                      }`}>
                        <p>{msg.content}</p>
                        <div className={`text-xs mt-1 ${
                          msg.role === 'user' 
                            ? 'text-blue-200' 
                            : 'text-gray-500 dark:text-gray-400'
                        }`}>
                          {msg.timestamp.toLocaleTimeString()}
                        </div>
                      </div>
                    </div>
                  ))
                )}
                {chatLoading && (
                  <div className="flex justify-start">
                    <div className="max-w-[80%] rounded-lg p-3 bg-gray-100 dark:bg-gray-700">
                      <div className="flex space-x-2">
                        <div className="w-2 h-2 rounded-full bg-gray-400 animate-bounce"></div>
                        <div className="w-2 h-2 rounded-full bg-gray-400 animate-bounce [animation-delay:0.2s]"></div>
                        <div className="w-2 h-2 rounded-full bg-gray-400 animate-bounce [animation-delay:0.4s]"></div>
                      </div>
                    </div>
                  </div>
                )}
              </div>
              
              <form onSubmit={handleSendMessage} className="mt-auto">
                <div className="relative">
                  <input
                    type="text"
                    value={message}
                    onChange={(e) => setMessage(e.target.value)}
                    placeholder="Type your security question..."
                    className="w-full bg-gray-100 dark:bg-gray-700 text-gray-800 dark:text-white border border-gray-300 dark:border-gray-600 rounded-lg py-3 px-4 pr-12 focus:outline-none focus:border-blue-500"
                    disabled={chatLoading}
                  />
                  <button
                    type="submit"
                    disabled={chatLoading || !message.trim()}
                    className="absolute right-2 top-2 bg-blue-500 hover:bg-blue-600 text-white rounded-lg p-1.5 transition-colors duration-200 disabled:bg-blue-300"
                  >
                    <ArrowRight size={20} />
                  </button>
                </div>
              </form>
            </div>
          </TabsContent>
        </Tabs>
      </motion.div>
      
      <motion.div
        initial={{ opacity: 0, y: 20 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ delay: 0.2, duration: 0.5 }}
        className="mt-8 grid grid-cols-1 md:grid-cols-2 gap-6"
      >
        <RecentCVEsWidget />
        
        <div className="bg-white dark:bg-gray-800 rounded-lg shadow-lg p-6">
          <h2 className="text-xl font-semibold mb-4 flex items-center">
            <AlertTriangle className="mr-2 text-yellow-400" size={24} />
            Security Status
          </h2>
          <ul className="space-y-3">
            <li className="flex items-start p-2 border-l-4 border-green-400 bg-green-50 dark:bg-green-900/20 pl-3">
              <CheckCircle size={16} className="mr-2 text-green-500 mt-0.5" />
              <div>
                <p className="font-medium">Firewall Status</p>
                <p className="text-sm text-gray-600 dark:text-gray-400">All systems operational</p>
              </div>
            </li>
            <li className="flex items-start p-2 border-l-4 border-yellow-400 bg-yellow-50 dark:bg-yellow-900/20 pl-3">
              <AlertTriangle size={16} className="mr-2 text-yellow-500 mt-0.5" />
              <div>
                <p className="font-medium">System Updates</p>
                <p className="text-sm text-gray-600 dark:text-gray-400">2 updates pending installation</p>
              </div>
            </li>
            <li className="flex items-start p-2 border-l-4 border-blue-400 bg-blue-50 dark:bg-blue-900/20 pl-3">
              <Shield size={16} className="mr-2 text-blue-500 mt-0.5" />
              <div>
                <p className="font-medium">Antivirus</p>
                <p className="text-sm text-gray-600 dark:text-gray-400">Last scan: 2 hours ago</p>
              </div>
            </li>
          </ul>
        </div>
      </motion.div>
    </Layout>
  )
}

export default OxIntell

