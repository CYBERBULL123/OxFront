import React, { useState, useEffect } from 'react'
import { Shield, AlertCircle, CheckCircle, ExternalLink, RefreshCw } from 'lucide-react'
import SecurityPermissionCheck, { SecurityPermission } from './SecurityPermissionCheck'

interface SecurityToolIntegration {
  id: string
  name: string
  type: 'scanner' | 'monitor' | 'analyzer' | 'reporter'
  isConnected: boolean
  statusMessage?: string
  lastSync?: string
  url?: string
}

const ExternalSecurityTools: React.FC = () => {
  const [integrations, setIntegrations] = useState<SecurityToolIntegration[]>([
    {
      id: 'virustotal',
      name: 'VirusTotal',
      type: 'analyzer',
      isConnected: true,
      statusMessage: 'Connected and syncing data',
      lastSync: new Date(Date.now() - 1000 * 60 * 30).toISOString(), // 30 minutes ago
      url: 'https://www.virustotal.com'
    },
    {
      id: 'shodan',
      name: 'Shodan',
      type: 'scanner',
      isConnected: true,
      statusMessage: 'Connected and monitoring',
      lastSync: new Date(Date.now() - 1000 * 60 * 120).toISOString(), // 2 hours ago
      url: 'https://www.shodan.io'
    },
    {
      id: 'qualys',
      name: 'Qualys Vulnerability Scanner',
      type: 'scanner',
      isConnected: false,
      statusMessage: 'API key expired',
      url: 'https://www.qualys.com'
    },
    {
      id: 'nist',
      name: 'NIST NVD',
      type: 'reporter',
      isConnected: true,
      statusMessage: 'Connected and receiving CVE updates',
      lastSync: new Date(Date.now() - 1000 * 60 * 60 * 2).toISOString(), // 2 hours ago
      url: 'https://nvd.nist.gov'
    },
    {
      id: 'snyk',
      name: 'Snyk',
      type: 'analyzer',
      isConnected: true,
      statusMessage: 'Connected and scanning repositories',
      lastSync: new Date(Date.now() - 1000 * 60 * 180).toISOString(), // 3 hours ago
      url: 'https://snyk.io'
    }
  ])
  
  const [loading, setLoading] = useState(false)

  const refreshIntegrations = async () => {
    setLoading(true)
    // Simulate API call to refresh integrations
    await new Promise(resolve => setTimeout(resolve, 1500))
    
    // Update last sync time for connected integrations
    setIntegrations(prevIntegrations => 
      prevIntegrations.map(integration => 
        integration.isConnected 
          ? { 
              ...integration, 
              lastSync: new Date().toISOString() 
            } 
          : integration
      )
    )
    
    setLoading(false)
  }

  const toggleConnection = (id: string) => {
    setIntegrations(prevIntegrations => 
      prevIntegrations.map(integration => 
        integration.id === id 
          ? { 
              ...integration, 
              isConnected: !integration.isConnected,
              lastSync: integration.isConnected ? undefined : new Date().toISOString(),
              statusMessage: integration.isConnected 
                ? 'Disconnected' 
                : 'Connected and syncing data'
            } 
          : integration
      )
    )
  }

  const formatTimeAgo = (timestamp?: string) => {
    if (!timestamp) return 'Never'
    
    const now = new Date()
    const date = new Date(timestamp)
    const diffMs = now.getTime() - date.getTime()
    const diffSecs = Math.floor(diffMs / 1000)
    const diffMins = Math.floor(diffSecs / 60)
    const diffHours = Math.floor(diffMins / 60)
    const diffDays = Math.floor(diffHours / 24)

    if (diffDays > 0) {
      return `${diffDays}d ago`
    } else if (diffHours > 0) {
      return `${diffHours}h ago`
    } else if (diffMins > 0) {
      return `${diffMins}m ago`
    } else {
      return 'Just now'
    }
  }

  return (
    <SecurityPermissionCheck requiredPermission={SecurityPermission.VIEW_ADVANCED}>
      <div className="bg-white dark:bg-gray-800 rounded-lg shadow-lg p-6">
        <div className="flex justify-between items-center mb-6">
          <h2 className="text-xl font-semibold flex items-center">
            <Shield className="mr-2 text-blue-500" size={24} />
            External Security Integrations
          </h2>
          <button
            onClick={refreshIntegrations}
            disabled={loading}
            className="px-4 py-2 bg-blue-500 hover:bg-blue-600 text-white rounded-lg flex items-center transition-colors disabled:bg-blue-300"
          >
            <RefreshCw size={16} className={`mr-2 ${loading ? 'animate-spin' : ''}`} />
            {loading ? 'Refreshing...' : 'Refresh'}
          </button>
        </div>

        <div className="space-y-4">
          {integrations.map((integration) => (
            <div 
              key={integration.id} 
              className="border border-gray-200 dark:border-gray-700 rounded-lg p-4 hover:bg-gray-50 dark:hover:bg-gray-750 transition-colors"
            >
              <div className="flex justify-between items-start flex-wrap">
                <div className="flex items-start">
                  <div className={`p-2 rounded-full mt-1 ${
                    integration.isConnected 
                      ? 'bg-green-100 dark:bg-green-900/30 text-green-500' 
                      : 'bg-red-100 dark:bg-red-900/30 text-red-500'
                  }`}>
                    {integration.isConnected ? <CheckCircle size={20} /> : <AlertCircle size={20} />}
                  </div>
                  <div className="ml-3">
                    <div className="flex items-center">
                      <h3 className="font-medium text-gray-800 dark:text-white">{integration.name}</h3>
                      {integration.url && (
                        <a 
                          href={integration.url} 
                          target="_blank" 
                          rel="noopener noreferrer" 
                          className="ml-2 text-blue-500 hover:text-blue-600 dark:text-blue-400"
                        >
                          <ExternalLink size={14} />
                        </a>
                      )}
                    </div>
                    
                    <div className="flex space-x-2 text-xs mt-1">
                      <span className={`px-2 py-0.5 rounded-full ${
                        integration.type === 'scanner' 
                          ? 'bg-blue-100 dark:bg-blue-900/30 text-blue-600 dark:text-blue-400' 
                          : integration.type === 'analyzer'
                            ? 'bg-purple-100 dark:bg-purple-900/30 text-purple-600 dark:text-purple-400'
                            : integration.type === 'monitor'
                              ? 'bg-yellow-100 dark:bg-yellow-900/30 text-yellow-600 dark:text-yellow-400'
                              : 'bg-gray-100 dark:bg-gray-900/30 text-gray-600 dark:text-gray-400'
                      }`}>
                        {integration.type}
                      </span>
                      
                      {integration.isConnected && integration.lastSync && (
                        <span className="px-2 py-0.5 rounded-full bg-gray-100 dark:bg-gray-700 text-gray-600 dark:text-gray-400">
                          Last sync: {formatTimeAgo(integration.lastSync)}
                        </span>
                      )}
                    </div>
                    
                    <p className="text-sm text-gray-500 dark:text-gray-400 mt-1">
                      {integration.statusMessage || 'No status available'}
                    </p>
                  </div>
                </div>
                
                <div className="mt-3 sm:mt-0">
                  <button
                    onClick={() => toggleConnection(integration.id)}
                    className={`px-3 py-1 text-xs font-medium rounded-full ${
                      integration.isConnected 
                        ? 'bg-red-50 text-red-600 hover:bg-red-100 dark:bg-red-900/20 dark:text-red-400' 
                        : 'bg-green-50 text-green-600 hover:bg-green-100 dark:bg-green-900/20 dark:text-green-400'
                    }`}
                  >
                    {integration.isConnected ? 'Disconnect' : 'Connect'}
                  </button>
                </div>
              </div>
            </div>
          ))}
        </div>
      </div>
    </SecurityPermissionCheck>
  )
}

export default ExternalSecurityTools
