import React, { useState, useEffect } from 'react'
import { Bell, ShieldAlert, Clock, User, ArrowRight } from 'lucide-react'
import Link from 'next/link'

interface SecurityAlert {
  id: string
  title: string
  description: string
  timestamp: string
  severity: 'critical' | 'high' | 'medium' | 'low'
  source: string
  isNew: boolean
}

const SecurityAlertsWidget: React.FC = () => {
  const [alerts, setAlerts] = useState<SecurityAlert[]>([
    {
      id: 'alert-1',
      title: 'Critical vulnerability detected in backend service',
      description: 'A new remote code execution vulnerability has been detected in one of your backend services.',
      timestamp: new Date(Date.now() - 1000 * 60 * 30).toISOString(), // 30 minutes ago
      severity: 'critical',
      source: 'OxInteLL Scanner',
      isNew: true
    },
    {
      id: 'alert-2',
      title: 'Suspicious login attempt detected',
      description: 'Multiple failed login attempts from unusual geographic location detected.',
      timestamp: new Date(Date.now() - 1000 * 60 * 120).toISOString(), // 2 hours ago
      severity: 'high',
      source: 'User Authentication Monitor',
      isNew: true
    },
    {
      id: 'alert-3',
      title: 'New CVE affecting your infrastructure',
      description: 'CVE-2023-34567 affects multiple services in your deployment and requires immediate attention.',
      timestamp: new Date(Date.now() - 1000 * 60 * 60 * 5).toISOString(), // 5 hours ago
      severity: 'high',
      source: 'CVE Monitor',
      isNew: false
    },
    {
      id: 'alert-4',
      title: 'Outdated software dependencies detected',
      description: 'Several npm packages with known vulnerabilities were found in your application.',
      timestamp: new Date(Date.now() - 1000 * 60 * 60 * 12).toISOString(), // 12 hours ago
      severity: 'medium',
      source: 'Dependency Scanner',
      isNew: false
    },
    {
      id: 'alert-5',
      title: 'Potential data leak detected',
      description: 'Unusual data access patterns detected in your database, possible data exfiltration attempt.',
      timestamp: new Date(Date.now() - 1000 * 60 * 60 * 24).toISOString(), // 1 day ago
      severity: 'high',
      source: 'Data Access Monitor',
      isNew: false
    }
  ])
  const [loading, setLoading] = useState(false)

  useEffect(() => {
    const fetchSecurityAlerts = async () => {
      try {
        setLoading(true)
        // In a real implementation, you would call an API to get real security alerts
        // For now, we'll use the mocked data above
        
        // Simulating an API call delay
        await new Promise(resolve => setTimeout(resolve, 1000))
        
        setLoading(false)
      } catch (error) {
        console.error('Error fetching security alerts:', error)
        setLoading(false)
      }
    }

    fetchSecurityAlerts()
  }, [])

  const getSeverityColor = (severity: string) => {
    switch (severity) {
      case 'critical':
        return 'text-red-600 bg-red-100 dark:bg-red-900 dark:text-red-200'
      case 'high':
        return 'text-orange-600 bg-orange-100 dark:bg-orange-900 dark:text-orange-200'
      case 'medium':
        return 'text-yellow-600 bg-yellow-100 dark:bg-yellow-900 dark:text-yellow-200'
      case 'low':
        return 'text-green-600 bg-green-100 dark:bg-green-900 dark:text-green-200'
      default:
        return 'text-blue-600 bg-blue-100 dark:bg-blue-900 dark:text-blue-200'
    }
  }

  const formatTimeAgo = (timestamp: string) => {
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

  if (loading) {
    return (
      <div className="bg-white dark:bg-gray-800 rounded-lg shadow-lg p-4">
        <h2 className="text-xl font-semibold mb-4 flex items-center">
          <Bell className="mr-2 text-red-500" size={24} />
          Security Alerts
        </h2>
        <div className="animate-pulse space-y-3">
          {[...Array(5)].map((_, i) => (
            <div key={i} className="h-16 bg-gray-200 dark:bg-gray-700 rounded"></div>
          ))}
        </div>
      </div>
    )
  }

  return (
    <div className="bg-white dark:bg-gray-800 rounded-lg shadow-lg p-4">
      <div className="flex justify-between items-center mb-4">
        <h2 className="text-xl font-semibold flex items-center">
          <Bell className="mr-2 text-red-500" size={24} />
          Security Alerts
        </h2>
        <Link 
          href="/oxintell" 
          className="text-sm text-blue-500 hover:text-blue-600 dark:text-blue-400 dark:hover:text-blue-300 flex items-center"
        >
          View all
          <ArrowRight size={16} className="ml-1" />
        </Link>
      </div>
      
      {alerts.length === 0 ? (
        <p className="text-gray-500 dark:text-gray-400">No security alerts found</p>
      ) : (
        <div className="space-y-3">
          {alerts.map((alert) => (
            <div 
              key={alert.id} 
              className={`border ${alert.isNew ? 'border-l-4 border-l-red-500' : 'border'} border-gray-200 dark:border-gray-700 rounded-lg p-3 transition-all`}
            >
              <div className="flex justify-between">
                <h3 className="font-medium text-gray-800 dark:text-white flex items-center">
                  {alert.isNew && (
                    <span className="w-2 h-2 bg-red-500 rounded-full mr-2"></span>
                  )}
                  {alert.title}
                </h3>
                <span className={`px-2 py-0.5 text-xs rounded-full ${getSeverityColor(alert.severity)}`}>
                  {alert.severity}
                </span>
              </div>
              <p className="text-sm text-gray-600 dark:text-gray-300 mt-1">
                {alert.description}
              </p>
              <div className="flex items-center text-xs text-gray-500 dark:text-gray-400 mt-2">
                <div className="flex items-center mr-3">
                  <Clock size={12} className="mr-1" />
                  {formatTimeAgo(alert.timestamp)}
                </div>
                <div className="flex items-center">
                  <ShieldAlert size={12} className="mr-1" />
                  {alert.source}
                </div>
              </div>
            </div>
          ))}
        </div>
      )}
    </div>
  )
}

export default SecurityAlertsWidget
