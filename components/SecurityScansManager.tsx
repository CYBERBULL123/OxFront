import React, { useState, useEffect } from 'react'
import { Calendar, Clock, Target, AlertTriangle, RefreshCw, Mail, CheckCircle, XCircle, ArrowRight, Plus } from 'lucide-react'
import { 
  scheduleScan, 
  getScheduledScans, 
  getScanHistory,
  runImmediateScan
} from '@/lib/api'
import SecurityPermissionCheck, { SecurityPermission } from './SecurityPermissionCheck'

interface ScheduledScan {
  scan_id: string
  scan_type: string
  target: string
  frequency: string
  next_scan_time: string
  status: string
}

interface ScanHistoryItem {
  scan_id: string
  scan_type: string
  target: string
  start_time: string
  end_time: string
  status: string
  findings: {
    high: number
    medium: number
    low: number
    total?: number
  }
}

const SecurityScansManager: React.FC = () => {
  const [scheduledScans, setScheduledScans] = useState<ScheduledScan[]>([])
  const [scanHistory, setScanHistory] = useState<ScanHistoryItem[]>([])
  const [loading, setLoading] = useState(true)
  const [formVisible, setFormVisible] = useState(false)
  const [formData, setFormData] = useState({
    scan_type: 'domain',
    target: '',
    frequency: 'daily',
    notify_email: '',
  })
  const [error, setError] = useState<string | null>(null)
  const [success, setSuccess] = useState<string | null>(null)

  useEffect(() => {
    fetchData()
  }, [])

  const fetchData = async () => {
    try {
      setLoading(true)
      const [scheduledResponse, historyResponse] = await Promise.all([
        getScheduledScans(),
        getScanHistory(30)
      ])
      setScheduledScans(scheduledResponse.scheduled_scans || [])
      setScanHistory(historyResponse.scan_history || [])
      setError(null)
    } catch (err) {
      console.error('Error fetching security scan data:', err)
      setError('Failed to load security scan data')
    } finally {
      setLoading(false)
    }
  }

  const handleInputChange = (e: React.ChangeEvent<HTMLInputElement | HTMLSelectElement>) => {
    const { name, value } = e.target
    setFormData(prev => ({ ...prev, [name]: value }))
  }

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault()
    try {
      setLoading(true)
      const response = await scheduleScan({
        scan_type: formData.scan_type,
        target: formData.target,
        frequency: formData.frequency,
        notify_email: formData.notify_email || undefined
      })
      
      setScheduledScans(prev => [...prev, response])
      setSuccess('Security scan scheduled successfully')
      setFormVisible(false)
      setFormData({
        scan_type: 'domain',
        target: '',
        frequency: 'daily',
        notify_email: ''
      })
    } catch (err) {
      console.error('Error scheduling security scan:', err)
      setError('Failed to schedule security scan')
    } finally {
      setLoading(false)
    }
  }

  const runScanNow = async (scan: ScheduledScan) => {
    try {
      setLoading(true)
      const response = await runImmediateScan({
        scan_type: scan.scan_type,
        target: scan.target
      })
      
      // Add the new scan to history
      setScanHistory(prev => [response, ...prev])
      setSuccess('Scan initiated successfully')
    } catch (err) {
      console.error('Error running immediate scan:', err)
      setError('Failed to run immediate scan')
    } finally {
      setLoading(false)
    }
  }

  const formatDate = (dateString: string) => {
    return new Date(dateString).toLocaleString('en-US', {
      year: 'numeric',
      month: 'short',
      day: 'numeric', 
      hour: '2-digit',
      minute: '2-digit'
    })
  }

  const getScanTypeIcon = (type: string) => {
    switch (type.toLowerCase()) {
      case 'domain':
        return <Globe className="w-4 h-4" />
      case 'code':
        return <Code className="w-4 h-4" />
      case 'system':
        return <Server className="w-4 h-4" />
      default:
        return <Shield className="w-4 h-4" />
    }
  }

  const getFrequencyLabel = (frequency: string) => {
    switch (frequency) {
      case 'hourly': return 'Every hour'
      case 'daily': return 'Once a day'
      case 'weekly': return 'Once a week'
      case 'monthly': return 'Once a month'
      default: return frequency
    }
  }

  const getSeverityColors = (count: number, type: 'high' | 'medium' | 'low') => {
    const colors = {
      high: 'text-red-500 dark:text-red-400',
      medium: 'text-orange-500 dark:text-orange-400',
      low: 'text-green-500 dark:text-green-400'
    }
    
    return count > 0 ? colors[type] : 'text-gray-400 dark:text-gray-500'
  }

  const renderScanResults = (findings: { high: number, medium: number, low: number }) => {
    return (
      <div className="flex space-x-3 text-sm">
        <div className={getSeverityColors(findings.high, 'high')}>
          {findings.high} High
        </div>
        <div className={getSeverityColors(findings.medium, 'medium')}>
          {findings.medium} Medium
        </div>
        <div className={getSeverityColors(findings.low, 'low')}>
          {findings.low} Low
        </div>
      </div>
    )
  }

  if (loading && scheduledScans.length === 0 && scanHistory.length === 0) {
    return (
      <div className="bg-white dark:bg-gray-800 rounded-lg shadow-lg p-6">
        <h2 className="text-xl font-semibold mb-6 flex items-center">
          <RefreshCw className="mr-2 text-blue-500" size={24} />
          Automated Security Scans
        </h2>
        <div className="animate-pulse space-y-4">
          <div className="h-12 bg-gray-200 dark:bg-gray-700 rounded"></div>
          <div className="h-36 bg-gray-200 dark:bg-gray-700 rounded"></div>
          <div className="h-64 bg-gray-200 dark:bg-gray-700 rounded"></div>
        </div>
      </div>
    )
  }

  return (
    <div className="bg-white dark:bg-gray-800 rounded-lg shadow-lg p-6">
      <div className="flex justify-between items-center mb-6">
        <h2 className="text-xl font-semibold flex items-center">
          <RefreshCw className="mr-2 text-blue-500" size={24} />
          Automated Security Scans
        </h2>
        <SecurityPermissionCheck requiredPermission={SecurityPermission.SCHEDULE_SCANS}>
          <button
            onClick={() => setFormVisible(!formVisible)}
            className="px-4 py-2 bg-blue-500 hover:bg-blue-600 text-white rounded-lg flex items-center transition-colors"
          >
            {formVisible ? (
              <>
                <XCircle size={16} className="mr-2" />
                Cancel
              </>
            ) : (
              <>
                <Plus size={16} className="mr-2" />
                Schedule New Scan
              </>
            )}
          </button>
        </SecurityPermissionCheck>
      </div>

      {error && (
        <div className="bg-red-100 border border-red-400 text-red-700 px-4 py-3 rounded mb-4">
          {error}
        </div>
      )}

      {success && (
        <div className="bg-green-100 border border-green-400 text-green-700 px-4 py-3 rounded mb-4">
          {success}
        </div>
      )}

      {formVisible && (
        <div className="mb-6 bg-gray-50 dark:bg-gray-750 p-4 rounded-lg border border-gray-200 dark:border-gray-700">
          <h3 className="text-lg font-medium mb-4">Schedule a New Security Scan</h3>
          <form onSubmit={handleSubmit}>
            <div className="grid grid-cols-1 md:grid-cols-2 gap-4 mb-4">
              <div>
                <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">
                  Scan Type
                </label>
                <select
                  name="scan_type"
                  value={formData.scan_type}
                  onChange={handleInputChange}
                  className="w-full px-3 py-2 border border-gray-300 dark:border-gray-600 rounded-md shadow-sm focus:outline-none focus:ring-blue-500 focus:border-blue-500 bg-white dark:bg-gray-700 text-gray-900 dark:text-gray-100"
                  required
                >
                  <option value="domain">Domain Analysis</option>
                  <option value="code">Code Security Scan</option>
                  <option value="system">System Vulnerability Scan</option>
                </select>
              </div>
              
              <div>
                <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">
                  Target
                </label>
                <input
                  type="text"
                  name="target"
                  value={formData.target}
                  onChange={handleInputChange}
                  placeholder={formData.scan_type === 'domain' ? 'example.com' : 
                              formData.scan_type === 'code' ? 'https://github.com/user/repo' : 
                              'system-name or IP address'}
                  className="w-full px-3 py-2 border border-gray-300 dark:border-gray-600 rounded-md shadow-sm focus:outline-none focus:ring-blue-500 focus:border-blue-500 bg-white dark:bg-gray-700 text-gray-900 dark:text-gray-100"
                  required
                />
              </div>
              
              <div>
                <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">
                  Frequency
                </label>
                <select
                  name="frequency"
                  value={formData.frequency}
                  onChange={handleInputChange}
                  className="w-full px-3 py-2 border border-gray-300 dark:border-gray-600 rounded-md shadow-sm focus:outline-none focus:ring-blue-500 focus:border-blue-500 bg-white dark:bg-gray-700 text-gray-900 dark:text-gray-100"
                  required
                >
                  <option value="hourly">Hourly</option>
                  <option value="daily">Daily</option>
                  <option value="weekly">Weekly</option>
                  <option value="monthly">Monthly</option>
                </select>
              </div>
              
              <div>
                <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">
                  Notification Email (Optional)
                </label>
                <input
                  type="email"
                  name="notify_email"
                  value={formData.notify_email}
                  onChange={handleInputChange}
                  placeholder="email@example.com"
                  className="w-full px-3 py-2 border border-gray-300 dark:border-gray-600 rounded-md shadow-sm focus:outline-none focus:ring-blue-500 focus:border-blue-500 bg-white dark:bg-gray-700 text-gray-900 dark:text-gray-100"
                />
              </div>
            </div>
            
            <div className="flex justify-end">
              <button
                type="submit"
                className="px-4 py-2 bg-blue-500 hover:bg-blue-600 text-white rounded-lg flex items-center transition-colors"
                disabled={loading}
              >
                {loading ? (
                  <>
                    <RefreshCw size={16} className="mr-2 animate-spin" />
                    Scheduling...
                  </>
                ) : (
                  <>
                    <Calendar size={16} className="mr-2" />
                    Schedule Scan
                  </>
                )}
              </button>
            </div>
          </form>
        </div>
      )}

      <div className="mb-8">
        <h3 className="text-lg font-medium mb-4">Scheduled Scans</h3>
        {scheduledScans.length === 0 ? (
          <p className="text-gray-500 dark:text-gray-400 text-sm italic">
            No scans currently scheduled. Use the button above to schedule a new scan.
          </p>
        ) : (
          <div className="space-y-4">
            {scheduledScans.map((scan) => (
              <div 
                key={scan.scan_id} 
                className="border border-gray-200 dark:border-gray-700 rounded-lg p-4  transition-colors"
              >
                <div className="flex justify-between flex-wrap">
                  <div>
                    <div className="flex items-center">
                      <div className="p-2 rounded-full bg-blue-100 dark:bg-blue-900 mr-3">
                        {getScanTypeIcon(scan.scan_type)}
                      </div>
                      <div>
                        <h4 className="font-medium">{scan.target}</h4>
                        <div className="text-sm text-gray-500 dark:text-gray-400 flex items-center mt-1">
                          <Clock size={14} className="mr-1" />
                          {getFrequencyLabel(scan.frequency)}
                        </div>
                      </div>
                    </div>
                  </div>
                  
                  <div className="flex items-center">
                    <div className="text-sm text-gray-500 dark:text-gray-400 mr-4">
                      <div>Next scan:</div>
                      <div className="font-medium">{formatDate(scan.next_scan_time)}</div>
                    </div>
                    
                    <button
                      onClick={() => runScanNow(scan)}
                      className="px-3 py-1 bg-green-500 hover:bg-green-600 text-white text-sm rounded flex items-center transition-colors"
                      disabled={loading}
                    >
                      <RefreshCw size={14} className="mr-1" />
                      Run Now
                    </button>
                  </div>
                </div>
              </div>
            ))}
          </div>
        )}
      </div>

      <div>
        <h3 className="text-lg font-medium mb-4">Scan History</h3>
        {scanHistory.length === 0 ? (
          <p className="text-gray-500 dark:text-gray-400 text-sm italic">
            No scan history available yet.
          </p>
        ) : (
          <div className="space-y-4">
            {scanHistory.map((scan) => (
              <div 
                key={scan.scan_id} 
                className="border border-gray-200 dark:border-gray-700 rounded-lg p-4 transition-colors"
              >
                <div className="flex justify-between items-start flex-wrap">
                  <div>
                    <div className="flex items-center">
                      <div className="p-2 rounded-full bg-blue-100 dark:bg-blue-900 mr-3">
                        {getScanTypeIcon(scan.scan_type)}
                      </div>
                      <div>
                        <h4 className="font-medium">{scan.target}</h4>
                        <div className="text-sm text-gray-500 dark:text-gray-400 flex items-center mt-1">
                          <Calendar size={14} className="mr-1" />
                          {formatDate(scan.start_time)}
                        </div>
                      </div>
                    </div>
                    
                    <div className="mt-3">
                      {renderScanResults(scan.findings)}
                    </div>
                  </div>
                  
                  <div className="flex items-center mt-2 sm:mt-0">
                    <div className={`px-3 py-1 rounded-full text-xs font-medium ${
                      scan.status === 'completed' ? 'bg-green-100 text-green-800 dark:bg-green-900 dark:text-green-200' :
                      scan.status === 'failed' ? 'bg-red-100 text-red-800 dark:bg-red-900 dark:text-red-200' :
                      'bg-blue-100 text-blue-800 dark:bg-blue-900 dark:text-blue-200'
                    }`}>
                      {scan.status}
                    </div>
                    
                    <button
                      className="ml-4 text-blue-500 hover:text-blue-600 dark:text-blue-400 dark:hover:text-blue-300 flex items-center"
                    >
                      View Details
                      <ArrowRight size={14} className="ml-1" />
                    </button>
                  </div>
                </div>
              </div>
            ))}
          </div>
        )}
      </div>
    </div>
  )
}

export default SecurityScansManager

// Add missing component imports
import { Globe, Code, Server, Shield } from 'lucide-react'
