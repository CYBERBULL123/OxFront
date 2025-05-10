import React, { useState, useEffect } from 'react'
import { AlertTriangle, ExternalLink } from 'lucide-react'
import { getRecentCVEs } from '@/lib/api'

interface CVE {
  cve_id: string
  description: string
  published_date: string
  severity: string
  cvss_score: number
}

const RecentCVEsWidget: React.FC = () => {
  const [cves, setCves] = useState<CVE[]>([])
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)

  useEffect(() => {
    const fetchRecentCVEs = async () => {
      try {
        setLoading(true)
        const data = await getRecentCVEs(undefined, undefined, 5)
        // Ensure that cves is always an array
        setCves(Array.isArray(data.cves) ? data.cves : [])
        setError(null)
      } catch (err) {
        console.error('Error fetching recent CVEs:', err)
        setError('Failed to load recent CVEs')
      } finally {
        setLoading(false)
      }
    }

    fetchRecentCVEs()
  }, [])

  const getSeverityColor = (severity: string) => {
    switch (severity.toLowerCase()) {
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

  const formatDate = (dateString: string) => {
    return new Date(dateString).toLocaleDateString('en-US', {
      year: 'numeric',
      month: 'short',
      day: 'numeric'
    })
  }

  const truncateDescription = (description: string, maxLength: number = 100) => {
    if (description.length <= maxLength) return description
    return description.substring(0, maxLength) + '...'
  }

  if (loading) {
    return (
      <div className="bg-white dark:bg-gray-800 rounded-lg shadow-lg p-4">
        <h2 className="text-xl font-semibold mb-4 flex items-center">
          <AlertTriangle className="mr-2 text-yellow-400" size={24} />
          Recent CVEs
        </h2>
        <div className="animate-pulse space-y-3">
          {[...Array(5)].map((_, i) => (
            <div key={i} className="h-14 bg-gray-200 dark:bg-gray-700 rounded"></div>
          ))}
        </div>
      </div>
    )
  }

  if (error) {
    return (
      <div className="bg-white dark:bg-gray-800 rounded-lg shadow-lg p-4">
        <h2 className="text-xl font-semibold mb-4 flex items-center">
          <AlertTriangle className="mr-2 text-yellow-400" size={24} />
          Recent CVEs
        </h2>
        <div className="text-red-500 dark:text-red-400">
          {error}
        </div>
      </div>
    )
  }

  return (
    <div className="bg-white dark:bg-gray-800 rounded-lg shadow-lg p-4">
      <h2 className="text-xl font-semibold mb-4 flex items-center">
        <AlertTriangle className="mr-2 text-yellow-400" size={24} />
        Recent CVEs
      </h2>
      {cves.length === 0 ? (
        <p className="text-gray-500 dark:text-gray-400">No recent CVEs found</p>
      ) : (
        <div className="space-y-3">
          {cves.map((cve) => (
            <div key={cve.cve_id} className="border border-gray-200 dark:border-gray-700 rounded-lg p-3">
              <div className="flex justify-between items-start">
                <div>
                  <div className="flex items-center">
                    <span className={`px-2 py-0.5 text-xs rounded-full ${getSeverityColor(cve.severity)}`}>
                      {cve.severity}
                    </span>
                    <span className="ml-2 text-sm text-gray-500 dark:text-gray-400">
                      {formatDate(cve.published_date)}
                    </span>
                  </div>
                  <h3 className="font-medium mt-1">
                    <a 
                      href={`https://nvd.nist.gov/vuln/detail/${cve.cve_id}`}
                      target="_blank"
                      rel="noopener noreferrer"
                      className="text-blue-500 hover:text-blue-600 dark:text-blue-400 dark:hover:text-blue-300 flex items-center"
                    >
                      {cve.cve_id}
                      <ExternalLink size={14} className="ml-1" />
                    </a>
                  </h3>
                  <p className="text-sm text-gray-600 dark:text-gray-300 mt-1">
                    {truncateDescription(cve.description)}
                  </p>
                </div>
                <div className="ml-2 flex-shrink-0">
                  <span className={`text-lg font-bold ${
                    cve.cvss_score > 8 ? 'text-red-500' : 
                    cve.cvss_score > 4 ? 'text-yellow-500' : 
                    'text-green-500'
                  }`}>
                    {cve.cvss_score.toFixed(1)}
                  </span>
                </div>
              </div>
            </div>
          ))}
        </div>
      )}
    </div>
  )
}

export default RecentCVEsWidget
