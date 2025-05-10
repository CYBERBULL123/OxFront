import React, { useState, useEffect } from 'react'
import { Shield, AlertTriangle, CheckCircle, Database, Code } from 'lucide-react'
import { analyzeQuery } from '@/lib/api'
import SecurityPermissionCheck from './SecurityPermissionCheck'

interface SecurityMetric {
  label: string
  value: number
  change: number
  icon: React.ReactNode
  color: string
}

const SecurityMetricsWidget: React.FC = () => {
  const [metrics, setMetrics] = useState<SecurityMetric[]>([
    {
      label: "Threat Score",
      value: 78,
      change: 2,
      icon: <Shield className="w-5 h-5" />,
      color: "text-red-500 bg-red-100 dark:bg-red-900 dark:text-red-200",
    },
    {
      label: "Vulnerabilities",
      value: 24,
      change: -3,
      icon: <AlertTriangle className="w-5 h-5" />,
      color: "text-orange-500 bg-orange-100 dark:bg-orange-900 dark:text-orange-200",
    },
    {
      label: "Security Compliance",
      value: 92,
      change: 5,
      icon: <CheckCircle className="w-5 h-5" />,
      color: "text-green-500 bg-green-100 dark:bg-green-900 dark:text-green-200",
    },
    {
      label: "Code Security Score",
      value: 85,
      change: 4,
      icon: <Code className="w-5 h-5" />,
      color: "text-blue-500 bg-blue-100 dark:bg-blue-900 dark:text-blue-200",
    }
  ])
  const [loading, setLoading] = useState(false)

  useEffect(() => {
    const fetchSecurityMetrics = async () => {
      try {
        setLoading(true)
        // In a real implementation, you would call an API to get real security metrics
        // For now, we'll use the mocked data above
        
        // Simulating an API call delay
        await new Promise(resolve => setTimeout(resolve, 1000))
        
        // If you have an API endpoint for security metrics, you could do:
        // const response = await analyzeQuery("get current security metrics");
        // const realMetrics = response.metrics;
        // setMetrics(realMetrics);
        
        setLoading(false)
      } catch (error) {
        console.error('Error fetching security metrics:', error)
        setLoading(false)
      }
    }

    fetchSecurityMetrics()
  }, [])

  if (loading) {
    return (
      <div className="bg-white dark:bg-gray-800 rounded-lg shadow-lg p-4">
        <h2 className="text-xl font-semibold mb-4 flex items-center">
          <Shield className="mr-2 text-blue-500" size={24} />
          Security Metrics
        </h2>
        <div className="animate-pulse grid grid-cols-2 gap-4">
          {[...Array(4)].map((_, i) => (
            <div key={i} className="h-24 bg-gray-200 dark:bg-gray-700 rounded"></div>
          ))}
        </div>
      </div>
    )
  }

  return (
    <div className="bg-white dark:bg-gray-800 rounded-lg shadow-lg p-4">
      <h2 className="text-xl font-semibold mb-4 flex items-center">
        <Shield className="mr-2 text-blue-500" size={24} />
        Security Metrics
      </h2>
      <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
        {metrics.map((metric, index) => (
          <div 
            key={index} 
            className="border border-gray-200 dark:border-gray-700 rounded-lg p-4 flex flex-col"
          >
            <div className="flex items-center mb-2">
              <div className={`p-2 rounded-full mr-3 ${metric.color}`}>
                {metric.icon}
              </div>
              <div>
                <h3 className="text-sm font-medium text-gray-600 dark:text-gray-400">
                  {metric.label}
                </h3>
                <div className="flex items-center mt-1">
                  <span className="text-2xl font-bold text-gray-800 dark:text-white">
                    {metric.value}{metric.label.includes('Score') || metric.label.includes('Compliance') ? '%' : ''}
                  </span>
                  <span className={`ml-2 text-sm font-medium ${metric.change > 0 ? 'text-green-500' : metric.change < 0 ? 'text-red-500' : 'text-gray-500'}`}>
                    {metric.change > 0 ? '+' : ''}{metric.change}%
                  </span>
                </div>
              </div>
            </div>
            <div className="mt-2 w-full bg-gray-200 dark:bg-gray-700 rounded-full h-2.5">
              <div 
                className={`h-2.5 rounded-full ${
                  metric.value > 80 ? 'bg-green-500' : 
                  metric.value > 60 ? 'bg-yellow-500' : 
                  'bg-red-500'
                }`}
                style={{ width: `${metric.value}%` }}
              ></div>
            </div>
          </div>
        ))}
      </div>
    </div>
  )
}

export default SecurityMetricsWidget
