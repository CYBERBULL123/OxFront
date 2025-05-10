'use client'

import React, { useEffect, useState } from 'react'
import { useSession } from 'next-auth/react'
import { Shield, AlertTriangle, Lock } from 'lucide-react'
import Link from 'next/link'

// Define security permission levels
export enum SecurityPermission {
  VIEW_BASIC = 'view_basic',
  VIEW_ADVANCED = 'view_advanced',
  SCAN = 'scan',
  SCHEDULE_SCANS = 'schedule_scans',
  MANAGE_SCANS = 'manage_scans',
  ADMIN = 'admin'
}

interface SecurityPermissionCheckProps {
  requiredPermission: SecurityPermission | SecurityPermission[]
  children: React.ReactNode
  fallback?: React.ReactNode
}

const SecurityPermissionCheck: React.FC<SecurityPermissionCheckProps> = ({
  requiredPermission,
  children,
  fallback
}) => {
  const { data: session } = useSession()
  const [hasPermission, setHasPermission] = useState<boolean>(false)
  const [loading, setLoading] = useState<boolean>(true)

  useEffect(() => {
    if (!session) {
      setHasPermission(false)
      setLoading(false)
      return
    }

    // In a real application, you would fetch the user's permissions from the server
    // For now, we'll simulate permissions based on the user's role
    const checkPermissions = async () => {
      try {
        // Simulate an API call to get user permissions
        await new Promise(resolve => setTimeout(resolve, 500))

        // Mock user permissions based on user role
        // In a real application, this would come from the API
        const userRole = session?.user?.role || 'user'
        const userPermissions = getUserPermissions(userRole)
        
        // Check if the user has the required permission(s)
        if (Array.isArray(requiredPermission)) {
          setHasPermission(requiredPermission.every(perm => userPermissions.includes(perm)))
        } else {
          setHasPermission(userPermissions.includes(requiredPermission))
        }
      } catch (error) {
        console.error('Error checking security permissions:', error)
        setHasPermission(false)
      } finally {
        setLoading(false)
      }
    }

    checkPermissions()
  }, [session, requiredPermission])

  // Function to get user permissions based on role
  const getUserPermissions = (role: string): SecurityPermission[] => {
    switch (role) {
      case 'admin':
        // Admins have all permissions
        return Object.values(SecurityPermission)
      case 'security_analyst':
        // Security analysts can view everything and run scans
        return [
          SecurityPermission.VIEW_BASIC,
          SecurityPermission.VIEW_ADVANCED,
          SecurityPermission.SCAN,
          SecurityPermission.SCHEDULE_SCANS,
          SecurityPermission.MANAGE_SCANS
        ]
      case 'security_operator':
        // Security operators can view and run basic scans
        return [
          SecurityPermission.VIEW_BASIC,
          SecurityPermission.VIEW_ADVANCED,
          SecurityPermission.SCAN
        ]
      case 'user':
        // Regular users can only view basic information
        return [SecurityPermission.VIEW_BASIC]
      default:
        // By default, users can only view basic information
        return [SecurityPermission.VIEW_BASIC]
    }
  }

  if (loading) {
    return (
      <div className="flex items-center justify-center p-4 text-gray-500">
        <Shield className="animate-pulse mr-2" size={20} />
        Checking security permissions...
      </div>
    )
  }

  if (!hasPermission) {
    return fallback || (
      <div className="bg-yellow-50 dark:bg-yellow-900/20 border border-yellow-200 dark:border-yellow-800 rounded-lg p-4">
        <div className="flex items-center">
          <AlertTriangle className="text-yellow-500 mr-3" size={24} />
          <div>
            <h3 className="font-medium text-yellow-800 dark:text-yellow-200">
              Insufficient Permissions
            </h3>
            <p className="text-sm text-yellow-700 dark:text-yellow-300 mt-1">
              You don't have the required permissions to access this feature.
            </p>
            <div className="mt-3">
              <Link 
                href="/docs/oxintell" 
                className="inline-flex items-center text-sm font-medium text-yellow-800 dark:text-yellow-200 hover:text-yellow-900 dark:hover:text-yellow-100"
              >
                <Lock className="mr-1" size={14} />
                Learn about security permissions
              </Link>
            </div>
          </div>
        </div>
      </div>
    )
  }

  return <>{children}</>
}

export default SecurityPermissionCheck