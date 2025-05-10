// Define user roles and their permissions
export enum SecurityRole {
  VIEWER = 'viewer',
  ANALYST = 'analyst',
  ADMIN = 'admin'
}

export interface SecurityPermission {
  id: string;
  name: string;
  description: string;
}

// Map roles to their permissions
export const securityPermissions: Record<string, SecurityPermission[]> = {
  [SecurityRole.VIEWER]: [
    {
      id: 'security:view_dashboard',
      name: 'View Security Dashboard',
      description: 'Access to view security metrics and alerts'
    },
    {
      id: 'security:view_cve',
      name: 'View CVE Information',
      description: 'Access to view CVE details and tracking'
    }
  ],
  [SecurityRole.ANALYST]: [
    {
      id: 'security:view_dashboard',
      name: 'View Security Dashboard',
      description: 'Access to view security metrics and alerts'
    },
    {
      id: 'security:view_cve',
      name: 'View CVE Information',
      description: 'Access to view CVE details and tracking'
    },
    {
      id: 'security:scan_domain',
      name: 'Scan Domains',
      description: 'Ability to scan domains for security issues'
    },
    {
      id: 'security:scan_file',
      name: 'Scan Files',
      description: 'Ability to scan files for malware and security issues'
    },
    {
      id: 'security:scan_code',
      name: 'Scan Code',
      description: 'Ability to scan code for security vulnerabilities'
    },
    {
      id: 'security:use_chat',
      name: 'Use Security Chat',
      description: 'Access to use the AI-powered security chat'
    },
    {
      id: 'security:run_scan',
      name: 'Run Immediate Scans',
      description: 'Ability to run immediate security scans'
    }
  ],
  [SecurityRole.ADMIN]: [
    {
      id: 'security:view_dashboard',
      name: 'View Security Dashboard',
      description: 'Access to view security metrics and alerts'
    },
    {
      id: 'security:view_cve',
      name: 'View CVE Information',
      description: 'Access to view CVE details and tracking'
    },
    {
      id: 'security:scan_domain',
      name: 'Scan Domains',
      description: 'Ability to scan domains for security issues'
    },
    {
      id: 'security:scan_file',
      name: 'Scan Files',
      description: 'Ability to scan files for malware and security issues'
    },
    {
      id: 'security:scan_code',
      name: 'Scan Code',
      description: 'Ability to scan code for security vulnerabilities'
    },
    {
      id: 'security:use_chat',
      name: 'Use Security Chat',
      description: 'Access to use the AI-powered security chat'
    },
    {
      id: 'security:run_scan',
      name: 'Run Immediate Scans',
      description: 'Ability to run immediate security scans'
    },
    {
      id: 'security:schedule_scan',
      name: 'Schedule Scans',
      description: 'Ability to schedule automated security scans'
    },
    {
      id: 'security:manage_users',
      name: 'Manage Security Users',
      description: 'Ability to manage user roles and permissions for security features'
    },
    {
      id: 'security:configure_system',
      name: 'Configure Security System',
      description: 'Ability to configure security system settings and integrations'
    }
  ]
};

// Helper function to check if a user has a specific permission
export const hasSecurityPermission = (
  userRole: SecurityRole,
  permissionId: string
): boolean => {
  if (!userRole || !permissionId) {
    return false;
  }
  
  const permissions = securityPermissions[userRole];
  
  if (!permissions) {
    return false;
  }
  
  return permissions.some(permission => permission.id === permissionId);
};

// Helper function to get all permissions for a role
export const getSecurityPermissionsForRole = (
  role: SecurityRole
): SecurityPermission[] => {
  return securityPermissions[role] || [];
};

export default {
  SecurityRole,
  securityPermissions,
  hasSecurityPermission,
  getSecurityPermissionsForRole
};
