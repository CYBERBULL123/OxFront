'use client'

import React from 'react'
import Layout from '../../../../components/Layout'
import { motion } from 'framer-motion'
import { 
  Shield, Lock, AlertTriangle, Eye, Key, Server, 
  Database, RefreshCw, FileText, CheckCircle, Users
} from 'lucide-react'
import Link from 'next/link'

export default function SecurityBestPractices() {
  return (
    <Layout>
      <motion.div
        initial={{ opacity: 0, y: 20 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ duration: 0.5 }}
        className="max-w-4xl mx-auto"
      >
        <div className="flex items-center justify-between mb-6">
          <h2 className="text-3xl font-semibold text-gray-800 dark:text-white">Security Best Practices</h2>
          <Link 
            href="/oxintell" 
            className="flex items-center px-4 py-2 bg-blue-500 text-white rounded-lg hover:bg-blue-600 transition-colors"
          >
            <Shield className="mr-2 w-5 h-5" />
            Open OxInteLL
          </Link>
        </div>

        {/* Introduction Section */}
        <section className="mb-8 bg-white dark:bg-gray-800 p-6 rounded-lg shadow-md">
          <h3 className="text-2xl font-semibold text-gray-700 dark:text-gray-300 mb-4 flex items-center">
            <Shield className="mr-2 w-5 h-5 text-blue-500" />
            Introduction
          </h3>
          <p className="text-gray-600 dark:text-gray-400 mb-4">
            This guide outlines essential security best practices for your organization. Implementing these recommendations 
            will help protect your systems, data, and users from common cyber threats and reduce your overall security risk.
          </p>
          <div className="p-4 bg-blue-50 dark:bg-blue-900/20 rounded-lg border border-blue-200 dark:border-blue-800">
            <p className="text-sm text-blue-700 dark:text-blue-300">
              <strong>Note:</strong> Security is an ongoing process, not a one-time setup. Regularly review and update your 
              security measures as new threats emerge and your infrastructure evolves.
            </p>
          </div>
        </section>

        {/* Authentication & Access Control */}
        <section className="mb-8 bg-white dark:bg-gray-800 p-6 rounded-lg shadow-md">
          <h3 className="text-2xl font-semibold text-gray-700 dark:text-gray-300 mb-4 flex items-center">
            <Lock className="mr-2 w-5 h-5 text-indigo-500" />
            Authentication & Access Control
          </h3>
          
          <div className="space-y-4">
            <div className="p-4 border border-gray-200 dark:border-gray-700 rounded-lg">
              <h4 className="font-medium text-gray-800 dark:text-gray-200 mb-2 flex items-center">
                <Key className="w-4 h-4 mr-2 text-indigo-500" />
                Strong Password Policies
              </h4>
              <ul className="list-disc list-inside space-y-1 text-gray-600 dark:text-gray-400 text-sm">
                <li>Enforce minimum password length of 12 characters</li>
                <li>Require a mix of uppercase, lowercase, numbers, and special characters</li>
                <li>Implement password expiration policies (60-90 days)</li>
                <li>Prevent password reuse (at least 10 previous passwords)</li>
                <li>Lock accounts after 5 failed login attempts</li>
              </ul>
            </div>
            
            <div className="p-4 border border-gray-200 dark:border-gray-700 rounded-lg">
              <h4 className="font-medium text-gray-800 dark:text-gray-200 mb-2 flex items-center">
                <CheckCircle className="w-4 h-4 mr-2 text-indigo-500" />
                Multi-Factor Authentication (MFA)
              </h4>
              <ul className="list-disc list-inside space-y-1 text-gray-600 dark:text-gray-400 text-sm">
                <li>Enable MFA for all user accounts, especially for privileged users</li>
                <li>Support multiple authentication methods (SMS, authenticator apps, hardware tokens)</li>
                <li>Require MFA for all remote access to systems</li>
                <li>Implement risk-based authentication for sensitive operations</li>
              </ul>
            </div>
            
            <div className="p-4 border border-gray-200 dark:border-gray-700 rounded-lg">
              <h4 className="font-medium text-gray-800 dark:text-gray-200 mb-2 flex items-center">
                <Users className="w-4 h-4 mr-2 text-indigo-500" />
                Principle of Least Privilege
              </h4>
              <ul className="list-disc list-inside space-y-1 text-gray-600 dark:text-gray-400 text-sm">
                <li>Grant users only the permissions necessary for their job functions</li>
                <li>Regularly review and audit user access rights</li>
                <li>Implement time-based access for temporary permissions</li>
                <li>Use role-based access control (RBAC) for consistent permission management</li>
              </ul>
            </div>
          </div>
        </section>

        {/* Network Security */}
        <section className="mb-8 bg-white dark:bg-gray-800 p-6 rounded-lg shadow-md">
          <h3 className="text-2xl font-semibold text-gray-700 dark:text-gray-300 mb-4 flex items-center">
            <Server className="mr-2 w-5 h-5 text-green-500" />
            Network Security
          </h3>
          
          <div className="space-y-4">
            <div className="p-4 border border-gray-200 dark:border-gray-700 rounded-lg">
              <h4 className="font-medium text-gray-800 dark:text-gray-200 mb-2">Firewalls & Network Segmentation</h4>
              <ul className="list-disc list-inside space-y-1 text-gray-600 dark:text-gray-400 text-sm">
                <li>Deploy next-generation firewalls at network boundaries</li>
                <li>Segment networks based on function and security requirements</li>
                <li>Implement internal firewalls between network segments</li>
                <li>Use private VLANs to isolate sensitive systems</li>
                <li>Review and update firewall rules quarterly</li>
              </ul>
            </div>
            
            <div className="p-4 border border-gray-200 dark:border-gray-700 rounded-lg">
              <h4 className="font-medium text-gray-800 dark:text-gray-200 mb-2">Secure Remote Access</h4>
              <ul className="list-disc list-inside space-y-1 text-gray-600 dark:text-gray-400 text-sm">
                <li>Use VPN with strong encryption for remote access</li>
                <li>Implement Zero Trust Network Access (ZTNA) principles</li>
                <li>Monitor and log all remote access sessions</li>
                <li>Enforce device compliance checks before allowing connections</li>
                <li>Disable split tunneling on VPN connections</li>
              </ul>
            </div>
            
            <div className="p-4 border border-gray-200 dark:border-gray-700 rounded-lg">
              <h4 className="font-medium text-gray-800 dark:text-gray-200 mb-2">Network Monitoring</h4>
              <ul className="list-disc list-inside space-y-1 text-gray-600 dark:text-gray-400 text-sm">
                <li>Deploy intrusion detection/prevention systems (IDS/IPS)</li>
                <li>Implement network flow analysis to detect anomalies</li>
                <li>Use network behavior analysis tools</li>
                <li>Collect and analyze DNS query logs</li>
                <li>Monitor for unauthorized devices on the network</li>
              </ul>
            </div>
          </div>
        </section>

        {/* Data Security */}
        <section className="mb-8 bg-white dark:bg-gray-800 p-6 rounded-lg shadow-md">
          <h3 className="text-2xl font-semibold text-gray-700 dark:text-gray-300 mb-4 flex items-center">
            <Database className="mr-2 w-5 h-5 text-red-500" />
            Data Security
          </h3>
          
          <div className="space-y-4">
            <div className="p-4 border border-gray-200 dark:border-gray-700 rounded-lg">
              <h4 className="font-medium text-gray-800 dark:text-gray-200 mb-2">Data Classification</h4>
              <ul className="list-disc list-inside space-y-1 text-gray-600 dark:text-gray-400 text-sm">
                <li>Classify data based on sensitivity (Public, Internal, Confidential, Restricted)</li>
                <li>Develop handling procedures for each data classification</li>
                <li>Train employees on data classification and proper handling</li>
                <li>Apply appropriate security controls based on classification</li>
              </ul>
            </div>
            
            <div className="p-4 border border-gray-200 dark:border-gray-700 rounded-lg">
              <h4 className="font-medium text-gray-800 dark:text-gray-200 mb-2">Encryption</h4>
              <ul className="list-disc list-inside space-y-1 text-gray-600 dark:text-gray-400 text-sm">
                <li>Encrypt sensitive data both at rest and in transit</li>
                <li>Use TLS 1.2+ for all web applications and services</li>
                <li>Implement full-disk encryption for all endpoint devices</li>
                <li>Use field-level encryption for sensitive database columns</li>
                <li>Secure key management with proper rotation policies</li>
              </ul>
            </div>
            
            <div className="p-4 border border-gray-200 dark:border-gray-700 rounded-lg">
              <h4 className="font-medium text-gray-800 dark:text-gray-200 mb-2">Data Loss Prevention</h4>
              <ul className="list-disc list-inside space-y-1 text-gray-600 dark:text-gray-400 text-sm">
                <li>Deploy DLP solutions to monitor and control data transfers</li>
                <li>Monitor outbound email for sensitive data</li>
                <li>Restrict USB and removable media usage</li>
                <li>Implement cloud access security brokers (CASB) for cloud services</li>
                <li>Secure file sharing with authenticated access and expiration dates</li>
              </ul>
            </div>
          </div>
        </section>

        {/* Vulnerability Management */}
        <section className="mb-8 bg-white dark:bg-gray-800 p-6 rounded-lg shadow-md">
          <h3 className="text-2xl font-semibold text-gray-700 dark:text-gray-300 mb-4 flex items-center">
            <AlertTriangle className="mr-2 w-5 h-5 text-yellow-500" />
            Vulnerability Management
          </h3>
          
          <div className="space-y-4">
            <div className="p-4 border border-gray-200 dark:border-gray-700 rounded-lg">
              <h4 className="font-medium text-gray-800 dark:text-gray-200 mb-2">Patch Management</h4>
              <ul className="list-disc list-inside space-y-1 text-gray-600 dark:text-gray-400 text-sm">
                <li>Implement a formal patch management process</li>
                <li>Patch critical security vulnerabilities within 24-48 hours</li>
                <li>Test patches in non-production environments first</li>
                <li>Maintain an inventory of all systems and their patch status</li>
                <li>Automate patch deployment where possible</li>
              </ul>
            </div>
            
            <div className="p-4 border border-gray-200 dark:border-gray-700 rounded-lg">
              <h4 className="font-medium text-gray-800 dark:text-gray-200 mb-2">Vulnerability Scanning</h4>
              <ul className="list-disc list-inside space-y-1 text-gray-600 dark:text-gray-400 text-sm">
                <li>Conduct regular vulnerability scans (at least monthly)</li>
                <li>Perform authenticated scans for more thorough results</li>
                <li>Scan both internal and external-facing systems</li>
                <li>Prioritize vulnerabilities based on risk and impact</li>
                <li>Integrate OxInteLL automated security scanning</li>
              </ul>
            </div>
            
            <div className="p-4 border border-gray-200 dark:border-gray-700 rounded-lg">
              <h4 className="font-medium text-gray-800 dark:text-gray-200 mb-2">Penetration Testing</h4>
              <ul className="list-disc list-inside space-y-1 text-gray-600 dark:text-gray-400 text-sm">
                <li>Conduct penetration tests at least annually</li>
                <li>Include both external and internal penetration testing</li>
                <li>Perform targeted testing on critical applications</li>
                <li>Test incident response procedures during penetration tests</li>
                <li>Create remediation plans for identified issues</li>
              </ul>
            </div>
          </div>
        </section>

        {/* Incident Response */}
        <section className="mb-8 bg-white dark:bg-gray-800 p-6 rounded-lg shadow-md">
          <h3 className="text-2xl font-semibold text-gray-700 dark:text-gray-300 mb-4 flex items-center">
            <RefreshCw className="mr-2 w-5 h-5 text-orange-500" />
            Incident Response
          </h3>
          
          <div className="space-y-4">
            <div className="p-4 border border-gray-200 dark:border-gray-700 rounded-lg">
              <h4 className="font-medium text-gray-800 dark:text-gray-200 mb-2">Incident Response Plan</h4>
              <ul className="list-disc list-inside space-y-1 text-gray-600 dark:text-gray-400 text-sm">
                <li>Develop a formal incident response plan</li>
                <li>Define roles and responsibilities for incident handling</li>
                <li>Establish communication procedures and escalation paths</li>
                <li>Create templates for incident documentation</li>
                <li>Integrate with business continuity and disaster recovery plans</li>
              </ul>
            </div>
            
            <div className="p-4 border border-gray-200 dark:border-gray-700 rounded-lg">
              <h4 className="font-medium text-gray-800 dark:text-gray-200 mb-2">Detection & Analysis</h4>
              <ul className="list-disc list-inside space-y-1 text-gray-600 dark:text-gray-400 text-sm">
                <li>Implement a security information and event management (SIEM) solution</li>
                <li>Deploy endpoint detection and response (EDR) tools</li>
                <li>Establish baseline of normal network and system behavior</li>
                <li>Create alert thresholds and escalation procedures</li>
                <li>Maintain threat intelligence feeds for current attack patterns</li>
              </ul>
            </div>
            
            <div className="p-4 border border-gray-200 dark:border-gray-700 rounded-lg">
              <h4 className="font-medium text-gray-800 dark:text-gray-200 mb-2">Incident Exercises</h4>
              <ul className="list-disc list-inside space-y-1 text-gray-600 dark:text-gray-400 text-sm">
                <li>Conduct tabletop exercises quarterly</li>
                <li>Perform full-scale incident simulations annually</li>
                <li>Include scenarios for common attack types (ransomware, data breach, DDoS)</li>
                <li>Test recovery procedures and backup restoration</li>
                <li>Document lessons learned and improve processes accordingly</li>
              </ul>
            </div>
          </div>
        </section>

        {/* User Security Awareness */}
        <section className="mb-8 bg-white dark:bg-gray-800 p-6 rounded-lg shadow-md">
          <h3 className="text-2xl font-semibold text-gray-700 dark:text-gray-300 mb-4 flex items-center">
            <Users className="mr-2 w-5 h-5 text-purple-500" />
            User Security Awareness
          </h3>
          
          <div className="space-y-4">
            <div className="p-4 border border-gray-200 dark:border-gray-700 rounded-lg">
              <h4 className="font-medium text-gray-800 dark:text-gray-200 mb-2">Security Training</h4>
              <ul className="list-disc list-inside space-y-1 text-gray-600 dark:text-gray-400 text-sm">
                <li>Conduct security awareness training for all employees at onboarding</li>
                <li>Provide refresher training at least annually</li>
                <li>Include role-specific security training for IT, developers, etc.</li>
                <li>Test knowledge retention through quizzes</li>
                <li>Keep training content updated with current threats</li>
              </ul>
            </div>
            
            <div className="p-4 border border-gray-200 dark:border-gray-700 rounded-lg">
              <h4 className="font-medium text-gray-800 dark:text-gray-200 mb-2">Phishing Awareness</h4>
              <ul className="list-disc list-inside space-y-1 text-gray-600 dark:text-gray-400 text-sm">
                <li>Run regular phishing simulation campaigns</li>
                <li>Provide immediate education for users who fall for simulations</li>
                <li>Track improvement metrics over time</li>
                <li>Create easy reporting mechanisms for suspicious emails</li>
                <li>Share examples of real-world phishing attempts</li>
              </ul>
            </div>
            
            <div className="p-4 border border-gray-200 dark:border-gray-700 rounded-lg">
              <h4 className="font-medium text-gray-800 dark:text-gray-200 mb-2">Security Culture</h4>
              <ul className="list-disc list-inside space-y-1 text-gray-600 dark:text-gray-400 text-sm">
                <li>Promote a "security is everyone's responsibility" culture</li>
                <li>Recognize and reward security-conscious behavior</li>
                <li>Share security updates and news through internal channels</li>
                <li>Include security considerations in employee performance reviews</li>
                <li>Encourage reporting of security incidents without fear of punishment</li>
              </ul>
            </div>
          </div>
        </section>

        {/* OxInteLL Integration */}
        <section className="mb-8 bg-white dark:bg-gray-800 p-6 rounded-lg shadow-md">
          <h3 className="text-2xl font-semibold text-gray-700 dark:text-gray-300 mb-4 flex items-center">
            <Shield className="mr-2 w-5 h-5 text-blue-500" />
            OxInteLL Security Integration
          </h3>
          
          <p className="text-gray-600 dark:text-gray-400 mb-4">
            OxInteLL provides powerful tools to enhance your security posture. Here's how to integrate OxInteLL into your security practices:
          </p>
          
          <div className="space-y-4">
            <div className="p-4 border border-gray-200 dark:border-gray-700 rounded-lg">
              <h4 className="font-medium text-gray-800 dark:text-gray-200 mb-2">Automated Security Scanning</h4>
              <ul className="list-disc list-inside space-y-1 text-gray-600 dark:text-gray-400 text-sm">
                <li>Schedule daily scans for critical infrastructure using OxInteLL's automation features</li>
                <li>Set up notifications for high-severity findings</li>
                <li>Integrate scan results into your vulnerability management process</li>
                <li>Customize scan parameters based on your security requirements</li>
              </ul>
            </div>
            
            <div className="p-4 border border-gray-200 dark:border-gray-700 rounded-lg">
              <h4 className="font-medium text-gray-800 dark:text-gray-200 mb-2">Threat Intelligence</h4>
              <ul className="list-disc list-inside space-y-1 text-gray-600 dark:text-gray-400 text-sm">
                <li>Monitor the CVE tracking dashboard for vulnerabilities affecting your systems</li>
                <li>Use domain analysis to evaluate third-party services before integration</li>
                <li>Analyze suspicious files through the file analysis feature</li>
                <li>Leverage Security Chat for quick security guidance and recommendations</li>
              </ul>
            </div>
            
            <div className="p-4 border border-gray-200 dark:border-gray-700 rounded-lg">
              <h4 className="font-medium text-gray-800 dark:text-gray-200 mb-2">Security Development Lifecycle</h4>
              <ul className="list-disc list-inside space-y-1 text-gray-600 dark:text-gray-400 text-sm">
                <li>Integrate OxInteLL's code scanning into your development pipeline</li>
                <li>Require security scan approval before production deployments</li>
                <li>Track security metrics over time using the dashboard</li>
                <li>Conduct periodic security reviews with OxInteLL reports</li>
              </ul>
            </div>
          </div>
          
          <div className="mt-6 p-4 bg-blue-50 dark:bg-blue-900/20 rounded-lg border border-blue-200 dark:border-blue-800">
            <p className="text-sm text-blue-700 dark:text-blue-300">
              For assistance with implementing these security best practices or configuring OxInteLL for your environment, 
              please contact your security team or reach out to our support team.
            </p>
          </div>
        </section>
      </motion.div>
    </Layout>
  )
}
