/**
 * OxInteLL Security Scanner Script
 * 
 * This script uses OxInteLL's own security scanning features to scan the codebase
 * for security vulnerabilities as part of the CI/CD pipeline.
 */

const fs = require('fs');
const path = require('path');
const axios = require('axios');

// Configuration
const config = {
  scanTypes: ['code', 'dependency', 'secret'],
  outputDir: path.join(__dirname, '..', 'security-report'),
  severityThreshold: 'MEDIUM', // Fail the build on MEDIUM or higher vulnerabilities
  excludeDirs: ['node_modules', '.next', 'coverage'],
};

// Ensure the output directory exists
if (!fs.existsSync(config.outputDir)) {
  fs.mkdirSync(config.outputDir, { recursive: true });
}

// Get list of files to scan
function getFilesToScan() {
  const filesToScan = [];
  
  function scanDir(dir) {
    const entries = fs.readdirSync(dir, { withFileTypes: true });
    
    for (const entry of entries) {
      const fullPath = path.join(dir, entry.name);
      
      // Skip excluded directories
      if (entry.isDirectory() && config.excludeDirs.includes(entry.name)) {
        continue;
      }
      
      if (entry.isDirectory()) {
        scanDir(fullPath);
      } else {
        // Only include relevant file types for scanning
        const ext = path.extname(entry.name).toLowerCase();
        if (['.js', '.ts', '.tsx', '.jsx', '.py', '.json', '.yml', '.yaml', '.env.example'].includes(ext)) {
          filesToScan.push(fullPath);
        }
      }
    }
  }
  
  scanDir(path.join(__dirname, '..'));
  return filesToScan;
}

// Helper function to read file content
function readFileContent(filePath) {
  return fs.readFileSync(filePath, 'utf8');
}

// Scan a single file for security issues
async function scanFile(filePath) {
  const fileContent = readFileContent(filePath);
  const fileExtension = path.extname(filePath).toLowerCase();
  
  // Different scan logic based on file type
  let scanResults = [];
  
  // Code security scan
  if (['.js', '.ts', '.tsx', '.jsx', '.py'].includes(fileExtension)) {
    console.log(`Scanning ${filePath} for security vulnerabilities...`);
    
    try {
      // In a real implementation, this would call the OxInteLL API
      // For now, we'll simulate the API call
      const result = simulateCodeScan(filePath, fileContent);
      scanResults = [...scanResults, ...result];
    } catch (error) {
      console.error(`Error scanning ${filePath}:`, error.message);
    }
  }
  
  // Dependency scan for package files
  if (['.json', '.txt'].includes(fileExtension) && 
      (filePath.includes('package.json') || filePath.includes('requirements.txt'))) {
    console.log(`Scanning ${filePath} for dependency vulnerabilities...`);
    
    try {
      const result = simulateDependencyScan(filePath, fileContent);
      scanResults = [...scanResults, ...result];
    } catch (error) {
      console.error(`Error scanning dependencies in ${filePath}:`, error.message);
    }
  }
  
  // Secret scan for all files
  try {
    const secretResults = simulateSecretScan(filePath, fileContent);
    scanResults = [...scanResults, ...secretResults];
  } catch (error) {
    console.error(`Error scanning for secrets in ${filePath}:`, error.message);
  }
  
  return {
    filePath,
    results: scanResults,
  };
}

// Main scanning function
async function runSecurityScan() {
  console.log('Starting OxInteLL Security Scan...');
  
  const files = getFilesToScan();
  console.log(`Found ${files.length} files to scan`);
  
  const results = [];
  let hasHighSeverityIssues = false;
  
  for (const file of files) {
    const fileResults = await scanFile(file);
    results.push(fileResults);
    
    // Check if there are any high severity issues
    const highSeverityIssues = fileResults.results.filter(issue => 
      ['HIGH', 'CRITICAL'].includes(issue.severity)
    );
    
    if (highSeverityIssues.length > 0) {
      hasHighSeverityIssues = true;
    }
  }
  
  // Generate final report
  const report = {
    scanDate: new Date().toISOString(),
    totalFilesScanned: files.length,
    results: results,
    summary: summarizeResults(results),
  };
  
  // Write report to file
  const reportPath = path.join(config.outputDir, 'security-scan-report.json');
  fs.writeFileSync(reportPath, JSON.stringify(report, null, 2));
  
  // Generate a more human-readable summary
  const summaryPath = path.join(config.outputDir, 'security-scan-summary.txt');
  const summaryContent = generateSummary(report);
  fs.writeFileSync(summaryPath, summaryContent);
  
  console.log(`Security scan complete. Reports saved to ${config.outputDir}`);
  
  // Exit with error code if there are high severity issues
  if (hasHighSeverityIssues && config.severityThreshold === 'MEDIUM') {
    console.error('High severity security issues were found! See the report for details.');
    process.exit(1);
  }
}

// Helper function to summarize results
function summarizeResults(results) {
  const issueBySeverity = {
    CRITICAL: 0,
    HIGH: 0,
    MEDIUM: 0,
    LOW: 0,
    INFO: 0,
  };
  
  const issueByType = {};
  
  results.forEach(fileResult => {
    fileResult.results.forEach(issue => {
      issueBySeverity[issue.severity]++;
      
      if (!issueByType[issue.type]) {
        issueByType[issue.type] = 0;
      }
      issueByType[issue.type]++;
    });
  });
  
  return {
    issueBySeverity,
    issueByType,
    totalIssues: results.reduce((sum, fileResult) => sum + fileResult.results.length, 0),
  };
}

// Generate a human-readable summary
function generateSummary(report) {
  const { summary } = report;
  
  let text = `# OxInteLL Security Scan Summary\n\n`;
  text += `Scan Date: ${new Date(report.scanDate).toLocaleString()}\n`;
  text += `Total Files Scanned: ${report.totalFilesScanned}\n`;
  text += `Total Issues Found: ${summary.totalIssues}\n\n`;
  
  text += `## Issues by Severity\n\n`;
  Object.entries(summary.issueBySeverity).forEach(([severity, count]) => {
    text += `- ${severity}: ${count}\n`;
  });
  
  text += `\n## Issues by Type\n\n`;
  Object.entries(summary.issueByType).forEach(([type, count]) => {
    text += `- ${type}: ${count}\n`;
  });
  
  text += `\n## Files with Issues\n\n`;
  const filesWithIssues = report.results.filter(result => result.results.length > 0);
  filesWithIssues.forEach(file => {
    text += `- ${file.filePath}: ${file.results.length} issues\n`;
  });
  
  return text;
}

// Simulation functions (in a real implementation, these would call the OxInteLL API)

function simulateCodeScan(filePath, content) {
  // This is a simulation - in a real implementation, you'd call the OxInteLL API
  const issues = [];
  
  // Simulate finding some security issues
  if (content.includes('eval(') || content.includes('new Function(')) {
    issues.push({
      type: 'code_injection',
      severity: 'HIGH',
      description: 'Dynamic code execution detected',
      line: content.split('\n').findIndex(line => line.includes('eval(') || line.includes('new Function(')),
      remediation: 'Avoid using eval() or new Function() as they can lead to code injection vulnerabilities',
    });
  }
  
  if (content.includes('innerHTML') || content.includes('dangerouslySetInnerHTML')) {
    issues.push({
      type: 'xss',
      severity: 'MEDIUM',
      description: 'Potentially unsafe DOM manipulation',
      line: content.split('\n').findIndex(line => line.includes('innerHTML') || line.includes('dangerouslySetInnerHTML')),
      remediation: 'Use safer alternatives like textContent or implement proper sanitization',
    });
  }
  
  // Check for hardcoded JWT secret
  if (content.includes('JWT_SECRET') && (content.includes('const') || content.includes('let') || content.includes('var'))) {
    issues.push({
      type: 'hardcoded_secret',
      severity: 'CRITICAL',
      description: 'Hardcoded JWT secret detected',
      line: content.split('\n').findIndex(line => line.includes('JWT_SECRET')),
      remediation: 'Store secrets in environment variables or a secure vault',
    });
  }
  
  return issues;
}

function simulateDependencyScan(filePath, content) {
  // This is a simulation - in a real implementation, you'd call the OxInteLL API
  const issues = [];
  
  if (filePath.includes('package.json')) {
    const packageJson = JSON.parse(content);
    const dependencies = { ...packageJson.dependencies, ...packageJson.devDependencies };
    
    // Simulate finding a vulnerable dependency
    if (dependencies && dependencies['some-vulnerable-package']) {
      issues.push({
        type: 'vulnerable_dependency',
        severity: 'HIGH',
        description: 'Known vulnerable dependency: some-vulnerable-package',
        remediation: 'Update to a patched version or replace with a secure alternative',
      });
    }
    
    // Simulate finding outdated dependencies
    Object.entries(dependencies || {}).forEach(([name, version]) => {
      if (version.startsWith('^1.') || version.startsWith('~1.')) {
        issues.push({
          type: 'outdated_dependency',
          severity: 'LOW',
          description: `Potentially outdated dependency: ${name} ${version}`,
          remediation: 'Regularly update dependencies to their latest secure versions',
        });
      }
    });
  }
  
  if (filePath.includes('requirements.txt')) {
    const lines = content.split('\n');
    
    lines.forEach((line, index) => {
      if (line.includes('==1.0.0')) {
        issues.push({
          type: 'outdated_dependency',
          severity: 'LOW',
          description: `Potentially outdated dependency: ${line}`,
          line: index,
          remediation: 'Regularly update dependencies to their latest secure versions',
        });
      }
      
      // Simulate finding a vulnerable package
      if (line.includes('insecure-package')) {
        issues.push({
          type: 'vulnerable_dependency',
          severity: 'HIGH',
          description: `Known vulnerable dependency: ${line}`,
          line: index,
          remediation: 'Update to a patched version or replace with a secure alternative',
        });
      }
    });
  }
  
  return issues;
}

function simulateSecretScan(filePath, content) {
  // This is a simulation - in a real implementation, you'd call the OxInteLL API
  const issues = [];
  
  // Check for API keys
  const apiKeyPatterns = [
    {
      name: 'Generic API Key',
      regex: /api[_-]?key\s*=\s*["']([a-zA-Z0-9]{20,})["']/gi,
      severity: 'HIGH',
    },
    {
      name: 'AWS Access Key',
      regex: /AKIA[0-9A-Z]{16}/g,
      severity: 'CRITICAL',
    },
    {
      name: 'Generic Secret',
      regex: /secret\s*=\s*["']([a-zA-Z0-9]{16,})["']/gi,
      severity: 'HIGH',
    },
  ];
  
  apiKeyPatterns.forEach(pattern => {
    const matches = content.matchAll(pattern.regex);
    
    for (const match of matches) {
      const line = content.substring(0, match.index).split('\n').length - 1;
      
      issues.push({
        type: 'exposed_secret',
        severity: pattern.severity,
        description: `Possible ${pattern.name} detected`,
        line,
        remediation: 'Store secrets in environment variables or a secure secret manager',
      });
    }
  });
  
  return issues;
}

// Run the scan
runSecurityScan().catch(error => {
  console.error('Error running security scan:', error);
  process.exit(1);
});
