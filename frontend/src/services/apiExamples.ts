// Example usage of API services

import {
  targetApi,
  scanApi,
  vulnerabilityApi,
  reportApi,
  dashboardApi,
  authApi,
} from '@/services/api';

/**
 * TARGETS EXAMPLES
 */

// Get all targets
async function fetchAllTargets() {
  try {
    const targets = await targetApi.getAll();
    console.log('Targets:', targets);
  } catch (error) {
    console.error('Failed to fetch targets:', error);
  }
}

// Create new target
async function createNewTarget() {
  try {
    const newTarget = await targetApi.create({
      name: 'Production API',
      url: 'https://api.example.com',
    });
    console.log('Created target:', newTarget);
  } catch (error) {
    console.error('Failed to create target:', error);
  }
}

// Upload file for scanning
async function uploadScanFile(targetId: string, file: File) {
  try {
    const result = await targetApi.uploadFile(targetId, file);
    console.log('File uploaded:', result);
  } catch (error) {
    console.error('Failed to upload file:', error);
  }
}

/**
 * SCANS EXAMPLES
 */

// Create new scan
async function startNewScan() {
  try {
    const scan = await scanApi.create({
      target: 'api-server',
      scanType: 'comprehensive',
      tools: ['nmap', 'owasp_zap', 'openvas'],
      timing: 'now',
      status: 'pending',
    });
    console.log('Scan created:', scan);
  } catch (error) {
    console.error('Failed to create scan:', error);
  }
}

// Start scan
async function startScan(scanId: string) {
  try {
    const scan = await scanApi.start(scanId);
    console.log('Scan started:', scan);
  } catch (error) {
    console.error('Failed to start scan:', error);
  }
}

// Get scan results
async function getScanResults(scanId: string) {
  try {
    const results = await scanApi.getResults(scanId);
    console.log('Scan results:', results);
  } catch (error) {
    console.error('Failed to fetch scan results:', error);
  }
}

/**
 * VULNERABILITIES EXAMPLES
 */

// Get all vulnerabilities
async function fetchAllVulnerabilities() {
  try {
    const vulnerabilities = await vulnerabilityApi.getAll();
    console.log('Vulnerabilities:', vulnerabilities);
  } catch (error) {
    console.error('Failed to fetch vulnerabilities:', error);
  }
}

// Get vulnerabilities for specific target
async function getTargetVulnerabilities(targetId: string) {
  try {
    const vulnerabilities = await vulnerabilityApi.getByTarget(targetId);
    console.log('Target vulnerabilities:', vulnerabilities);
  } catch (error) {
    console.error('Failed to fetch target vulnerabilities:', error);
  }
}

// Update vulnerability status
async function updateVulnStatus(vulnId: number, newStatus: string) {
  try {
    const updated = await vulnerabilityApi.updateStatus(vulnId, newStatus);
    console.log('Vulnerability updated:', updated);
  } catch (error) {
    console.error('Failed to update vulnerability:', error);
  }
}

// Rescan vulnerability
async function rescanVulnerability(vulnId: number) {
  try {
    const newScan = await vulnerabilityApi.rescan(vulnId);
    console.log('Rescan initiated:', newScan);
  } catch (error) {
    console.error('Failed to rescan vulnerability:', error);
  }
}

// Delete vulnerability
async function deleteVulnerability(vulnId: number) {
  try {
    await vulnerabilityApi.delete(vulnId);
    console.log('Vulnerability deleted');
  } catch (error) {
    console.error('Failed to delete vulnerability:', error);
  }
}

/**
 * REPORTS EXAMPLES
 */

// Create report
async function generateReport(targetId: string, format: 'pdf' | 'html') {
  try {
    const report = await reportApi.create(targetId, format);
    console.log('Report created:', report);
  } catch (error) {
    console.error('Failed to create report:', error);
  }
}

// Download report
async function downloadReport(reportId: string, format: 'pdf' | 'html') {
  try {
    const blob = await reportApi.download(reportId, format);
    // Create download link
    const url = window.URL.createObjectURL(blob);
    const link = document.createElement('a');
    link.href = url;
    link.download = `report_${reportId}.${format}`;
    link.click();
  } catch (error) {
    console.error('Failed to download report:', error);
  }
}

/**
 * DASHBOARD EXAMPLES
 */

// Get dashboard stats
async function getDashboardStats() {
  try {
    const stats = await dashboardApi.getStats();
    console.log('Dashboard stats:', stats);
  } catch (error) {
    console.error('Failed to fetch dashboard stats:', error);
  }
}

// Get recent activities
async function getRecentActivities(limit: number = 20) {
  try {
    const activities = await dashboardApi.getRecentActivities(limit);
    console.log('Recent activities:', activities);
  } catch (error) {
    console.error('Failed to fetch activities:', error);
  }
}

/**
 * AUTHENTICATION EXAMPLES
 */

// Login
async function login(email: string, password: string) {
  try {
    const result = await authApi.login(email, password);
    console.log('Logged in:', result.user);
  } catch (error) {
    console.error('Login failed:', error);
  }
}

// Get current user
async function getCurrentUser() {
  try {
    const user = await authApi.getCurrentUser();
    console.log('Current user:', user);
  } catch (error) {
    console.error('Failed to fetch current user:', error);
  }
}

// Logout
async function logout() {
  try {
    await authApi.logout();
    console.log('Logged out');
  } catch (error) {
    console.error('Logout failed:', error);
  }
}

export {
  fetchAllTargets,
  createNewTarget,
  uploadScanFile,
  startNewScan,
  startScan,
  getScanResults,
  fetchAllVulnerabilities,
  getTargetVulnerabilities,
  updateVulnStatus,
  rescanVulnerability,
  deleteVulnerability,
  generateReport,
  downloadReport,
  getDashboardStats,
  getRecentActivities,
  login,
  getCurrentUser,
  logout,
};
