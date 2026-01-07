import axiosInstance from './apiClient';

// Types
export interface Target {
  id: string;
  name: string;
  url: string;
  lastScanned?: string;
  status?: string;
}

export interface Scan {
  id: string;
  target: string;
  scanType: string;
  tools: string[];
  timing: string;
  scheduledDate?: string;
  scheduledTime?: string;
  status: string;
  createdAt: string;
}

export interface Vulnerability {
  id: number;
  name: string;
  severity: string;
  asset: string;
  cvssScore: number;
  description: string;
  evidence: string;
  remediation: string;
  status: string;
  scanStatus: string;
}

export interface Report {
  id: string;
  targetId: string;
  format: string;
  status: string;
  createdAt: string;
  downloadUrl?: string;
}

// Targets API
export const targetApi = {
  // Get all targets
  getAll: async (): Promise<Target[]> => {
    try {
      const response = await axiosInstance.get('/targets');
      return response.data;
    } catch (error) {
      console.error('Error fetching targets:', error);
      throw error;
    }
  },

  // Get target by ID
  getById: async (id: string): Promise<Target> => {
    try {
      const response = await axiosInstance.get(`/targets/${id}`);
      return response.data;
    } catch (error) {
      console.error('Error fetching target:', error);
      throw error;
    }
  },

  // Create target
  create: async (data: Omit<Target, 'id'>): Promise<Target> => {
    try {
      const response = await axiosInstance.post('/targets', data);
      return response.data;
    } catch (error) {
      console.error('Error creating target:', error);
      throw error;
    }
  },

  // Update target
  update: async (id: string, data: Partial<Target>): Promise<Target> => {
    try {
      const response = await axiosInstance.put(`/targets/${id}`, data);
      return response.data;
    } catch (error) {
      console.error('Error updating target:', error);
      throw error;
    }
  },

  // Delete target
  delete: async (id: string): Promise<void> => {
    try {
      await axiosInstance.delete(`/targets/${id}`);
    } catch (error) {
      console.error('Error deleting target:', error);
      throw error;
    }
  },

  // Upload file for scanning
  uploadFile: async (targetId: string, file: File): Promise<any> => {
    try {
      const formData = new FormData();
      formData.append('file', file);
      const response = await axiosInstance.post(`/targets/${targetId}/upload`, formData, {
        headers: {
          'Content-Type': 'multipart/form-data',
        },
      });
      return response.data;
    } catch (error) {
      console.error('Error uploading file:', error);
      throw error;
    }
  },
};

// Scans API
export const scanApi = {
  // Get all scans
  getAll: async (): Promise<Scan[]> => {
    try {
      const response = await axiosInstance.get('/scans');
      return response.data;
    } catch (error) {
      console.error('Error fetching scans:', error);
      throw error;
    }
  },

  // Get scan by ID
  getById: async (id: string): Promise<Scan> => {
    try {
      const response = await axiosInstance.get(`/scans/${id}`);
      return response.data;
    } catch (error) {
      console.error('Error fetching scan:', error);
      throw error;
    }
  },

  // Create scan
  create: async (data: Omit<Scan, 'id' | 'createdAt'>): Promise<Scan> => {
    try {
      const response = await axiosInstance.post('/scans', data);
      return response.data;
    } catch (error) {
      console.error('Error creating scan:', error);
      throw error;
    }
  },

  // Start scan
  start: async (scanId: string): Promise<Scan> => {
    try {
      const response = await axiosInstance.post(`/scans/${scanId}/start`);
      return response.data;
    } catch (error) {
      console.error('Error starting scan:', error);
      throw error;
    }
  },

  // Stop scan
  stop: async (scanId: string): Promise<Scan> => {
    try {
      const response = await axiosInstance.post(`/scans/${scanId}/stop`);
      return response.data;
    } catch (error) {
      console.error('Error stopping scan:', error);
      throw error;
    }
  },

  // Delete scan
  delete: async (id: string): Promise<void> => {
    try {
      await axiosInstance.delete(`/scans/${id}`);
    } catch (error) {
      console.error('Error deleting scan:', error);
      throw error;
    }
  },

  // Get scan results
  getResults: async (scanId: string): Promise<Vulnerability[]> => {
    try {
      const response = await axiosInstance.get(`/scans/${scanId}/results`);
      return response.data;
    } catch (error) {
      console.error('Error fetching scan results:', error);
      throw error;
    }
  },
};

// Vulnerabilities API
export const vulnerabilityApi = {
  // Get all vulnerabilities
  getAll: async (): Promise<Vulnerability[]> => {
    try {
      const response = await axiosInstance.get('/vulnerabilities');
      return response.data;
    } catch (error) {
      console.error('Error fetching vulnerabilities:', error);
      throw error;
    }
  },

  // Get vulnerability by ID
  getById: async (id: number): Promise<Vulnerability> => {
    try {
      const response = await axiosInstance.get(`/vulnerabilities/${id}`);
      return response.data;
    } catch (error) {
      console.error('Error fetching vulnerability:', error);
      throw error;
    }
  },

  // Get vulnerabilities by target
  getByTarget: async (targetId: string): Promise<Vulnerability[]> => {
    try {
      const response = await axiosInstance.get(`/vulnerabilities/target/${targetId}`);
      return response.data;
    } catch (error) {
      console.error('Error fetching vulnerabilities:', error);
      throw error;
    }
  },

  // Update vulnerability status
  updateStatus: async (id: number, status: string): Promise<Vulnerability> => {
    try {
      const response = await axiosInstance.put(`/vulnerabilities/${id}/status`, { status });
      return response.data;
    } catch (error) {
      console.error('Error updating vulnerability:', error);
      throw error;
    }
  },

  // Delete vulnerability
  delete: async (id: number): Promise<void> => {
    try {
      await axiosInstance.delete(`/vulnerabilities/${id}`);
    } catch (error) {
      console.error('Error deleting vulnerability:', error);
      throw error;
    }
  },

  // Rescan vulnerability
  rescan: async (id: number): Promise<Scan> => {
    try {
      const response = await axiosInstance.post(`/vulnerabilities/${id}/rescan`);
      return response.data;
    } catch (error) {
      console.error('Error rescanning vulnerability:', error);
      throw error;
    }
  },
};

// Reports API
export const reportApi = {
  // Get all reports
  getAll: async (): Promise<Report[]> => {
    try {
      const response = await axiosInstance.get('/reports');
      return response.data;
    } catch (error) {
      console.error('Error fetching reports:', error);
      throw error;
    }
  },

  // Get report by ID
  getById: async (id: string): Promise<Report> => {
    try {
      const response = await axiosInstance.get(`/reports/${id}`);
      return response.data;
    } catch (error) {
      console.error('Error fetching report:', error);
      throw error;
    }
  },

  // Create report
  create: async (targetId: string, format: 'pdf' | 'html'): Promise<Report> => {
    try {
      const response = await axiosInstance.post('/reports', {
        targetId,
        format,
      });
      return response.data;
    } catch (error) {
      console.error('Error creating report:', error);
      throw error;
    }
  },

  // Download report
  download: async (reportId: string, format: 'pdf' | 'html'): Promise<Blob> => {
    try {
      const response = await axiosInstance.get(`/reports/${reportId}/download`, {
        params: { format },
        responseType: 'blob',
      });
      return response.data;
    } catch (error) {
      console.error('Error downloading report:', error);
      throw error;
    }
  },

  // Delete report
  delete: async (id: string): Promise<void> => {
    try {
      await axiosInstance.delete(`/reports/${id}`);
    } catch (error) {
      console.error('Error deleting report:', error);
      throw error;
    }
  },
};

// Dashboard API
export const dashboardApi = {
  // Get dashboard statistics
  getStats: async (): Promise<any> => {
    try {
      const response = await axiosInstance.get('/dashboard/stats');
      return response.data;
    } catch (error) {
      console.error('Error fetching dashboard stats:', error);
      throw error;
    }
  },

  // Get recent activities
  getRecentActivities: async (limit: number = 10): Promise<any[]> => {
    try {
      const response = await axiosInstance.get('/dashboard/activities', {
        params: { limit },
      });
      return response.data;
    } catch (error) {
      console.error('Error fetching activities:', error);
      throw error;
    }
  },

  // Get security overview
  getSecurityOverview: async (): Promise<any> => {
    try {
      const response = await axiosInstance.get('/dashboard/security-overview');
      return response.data;
    } catch (error) {
      console.error('Error fetching security overview:', error);
      throw error;
    }
  },
};

// Authentication API
export const authApi = {
  // Login
  login: async (email: string, password: string): Promise<{ token: string; user: any }> => {
    try {
      const response = await axiosInstance.post('/auth/login', { email, password });
      if (response.data.token) {
        localStorage.setItem('authToken', response.data.token);
      }
      return response.data;
    } catch (error) {
      console.error('Error logging in:', error);
      throw error;
    }
  },

  // Logout
  logout: async (): Promise<void> => {
    try {
      await axiosInstance.post('/auth/logout');
      localStorage.removeItem('authToken');
    } catch (error) {
      console.error('Error logging out:', error);
      throw error;
    }
  },

  // Get current user
  getCurrentUser: async (): Promise<any> => {
    try {
      const response = await axiosInstance.get('/auth/me');
      return response.data;
    } catch (error) {
      console.error('Error fetching current user:', error);
      throw error;
    }
  },
};
