import axios from 'axios';

const API_BASE_URL = process.env.NEXT_PUBLIC_API_BASE_URL || 'http://localhost:8000';

// Helper functions for token management
export const storeToken = async (token: string): Promise<void> => {
  // Store in localStorage for client-side access
  if (typeof window !== 'undefined') {
    localStorage.setItem('authToken', token);
  }
  
  // Also set it as an HTTP-only cookie for server-side access (middleware)
  try {
    await fetch('/api/auth/token', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({ token }),
    });
  } catch (error) {
    console.error('Failed to set auth cookie:', error);
  }
};

export const getToken = (): string | null => {
  if (typeof window !== 'undefined') {
    return localStorage.getItem('authToken');
  }
  return null;
};

export const removeToken = async (): Promise<void> => {
  // Remove from localStorage
  if (typeof window !== 'undefined') {
    localStorage.removeItem('authToken');
  }
  
  // Remove the HTTP-only cookie
  try {
    await fetch('/api/auth/token', {
      method: 'DELETE',
    });
  } catch (error) {
    console.error('Failed to remove auth cookie:', error);
  }
};

// Logout function
export const logout = async (): Promise<void> => {
  await removeToken();
  window.location.href = '/login';
};

// Create axios instance
const api = axios.create({
  baseURL: API_BASE_URL,
  headers: {
    'Content-Type': 'application/json',
  },
});

// Add a request interceptor to include the auth token
api.interceptors.request.use(
  (config) => { // Simplified type for config, relying on inference
    const token = getToken();
    if (token) {
      config.headers.Authorization = `Bearer ${token}`;
    }
    return config;
  },
  (error) => {
    return Promise.reject(error);
  }
);

// Authentication
export const login = async (username: string, password: string): Promise<{ access_token: string }> => {
  const formData = new URLSearchParams();
  formData.append('username', username);
  formData.append('password', password);

  try {
    const response = await axios.post<{ access_token: string }>(`${API_BASE_URL}/token`, formData, {
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded',
      },
    });
    return response.data;
  } catch (error) {
    console.error('Login error:', error);
    throw error;
  }
};

// OxRAG APIs
export const analyzeText = async (text: string, query: string): Promise<string> => {
  try {
    const response = await api.post('/api/oxrag/analyze/text', { text, query });
    return response.data.response;
  } catch (error) {
    console.error('Error in analyzeText:', error);
    throw error;
  }
};

export const analyzePdf = async (file: File, query: string): Promise<string> => {
  try {
    const formData = new FormData();
    formData.append('file', file);
    formData.append('query', query);
    
    const response = await api.post('/api/oxrag/analyze/pdf', formData, {
      headers: {
        'Content-Type': 'multipart/form-data',
      },
    });
    return response.data.response;
  } catch (error) {
    console.error('Error in analyzePdf:', error);
    throw error;
  }
};

export const analyzeUrl = async (url: string, query: string): Promise<string> => {
  try {
    const response = await api.post('/api/oxrag/analyze/url', { url, query });
    return response.data.response;
  } catch (error) {
    console.error('Error in analyzeUrl:', error);
    throw error;
  }
};

export const analyzeImage = async (file: File, query: string): Promise<string> => {
  try {
    const formData = new FormData();
    formData.append('file', file);
    formData.append('query', query);
    
    const response = await api.post('/api/oxrag/analyze/image', formData, {
      headers: {
        'Content-Type': 'multipart/form-data',
      },
    });
    return response.data.response;
  } catch (error) {
    console.error('Error in analyzeImage:', error);
    throw error;
  }
};

// OxImage APIs
export const generateImage = async (prompt: string): Promise<string> => {
  try {
    const response = await api.post('/api/oximage/generate', { prompt });
    return response.data.image_data;
  } catch (error) {
    console.error('Error in generateImage:', error);
    throw error;
  }
};

export const enhanceImage = async (file: File, prompt: string): Promise<string> => {
  try {
    const formData = new FormData();
    formData.append('file', file);
    formData.append('prompt', prompt);
    
    const response = await api.post('/api/oximage/enhance', formData, {
      headers: {
        'Content-Type': 'multipart/form-data',
      },
    });
    return response.data.response;
  } catch (error) {
    console.error('Error in enhanceImage:', error);
    throw error;
  }
};

// OxInteLL APIs
export const analyzeQuery = async (query: string): Promise<string> => {
  try {
    const response = await api.post('/api/oxintell/analyze', { query });
    return response.data.response;
  } catch (error) {
    console.error('Error in analyzeQuery:', error);
    throw error;
  }
};

export const analyzeDomain = async (domain: string): Promise<any> => {
  try {
    const response = await api.post('/api/oxintell/domain-analysis', { domain });
    return response.data;
  } catch (error) {
    console.error('Error in analyzeDomain:', error);
    throw error;
  }
};

export const scanFile = async (file: File): Promise<any> => {
  try {
    const formData = new FormData();
    formData.append('file', file);
    
    const response = await api.post('/api/oxintell/file', formData, {
      headers: {
        'Content-Type': 'multipart/form-data',
      },
    });
    return response.data;
  } catch (error) {
    console.error('Error in scanFile:', error);
    throw error;
  }
};

export const getCVEInfo = async (cveId: string): Promise<any> => {
  try {
    const response = await api.get(`/api/oxintell/cve/${cveId}`);
    return response.data;
  } catch (error) {
    console.error('Error in getCVEInfo:', error);
    throw error;
  }
};

export const scanCode = async (file: File): Promise<any> => {
  try {
    const formData = new FormData();
    formData.append('file', file);
    
    const response = await api.post('/api/oxintell/code', formData, {
      headers: {
        'Content-Type': 'multipart/form-data',
      },
    });
    return response.data;
  } catch (error) {
    console.error('Error in scanCode:', error);
    throw error;
  }
};

export const securityChat = async (message: string, chatHistory: Array<any> = []): Promise<any> => {
  try {
    const response = await api.post('/api/oxintell/chat', { 
      message,
      chat_history: chatHistory
    });
    return response.data;
  } catch (error) {
    console.error('Error in securityChat:', error);
    throw error;
  }
};

export const getRecentCVEs = async (
  pubStartDate?: string, 
  pubEndDate?: string, 
  maxResults: number = 10
): Promise<any> => {
  try {
    let url = `/api/oxintell/recent-cves?max_results=${maxResults}`;
    
    if (pubStartDate) {
      url += `&pub_start_date=${pubStartDate}`;
    }
    
    if (pubEndDate) {
      url += `&pub_end_date=${pubEndDate}`;
    }
    
    const response = await api.get(url);
    return response.data;
  } catch (error) {
    console.error('Error in getRecentCVEs:', error);
    throw error;
  }
};

export const scheduleScan = async (scanConfig: {
  scan_type: string;
  target: string;
  frequency: string;
  notify_email?: string;
  parameters?: any;
}): Promise<any> => {
  try {
    const response = await api.post('/api/oxintell/schedule-scan', scanConfig);
    return response.data;
  } catch (error) {
    console.error('Error in scheduleScan:', error);
    throw error;
  }
};

export const getScheduledScans = async (): Promise<any> => {
  try {
    const response = await api.get('/api/oxintell/scheduled-scans');
    return response.data;
  } catch (error) {
    console.error('Error in getScheduledScans:', error);
    throw error;
  }
};

export const getScanHistory = async (days: number = 30): Promise<any> => {
  try {
    const response = await api.get(`/api/oxintell/scan-history?days=${days}`);
    return response.data;
  } catch (error) {
    console.error('Error in getScanHistory:', error);
    throw error;
  }
};

export const runImmediateScan = async (scanConfig: {
  scan_type: string;
  target: string;
  parameters?: any;
}): Promise<any> => {
  try {
    const response = await api.post('/api/oxintell/immediate-scan', scanConfig);
    return response.data;
  } catch (error) {
    console.error('Error in runImmediateScan:', error);
    throw error;
  }
};

// User Management
export const getCurrentUser = async () => {
  try {
    const response = await api.get('/api/users/me'); 
    return response.data;
  } catch (error) {
    console.error('Error fetching current user:', error);
    if (axios.isAxiosError(error) && error.response?.status === 401) {
      removeToken();
    }
    throw error;
  }
};

