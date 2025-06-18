import axios, { AxiosInstance } from 'axios';
import {
  PaginatedResponse,
  AuthResponse,
  Customer,
  CreateCustomerRequest,
  Domain,
  CreateDomainRequest,
  DomainValidationInfo,
  Certificate,
  CreateCertificateRequest,
  CertificateTemplate,
  IntermediateCA,
  CreateIntermediateCARequest,
  AuditLog,
  HealthStatus,
  SystemMetrics,
  VersionInfo,
} from '../types/api';

class ApiService {
  private client: AxiosInstance;

  constructor() {
    this.client = axios.create({
      baseURL: process.env.REACT_APP_API_URL || 'https://your-api-domain.com/api/v1',
      timeout: 30000,
      headers: {
        'Content-Type': 'application/json',
      },
    });

    this.setupInterceptors();
  }

  private setupInterceptors() {
    this.client.interceptors.request.use(
      (config) => {
        const token = localStorage.getItem('auth_token');
        if (token) {
          config.headers.Authorization = `Bearer ${token}`;
        }
        return config;
      },
      (error) => Promise.reject(error)
    );

    this.client.interceptors.response.use(
      (response) => response,
      async (error) => {
        if (error.response?.status === 401) {
          localStorage.removeItem('auth_token');
          localStorage.removeItem('refresh_token');
          window.location.href = '/login';
        }
        return Promise.reject(error);
      }
    );
  }

  async login(request: { api_key: string }): Promise<AuthResponse> {
    const response = await this.client.post<AuthResponse>('/auth/login', request);
    return response.data;
  }

  async refreshToken(token: string): Promise<AuthResponse> {
    const response = await this.client.post<AuthResponse>('/auth/refresh', { token });
    return response.data;
  }

  async createCustomer(request: CreateCustomerRequest): Promise<Customer> {
    const response = await this.client.post<Customer>('/customers', {
      company_name: request.name,
      email: request.email,
      tier: request.tier === 'basic' ? 1 : request.tier === 'premium' ? 2 : 3
    });
    return response.data;
  }

  async getCustomers(params?: { page?: number; page_size?: number }): Promise<PaginatedResponse<Customer>> {
    const response = await this.client.get<PaginatedResponse<Customer>>('/customers', { params });
    return response.data;
  }

  async getCustomer(id: string): Promise<Customer> {
    const response = await this.client.get<Customer>(`/customers/${id}`);
    return response.data;
  }

  async updateCustomer(id: string, updates: Partial<Customer>): Promise<Customer> {
    const response = await this.client.put<Customer>(`/customers/${id}`, updates);
    return response.data;
  }

  async createDomain(request: CreateDomainRequest): Promise<Domain> {
    const response = await this.client.post<Domain>('/domains', {
      domain_name: request.domain,
      validation_method: request.validationType
    });
    return response.data;
  }

  async getDomains(params?: { page?: number; page_size?: number; verified?: boolean }): Promise<PaginatedResponse<Domain>> {
    const response = await this.client.get<{ domains: Domain[]; total: number; page: number; page_size: number; total_pages: number }>('/domains', { params });
    return {
      data: response.data.domains,
      total: response.data.total,
      page: response.data.page,
      limit: response.data.page_size,
      totalPages: response.data.total_pages
    };
  }

  async verifyDomain(id: string): Promise<Domain> {
    const response = await this.client.post<Domain>(`/domains/${id}/verify`);
    return response.data;
  }

  async deleteDomain(id: string): Promise<void> {
    await this.client.delete(`/domains/${id}`);
  }

  async getDomainValidationInfo(id: string): Promise<DomainValidationInfo> {
    const response = await this.client.get<Domain>(`/domains/${id}`);
    const domain = response.data;
    
    return {
      domain: domain.domain,
      validationType: domain.validationType,
      instructions: {
        dnsRecord: domain.validationType === 'dns-txt' ? {
          type: 'TXT',
          name: `_quantumca-challenge.${domain.domain}`,
          value: domain.validationToken
        } : undefined,
        httpFile: domain.validationType === 'http-01' ? {
          path: `/.well-known/acme-challenge/${domain.validationToken}`,
          content: domain.validationToken
        } : undefined
      }
    };
  }

  async createCertificate(request: CreateCertificateRequest): Promise<Certificate> {
    const response = await this.client.post<Certificate>('/certificates', {
      common_name: request.domains[0],
      subject_alt_names: request.domains.slice(1),
      validity_days: request.validityPeriod,
      template_id: request.templateId ? parseInt(request.templateId) : 1,
      algorithm: request.algorithm.toLowerCase(),
      use_multi_pqc: false
    });
    return response.data;
  }

  async getCertificates(params?: { 
    page?: number; 
    page_size?: number; 
    status?: string; 
    common_name?: string;
  }): Promise<PaginatedResponse<Certificate>> {
    const response = await this.client.get<{ certificates: Certificate[]; total: number; page: number; page_size: number; total_pages: number }>('/certificates', { params });
    return {
      data: response.data.certificates,
      total: response.data.total,
      page: response.data.page,
      limit: response.data.page_size,
      totalPages: response.data.total_pages
    };
  }

  async getCertificate(id: string): Promise<Certificate> {
    const response = await this.client.get<Certificate>(`/certificates/${id}`);
    return response.data;
  }

  async revokeCertificate(id: string, reason?: string): Promise<void> {
    await this.client.post(`/certificates/${id}/revoke`);
  }

  async renewCertificate(id: string): Promise<Certificate> {
    const response = await this.client.post<Certificate>(`/certificates/${id}/renew`);
    return response.data;
  }

  async downloadCertificate(id: string, format: 'pem' | 'key' | 'bundle' | 'multi-pqc'): Promise<Blob> {
    const response = await this.client.get(`/certificates/${id}/download`, {
      params: { format },
      responseType: 'blob',
    });
    return response.data;
  }

  async getTemplates(): Promise<CertificateTemplate[]> {
    const response = await this.client.get<CertificateTemplate[]>('/templates');
    return response.data;
  }

  async getTemplate(id: string): Promise<CertificateTemplate> {
    const response = await this.client.get<CertificateTemplate>(`/templates/${id}`);
    return response.data;
  }

  async createIntermediateCA(request: CreateIntermediateCARequest): Promise<IntermediateCA> {
    const response = await this.client.post<IntermediateCA>('/intermediate-ca', {
      common_name: request.name,
      country: 'US',
      state: 'California',
      city: 'San Francisco',
      organization: 'QuantumCA',
      organizational_unit: 'IT Department',
      validity_days: request.validityPeriod,
      algorithm: 'dilithium5',
      use_multi_pqc: true,
      max_path_len: 0
    });
    return response.data;
  }

  async getIntermediateCAs(): Promise<IntermediateCA[]> {
    const response = await this.client.get<IntermediateCA[]>('/intermediate-ca');
    return response.data;
  }

  async getIntermediateCA(id: string): Promise<IntermediateCA> {
    const response = await this.client.get<IntermediateCA>(`/intermediate-ca/${id}`);
    return response.data;
  }

  async deleteIntermediateCA(id: string): Promise<void> {
    await this.client.delete(`/intermediate-ca/${id}`);
  }

  async getAuditLogs(params?: {
    page?: number;
    page_size?: number;
    action?: string;
    from?: string;
  }): Promise<PaginatedResponse<AuditLog>> {
    const response = await this.client.get<{ logs: AuditLog[]; total: number; page: number; page_size: number; total_pages: number }>('/audit-logs', { params });
    return {
      data: response.data.logs,
      total: response.data.total,
      page: response.data.page,
      limit: response.data.page_size,
      totalPages: response.data.total_pages
    };
  }

  async getAuditLog(id: string): Promise<AuditLog> {
    const response = await this.client.get<AuditLog>(`/audit-logs/${id}`);
    return response.data;
  }

  async getHealth(): Promise<HealthStatus> {
    const healthClient = axios.create({
      baseURL: process.env.REACT_APP_HEALTH_URL || 'https://your-api-domain.com/health',
      timeout: 10000,
    });
    
    const response = await healthClient.get<HealthStatus>('/');
    return response.data;
  }

  async getHealthMetrics(): Promise<SystemMetrics> {
    const healthClient = axios.create({
      baseURL: process.env.REACT_APP_HEALTH_URL || 'https://your-api-domain.com/health',
      timeout: 10000,
    });
    
    const response = await healthClient.get<SystemMetrics>('/metrics');
    return response.data;
  }

  async getVersion(): Promise<VersionInfo> {
    const response = await this.client.get<VersionInfo>('/version');
    return response.data;
  }
}

export const apiService = new ApiService();