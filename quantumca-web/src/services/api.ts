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
      baseURL: process.env.REACT_APP_API_URL || 'http://localhost:8080/api/v1',
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
        const apiKey = localStorage.getItem('api_key');
        if (apiKey) {
          config.headers.Authorization = `Bearer ${apiKey}`;
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
          localStorage.removeItem('api_key');
          window.location.href = '/login';
        }
        return Promise.reject(error);
      }
    );
  }

  async login(request: { api_key: string }): Promise<AuthResponse> {
    const response = await this.client.post<AuthResponse>('/auth/login', request);
    localStorage.setItem('api_key', request.api_key);
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

  async verifyDomain(id: string): Promise<void> {
    await this.client.post(`/domains/${id}/verify`);
  }

  async deleteDomain(id: string): Promise<void> {
    await this.client.delete(`/domains/${id}`);
  }

  async getDomainValidationInfo(id: string): Promise<DomainValidationInfo> {
    const response = await this.client.get<Domain>(`/domains/${id}`);
    const domain = response.data;
    
    return {
      domain: domain.domain_name,
      validationType: domain.validation_method,
      instructions: {
        dnsRecord: domain.dns_challenge ? {
          type: 'TXT',
          name: domain.dns_challenge.record_name,
          value: domain.dns_challenge.record_value
        } : undefined,
        httpFile: domain.http_challenge ? {
          path: domain.http_challenge.path,
          content: domain.http_challenge.content
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
    await this.client.post(`/certificates/${id}/revoke`, { reason });
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

  async batchIssueCertificates(requests: CreateCertificateRequest[]): Promise<any> {
    const response = await this.client.post('/certificates/batch', {
      requests: requests.map(req => ({
        common_name: req.domains[0],
        subject_alt_names: req.domains.slice(1),
        validity_days: req.validityPeriod,
        template_id: req.templateId ? parseInt(req.templateId) : 1,
        algorithm: req.algorithm.toLowerCase(),
        use_multi_pqc: false
      }))
    });
    return response.data;
  }

  async batchRevokeCertificates(certificateIds: string[], reason?: string): Promise<any> {
    const response = await this.client.post('/certificates/batch-revoke', {
      certificate_ids: certificateIds.map(id => parseInt(id)),
      reason: reason || 'user_requested'
    });
    return response.data;
  }

  async getExpiringCertificates(days: number = 30): Promise<any> {
    const response = await this.client.get('/certificates/expiring', {
      params: { days }
    });
    return response.data;
  }

  async bulkExportCertificates(certificateIds: string[], format: string): Promise<any> {
    const response = await this.client.post('/certificates/bulk-export', {
      certificate_ids: certificateIds.map(id => parseInt(id)),
      format
    });
    return response.data;
  }

  async getCertificateChain(id: string): Promise<any> {
    const response = await this.client.get(`/certificates/${id}/chain`);
    return response.data;
  }

  async exportPKCS12(id: string, password?: string): Promise<Blob> {
    const response = await this.client.get(`/certificates/${id}/pkcs12`, {
      params: password ? { password } : {},
      responseType: 'blob'
    });
    return response.data;
  }

  async exportMultipleFormats(id: string, formats: string[]): Promise<any> {
    const response = await this.client.post(`/certificates/${id}/formats`, { formats });
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
      algorithm: 'dilithium3',
      use_multi_pqc: true,
      max_path_len: 0
    });
    return response.data;
  }

  async getIntermediateCAs(params?: { page?: number; page_size?: number; status?: string }): Promise<PaginatedResponse<IntermediateCA>> {
    const response = await this.client.get<{ intermediate_cas: IntermediateCA[]; total: number; page: number; page_size: number; total_pages: number }>('/intermediate-ca', { params });
    return {
      data: response.data.intermediate_cas,
      total: response.data.total,
      page: response.data.page,
      limit: response.data.page_size,
      totalPages: response.data.total_pages
    };
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
    resource?: string;
    from?: string;
    to?: string;
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

  async getRootCAInfo(): Promise<any> {
    const response = await this.client.get('/ca/root/info');
    return response.data;
  }

  async getIntermediateCAInfo(): Promise<any> {
    const response = await this.client.get('/ca/intermediate/info');
    return response.data;
  }

  async getCertificateChainInfo(): Promise<any> {
    const response = await this.client.get('/ca/chain');
    return response.data;
  }

  async getSupportedAlgorithms(): Promise<any> {
    const response = await this.client.get('/ca/algorithms');
    return response.data;
  }

  async downloadCRL(): Promise<Blob> {
    const response = await this.client.get('/crl', {
      responseType: 'blob'
    });
    return response.data;
  }

  async getCRLInfo(): Promise<any> {
    const response = await this.client.get('/crl/info');
    return response.data;
  }

  async generateCRL(force: boolean = false): Promise<any> {
    const response = await this.client.post('/crl/generate', { force });
    return response.data;
  }

  async checkOCSPStatus(serialNumber: string): Promise<any> {
    const response = await this.client.get(`/ocsp/status/${serialNumber}`);
    return response.data;
  }

  async batchCheckOCSPStatus(serialNumbers: string[]): Promise<any> {
    const response = await this.client.post('/certificates/batch-ocsp-check', {
      serial_numbers: serialNumbers
    });
    return response.data;
  }

  async getOCSPHealth(): Promise<any> {
    const response = await this.client.get('/ocsp/responder/health');
    return response.data;
  }

  async getOCSPStats(): Promise<any> {
    const response = await this.client.get('/ocsp/responder/stats');
    return response.data;
  }

  async getOCSPConfig(): Promise<any> {
    const response = await this.client.get('/ocsp/responder/config');
    return response.data;
  }

  async getAnalyticsDashboard(): Promise<any> {
    const response = await this.client.get('/analytics/dashboard');
    return response.data;
  }

  async getExpirationReport(): Promise<any> {
    const response = await this.client.get('/analytics/expiration-report');
    return response.data;
  }

  async getAlgorithmUsage(): Promise<any> {
    const response = await this.client.get('/analytics/algorithm-usage');
    return response.data;
  }

  async getRevocationStats(): Promise<any> {
    const response = await this.client.get('/analytics/revocation-stats');
    return response.data;
  }

  async getCertificateStatus(id: string): Promise<any> {
    const response = await this.client.get(`/certificates/${id}/status`);
    return response.data;
  }

  async bulkRenewCertificates(certificateIds: string[]): Promise<any> {
    const response = await this.client.post('/certificates/bulk-renew', {
      certificate_ids: certificateIds.map(id => parseInt(id))
    });
    return response.data;
  }

  async getHealth(): Promise<HealthStatus> {
    const response = await this.client.get<HealthStatus>('/health');
    return response.data;
  }

  async getHealthMetrics(): Promise<SystemMetrics> {
    const response = await this.client.get<SystemMetrics>('/health/metrics');
    return response.data;
  }

  async getLiveness(): Promise<any> {
    const response = await this.client.get('/health/live');
    return response.data;
  }

  async getReadiness(): Promise<any> {
    const response = await this.client.get('/health/ready');
    return response.data;
  }

  async getVersion(): Promise<VersionInfo> {
    const response = await this.client.get<VersionInfo>('/version');
    return response.data;
  }
}

export const apiService = new ApiService();