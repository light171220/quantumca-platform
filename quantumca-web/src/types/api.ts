export interface ApiResponse<T> {
  data: T;
  message?: string;
  status: number;
}

export interface PaginatedResponse<T> {
  data: T[];
  total: number;
  page: number;
  limit: number;
  totalPages: number;
}

export interface AuthResponse {
  token: string;
  expires_at: string;
  customer: {
    id: number;
    company_name: string;
    email: string;
    tier: number;
  };
  refreshToken?: string;
}

export interface Customer {
  id: string;
  company_name: string;
  email: string;
  api_key: string;
  tier: number;
  status: 'active' | 'inactive' | 'suspended';
  created_at: string;
  updated_at: string;
  name?: string;
  organization?: string;
}

export interface CreateCustomerRequest {
  name: string;
  email: string;
  organization?: string;
  tier: 'basic' | 'premium' | 'enterprise';
}

export interface Domain {
  id: string;
  customer_id: string;
  domain_name: string;
  validation_token: string;
  is_verified: boolean;
  created_at: string;
  updated_at: string;
  validation_method: 'dns-txt' | 'http-01';
  dns_challenge?: {
    domain: string;
    token: string;
    record_name: string;
    record_value: string;
    expires_at: string;
  };
  domain: string;
  status: 'pending' | 'verified' | 'failed' | 'expired';
  validationType: 'dns-txt' | 'http-01';
  validationToken: string;
  validationRecord?: string;
  verifiedAt?: string;
  expiresAt?: string;
  createdAt: string;
  updatedAt: string;
}

export interface CreateDomainRequest {
  domain: string;
  validationType: 'dns-txt' | 'http-01';
}

export interface DomainValidationInfo {
  domain: string;
  validationType: 'dns-txt' | 'http-01';
  instructions: {
    dnsRecord?: {
      type: string;
      name: string;
      value: string;
    };
    httpFile?: {
      path: string;
      content: string;
    };
  };
}

export interface Certificate {
  id: string;
  serial_number: string;
  common_name: string;
  subject_alt_names: string[];
  certificate: string;
  private_key: string;
  algorithms: string[];
  is_multi_pqc: boolean;
  has_kem: boolean;
  fingerprint: string;
  key_id: string;
  not_before: string;
  not_after: string;
  status: 'pending' | 'issued' | 'expired' | 'revoked' | 'failed';
  created_at: string;
  expires_in: number;
  domains: string[];
  customerId?: string;
  serialNumber?: string;
  issuer: string;
  subject: string;
  validFrom: string;
  validTo: string;
  algorithm: string;
  keySize: number;
  templateId?: string;
  intermediateCAId?: string;
  downloadUrls?: {
    certificate: string;
    privateKey: string;
    bundle: string;
  };
  createdAt: string;
  updatedAt: string;
}

export interface CreateCertificateRequest {
  domains: string[];
  validityPeriod: number;
  algorithm: 'RSA' | 'ECDSA';
  keySize: number;
  templateId?: string;
  intermediateCAId?: string;
}

export interface CertificateTemplate {
  id: string;
  name: string;
  description: string;
  key_usages: string[];
  ext_key_usages: string[];
  validity_days: number;
  max_validity_days: number;
  is_ca: boolean;
  status: string;
  validityPeriod: number;
  algorithm: 'RSA' | 'ECDSA';
  keySize: number;
  extensions: Record<string, any>;
  tier: 'basic' | 'premium' | 'enterprise';
  isActive: boolean;
  createdAt: string;
  updatedAt: string;
}

export interface IntermediateCA {
  id: string;
  name: string;
  description?: string;
  subject: string;
  issuer: string;
  serialNumber: string;
  validFrom: string;
  validTo: string;
  status: 'active' | 'revoked' | 'expired';
  parentCAId?: string;
  tier: 'premium' | 'enterprise';
  createdAt: string;
  updatedAt: string;
}

export interface CreateIntermediateCARequest {
  name: string;
  description?: string;
  validityPeriod: number;
  parentCAId?: string;
}

export interface AuditLog {
  id: string;
  user_id: string;
  customer_id: number;
  action: string;
  resource: string;
  resource_id: string;
  ip_address: string;
  user_agent: string;
  details: Record<string, any>;
  created_at: string;
  customerId?: string;
  timestamp: string;
  severity: 'info' | 'warning' | 'error';
}

export interface HealthStatus {
  status: 'healthy' | 'degraded' | 'unhealthy';
  timestamp: string;
  version: string;
  uptime: string;
  checks: {
    database: string;
    database_query: string;
  };
  services: {
    database: 'up' | 'down';
    redis: 'up' | 'down';
    ca: 'up' | 'down';
    ocsp: 'up' | 'down';
  };
  metrics: {
    uptime: number;
    memoryUsage: number;
    cpuUsage: number;
    activeConnections: number;
  };
}

export interface SystemMetrics {
  database_connections: number;
  active_certificates: number;
  total_customers: number;
  timestamp: string;
  certificates: {
    total: number;
    active: number;
    expired: number;
    expiringSoon: number;
  };
  domains: {
    total: number;
    verified: number;
    pending: number;
  };
  customers: {
    total: number;
    active: number;
  };
  performance: {
    avgResponseTime: number;
    requestsPerSecond: number;
    errorRate: number;
  };
}

export interface VersionInfo {
  version: string;
  buildTime: string;
  gitCommit: string;
  environment: string;
}