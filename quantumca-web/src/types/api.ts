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
  refresh_token: string;
  expires_at: string;
  customer: {
    id: number;
    company_name: string;
    email: string;
    tier: number;
  };
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
  verified_at?: string;
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
  http_challenge?: {
    path: string;
    content: string;
    expires_at: string;
  };
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
  multi_pqc_certificates?: string[];
  multi_pqc_private_keys?: string[];
  kem_public_key_pem?: string;
  kem_private_key_pem?: string;
  fingerprint: string;
  key_id: string;
  not_before: string;
  not_after: string;
  status: 'pending' | 'active' | 'expired' | 'revoked' | 'failed';
  created_at: string;
  expires_in: number;
}

export interface CreateCertificateRequest {
  domains: string[];
  validityPeriod: number;
  algorithm: 'RSA' | 'ECDSA' | 'dilithium2' | 'dilithium3' | 'dilithium5';
  keySize: number;
  templateId?: string;
  intermediateCAId?: string;
  useMultiPQC?: boolean;
  kemAlgorithm?: string;
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
  path_length?: number;
  policies?: Record<string, any>;
  status: string;
  created_at: string;
  updated_at: string;
}

export interface IntermediateCA {
  id: string;
  common_name: string;
  serial_number: string;
  algorithm: string;
  algorithms: string[];
  is_multi_pqc: boolean;
  has_kem: boolean;
  certificate?: string;
  private_key?: string;
  multi_pqc_certificates?: string[];
  multi_pqc_private_keys?: string[];
  kem_public_key_pem?: string;
  kem_private_key_pem?: string;
  fingerprint: string;
  key_id: string;
  max_path_len: number;
  not_before: string;
  not_after: string;
  status: 'active' | 'revoked' | 'expired';
  created_at: string;
  customer_id: number;
}

export interface CreateIntermediateCARequest {
  name: string;
  description?: string;
  validityPeriod: number;
  parentCAId?: string;
  country?: string;
  state?: string;
  city?: string;
  organization?: string;
  organizationalUnit?: string;
  algorithm?: string;
  useMultiPQC?: boolean;
  kemAlgorithm?: string;
  maxPathLen?: number;
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
}

export interface SystemMetrics {
  database_connections: number;
  active_certificates: number;
  total_customers: number;
  timestamp: string;
}

export interface VersionInfo {
  service: string;
  version: string;
  build: string;
  commit: string;
  build_time: string;
  go_version: string;
}

export interface BatchOperationResponse {
  successful: number[];
  failed: Array<{
    id: number;
    error: string;
  }>;
  summary: {
    total: number;
    successful: number;
    failed: number;
  };
}

export interface ExpiringCertificate {
  id: string;
  common_name: string;
  serial_number: string;
  not_after: string;
  days_left: number;
  customer_id: number;
}

export interface AnalyticsDashboard {
  summary: {
    total_certificates: number;
    active_certificates: number;
    expiring_soon: number;
    revoked_certificates: number;
    intermediate_cas: number;
    domains_validated: number;
    certificates_issued_24h: number;
    certificates_revoked_24h: number;
  };
  certificates_by_status: Record<string, number>;
  algorithm_usage: Array<{
    algorithm: string;
    count: number;
    percentage: number;
    is_multi_pqc: boolean;
  }>;
  expiration_trends: Array<{
    date: string;
    count: number;
  }>;
  recent_activity: Array<{
    type: string;
    description: string;
    timestamp: string;
    details: Record<string, any>;
  }>;
  timestamp: string;
}

export interface OCSPStatus {
  serial_number: string;
  status: 'good' | 'revoked' | 'unknown';
  revoked_at?: string;
  reason?: number;
  checked_at: string;
}

export interface CRLInfo {
  version: number;
  issuer: string;
  this_update: string;
  next_update: string;
  crl_number: number;
  entry_count: number;
  size_bytes: number;
  signature_algorithm: string;
  download_url: string;
}

export interface CAInfo {
  certificate: string;
  serial_number: string;
  subject: {
    common_name: string;
    country: string[];
    organization: string[];
    organizational_unit: string[];
    locality: string[];
    province: string[];
  };
  not_before: string;
  not_after: string;
  fingerprint: string;
  key_usages: string[];
  basic_constraints: {
    is_ca: boolean;
    max_path_len: number;
  };
  algorithms: string[];
  is_multi_pqc: boolean;
}

export interface SupportedAlgorithms {
  signature: Array<{
    name: string;
    description: string;
    security_bits: number;
    type: string;
  }>;
  kem: Array<{
    name: string;
    description: string;
    security_bits: number;
    type: string;
  }>;
  multi_pqc_supported: boolean;
}