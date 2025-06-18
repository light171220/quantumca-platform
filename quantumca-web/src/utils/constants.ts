export const API_BASE_URL = '/api';

export const CERTIFICATE_STATUS = {
  PENDING: 'pending',
  ISSUED: 'issued',
  EXPIRED: 'expired',
  REVOKED: 'revoked',
  FAILED: 'failed',
  ACTIVE: 'active',
} as const;

export const DOMAIN_STATUS = {
  PENDING: 'pending',
  VERIFIED: 'verified',
  FAILED: 'failed',
  EXPIRED: 'expired',
} as const;

export const CUSTOMER_STATUS = {
  ACTIVE: 'active',
  INACTIVE: 'inactive',
  SUSPENDED: 'suspended',
} as const;

export const CUSTOMER_TIER = {
  BASIC: 1,
  PREMIUM: 2,
  ENTERPRISE: 3,
} as const;

export const VALIDATION_TYPE = {
  DNS_TXT: 'dns-txt',
  HTTP_01: 'http-01',
} as const;

export const CERTIFICATE_ALGORITHM = {
  RSA: 'RSA',
  ECDSA: 'ECDSA',
  DILITHIUM3: 'dilithium3',
  DILITHIUM5: 'dilithium5',
} as const;

export const AUDIT_SEVERITY = {
  INFO: 'info',
  WARNING: 'warning',
  ERROR: 'error',
} as const;

export const TOAST_DURATION = {
  SHORT: 3000,
  MEDIUM: 5000,
  LONG: 8000,
} as const;

export const PAGE_SIZE_OPTIONS = [10, 25, 50, 100];

export const DEFAULT_PAGE_SIZE = 25;

export const ROUTES = {
  HOME: '/',
  DASHBOARD: '/dashboard',
  CERTIFICATES: '/certificates',
  DOMAINS: '/domains',
  CUSTOMERS: '/customers',
  TEMPLATES: '/templates',
  INTERMEDIATE_CA: '/intermediate-ca',
  AUDIT_LOGS: '/audit-logs',
  MONITORING: '/monitoring',
  LOGIN: '/login',
} as const;

export const STATUS_COLORS = {
  CERTIFICATE: {
    [CERTIFICATE_STATUS.PENDING]: 'bg-yellow-100 text-yellow-800',
    [CERTIFICATE_STATUS.ISSUED]: 'bg-green-100 text-green-800',
    [CERTIFICATE_STATUS.ACTIVE]: 'bg-green-100 text-green-800',
    [CERTIFICATE_STATUS.EXPIRED]: 'bg-red-100 text-red-800',
    [CERTIFICATE_STATUS.REVOKED]: 'bg-gray-100 text-gray-800',
    [CERTIFICATE_STATUS.FAILED]: 'bg-red-100 text-red-800',
  },
  DOMAIN: {
    [DOMAIN_STATUS.VERIFIED]: 'bg-green-100 text-green-800',
  },
  CUSTOMER: {
    [CUSTOMER_STATUS.ACTIVE]: 'bg-green-100 text-green-800',
    [CUSTOMER_STATUS.INACTIVE]: 'bg-gray-100 text-gray-800',
    [CUSTOMER_STATUS.SUSPENDED]: 'bg-red-100 text-red-800',
  },
} as const;

export const CHART_COLORS = [
  '#0ea5e9',
  '#22c55e',
  '#f59e0b',
  '#ef4444',
  '#8b5cf6',
  '#06b6d4',
  '#84cc16',
  '#f97316',
] as const;