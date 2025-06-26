import { z } from 'zod';

export const emailSchema = z.string().email('Invalid email address');

export const domainSchema = z.string()
  .min(1, 'Domain is required')
  .regex(
    /^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)*[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?$/,
    'Invalid domain format'
  );

export const apiKeySchema = z.string()
  .min(32, 'API key must be at least 32 characters')
  .max(128, 'API key must be at most 128 characters')
  .regex(/^[a-zA-Z0-9_\-=+/]+$/, 'API key contains invalid characters');

export const customerFormSchema = z.object({
  name: z.string().min(1, 'Name is required').max(255, 'Name too long'),
  email: emailSchema,
  organization: z.string().max(255, 'Organization name too long').optional(),
  tier: z.enum(['basic', 'premium', 'enterprise']),
});

export const domainFormSchema = z.object({
  domain: domainSchema,
  validationType: z.enum(['dns-txt', 'http-01']),
});

export const certificateFormSchema = z.object({
  domains: z.array(domainSchema).min(1, 'At least one domain is required'),
  validityPeriod: z.number().min(1).max(825, 'Validity period must be between 1 and 825 days'),
  algorithm: z.enum(['RSA', 'ECDSA', 'dilithium2', 'dilithium3', 'dilithium5']),
  keySize: z.number().min(2048, 'Key size must be at least 2048 bits'),
  templateId: z.string().optional(),
  intermediateCAId: z.string().optional(),
  useMultiPQC: z.boolean().optional(),
  kemAlgorithm: z.enum(['kyber512', 'kyber768', 'kyber1024']).optional(),
});

export const intermediateCAFormSchema = z.object({
  name: z.string().min(1, 'Name is required').max(64, 'Name too long'),
  description: z.string().max(500, 'Description too long').optional(),
  validityPeriod: z.number().min(365).max(7300, 'Validity period must be between 365 and 7300 days'),
  parentCAId: z.string().optional(),
  country: z.string().length(2, 'Country must be 2 characters').optional(),
  state: z.string().max(64, 'State too long').optional(),
  city: z.string().max(64, 'City too long').optional(),
  organization: z.string().max(64, 'Organization too long').optional(),
  organizationalUnit: z.string().max(64, 'Organizational unit too long').optional(),
  algorithm: z.enum(['dilithium2', 'dilithium3', 'dilithium5']).optional(),
  useMultiPQC: z.boolean().optional(),
  kemAlgorithm: z.enum(['kyber512', 'kyber768', 'kyber1024']).optional(),
  maxPathLen: z.number().min(0).max(5).optional(),
});

export const loginFormSchema = z.object({
  apiKey: apiKeySchema,
});

export const bulkOperationSchema = z.object({
  certificateIds: z.array(z.string()).min(1, 'Select at least one certificate'),
  operation: z.enum(['renew', 'revoke']),
  reason: z.string().optional(),
});

export const auditLogFilterSchema = z.object({
  customerId: z.string().optional(),
  action: z.string().optional(),
  resource: z.string().optional(),
  startDate: z.string().optional(),
  endDate: z.string().optional(),
  severity: z.enum(['info', 'warning', 'error']).optional(),
});

export const batchCertificateSchema = z.object({
  requests: z.array(certificateFormSchema).min(1).max(50, 'Maximum 50 certificates can be issued at once'),
  batchId: z.string().optional(),
});

export const batchRevocationSchema = z.object({
  certificateIds: z.array(z.string()).min(1).max(100, 'Maximum 100 certificates can be revoked at once'),
  reason: z.enum([
    'unspecified',
    'key_compromise', 
    'ca_compromise',
    'affiliation_changed',
    'superseded',
    'cessation_of_operation',
    'certificate_hold',
    'privilege_withdrawn',
    'aa_compromise',
    'user_requested'
  ]).optional(),
  batchId: z.string().optional(),
});

export const exportFormatsSchema = z.object({
  certificateIds: z.array(z.string()).min(1),
  formats: z.array(z.enum(['pem', 'der', 'p7b', 'bundle', 'json'])).min(1),
});

export const ocspCheckSchema = z.object({
  serialNumbers: z.array(z.string()).min(1).max(100, 'Maximum 100 serial numbers allowed'),
});

export const crlGenerateSchema = z.object({
  force: z.boolean().optional(),
});

export const validateDomain = (domain: string): boolean => {
  try {
    domainSchema.parse(domain);
    return true;
  } catch {
    return false;
  }
};

export const validateEmail = (email: string): boolean => {
  try {
    emailSchema.parse(email);
    return true;
  } catch {
    return false;
  }
};

export const validateApiKey = (apiKey: string): boolean => {
  try {
    apiKeySchema.parse(apiKey);
    return true;
  } catch {
    return false;
  }
};

export const validateCommonName = (commonName: string): boolean => {
  if (!commonName || commonName.length === 0) return false;
  if (commonName.length > 255) return false;
  return domainSchema.safeParse(commonName).success;
};

export const validateSerialNumber = (serialNumber: string): boolean => {
  return /^[a-fA-F0-9]+$/.test(serialNumber) && serialNumber.length >= 16;
};

export const validateFingerprint = (fingerprint: string): boolean => {
  return /^[a-fA-F0-9:]+$/.test(fingerprint) && fingerprint.length >= 32;
};

export const validateAlgorithm = (algorithm: string): boolean => {
  const validAlgorithms = [
    'RSA', 'ECDSA', 
    'dilithium2', 'dilithium3', 'dilithium5',
    'sphincs-sha256-128f', 'sphincs-sha256-128s',
    'sphincs-sha256-192f', 'sphincs-sha256-256f'
  ];
  return validAlgorithms.includes(algorithm);
};

export const validateKEMAlgorithm = (kemAlgorithm: string): boolean => {
  const validKEMAlgorithms = ['kyber512', 'kyber768', 'kyber1024'];
  return validKEMAlgorithms.includes(kemAlgorithm);
};

export const validateValidityDays = (days: number): boolean => {
  return days >= 1 && days <= 825;
};

export const validateCustomerTier = (tier: number): boolean => {
  return [1, 2, 3].includes(tier);
};

export type CustomerFormData = z.infer<typeof customerFormSchema>;
export type DomainFormData = z.infer<typeof domainFormSchema>;
export type CertificateFormData = z.infer<typeof certificateFormSchema>;
export type IntermediateCAFormData = z.infer<typeof intermediateCAFormSchema>;
export type LoginFormData = z.infer<typeof loginFormSchema>;
export type BulkOperationData = z.infer<typeof bulkOperationSchema>;
export type AuditLogFilterData = z.infer<typeof auditLogFilterSchema>;
export type BatchCertificateData = z.infer<typeof batchCertificateSchema>;
export type BatchRevocationData = z.infer<typeof batchRevocationSchema>;
export type ExportFormatsData = z.infer<typeof exportFormatsSchema>;
export type OCSPCheckData = z.infer<typeof ocspCheckSchema>;
export type CRLGenerateData = z.infer<typeof crlGenerateSchema>;