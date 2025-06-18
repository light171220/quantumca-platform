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
  .regex(/^[a-zA-Z0-9_\-=+/]+$/, 'API key contains invalid characters');

export const customerFormSchema = z.object({
  name: z.string().min(1, 'Name is required').max(100, 'Name too long'),
  email: emailSchema,
  organization: z.string().max(100, 'Organization name too long').optional(),
  tier: z.enum(['basic', 'premium', 'enterprise']),
});

export const domainFormSchema = z.object({
  domain: domainSchema,
  validationType: z.enum(['dns-txt', 'http-01']),
});

export const certificateFormSchema = z.object({
  domains: z.array(domainSchema).min(1, 'At least one domain is required'),
  validityPeriod: z.number().min(1).max(825, 'Validity period must be between 1 and 825 days'),
  algorithm: z.enum(['RSA', 'ECDSA']),
  keySize: z.number().min(2048, 'Key size must be at least 2048 bits'),
  templateId: z.string().optional(),
  intermediateCAId: z.string().optional(),
});

export const intermediateCAFormSchema = z.object({
  name: z.string().min(1, 'Name is required').max(100, 'Name too long'),
  description: z.string().max(500, 'Description too long').optional(),
  validityPeriod: z.number().min(365).max(3650, 'Validity period must be between 365 and 3650 days'),
  parentCAId: z.string().optional(),
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

export type CustomerFormData = z.infer<typeof customerFormSchema>;
export type DomainFormData = z.infer<typeof domainFormSchema>;
export type CertificateFormData = z.infer<typeof certificateFormSchema>;
export type IntermediateCAFormData = z.infer<typeof intermediateCAFormSchema>;
export type LoginFormData = z.infer<typeof loginFormSchema>;
export type BulkOperationData = z.infer<typeof bulkOperationSchema>;
export type AuditLogFilterData = z.infer<typeof auditLogFilterSchema>;