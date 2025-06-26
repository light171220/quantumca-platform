/* eslint-disable no-restricted-globals */
import React, { useState } from 'react';
import { useApi, useMutation } from '../hooks/useApi';
import { apiService } from '../services/api';
import { Certificate, CreateCertificateRequest } from '../types/api';
import { TableColumn } from '../types/common';
import DataTable from '../components/DataTable';
import StatusBadge from '../components/StatusBadge';
import Modal from '../components/Modal';
import LoadingSpinner from '../components/LoadingSpinner';
import { formatDate, formatRelativeTime, downloadFile } from '../utils/helpers';
import { certificateFormSchema, CertificateFormData } from '../utils/validation';
import { 
  PlusIcon, 
  ArrowDownTrayIcon, 
  ArrowPathIcon, 
  XMarkIcon,
  DocumentTextIcon,
  ShieldCheckIcon,
  ClockIcon,
  ExclamationTriangleIcon
} from '@heroicons/react/24/outline';
import toast from 'react-hot-toast';

const Certificates: React.FC = () => {
  const [page, setPage] = useState(1);
  const [selectedCerts, setSelectedCerts] = useState<string[]>([]);
  const [showCreateModal, setShowCreateModal] = useState(false);
  const [showDetailsModal, setShowDetailsModal] = useState(false);
  const [showBatchModal, setShowBatchModal] = useState(false);
  const [selectedCert, setSelectedCert] = useState<Certificate | null>(null);
  const [formData, setFormData] = useState<CertificateFormData>({
    domains: [''],
    validityPeriod: 365,
    algorithm: 'RSA',
    keySize: 2048,
  });

  const { data: certificatesData, loading, refetch } = useApi(() => 
    apiService.getCertificates({ page, page_size: 25 })
  );

  const { data: templatesData } = useApi(() => apiService.getTemplates());

  const createMutation = useMutation((data: CreateCertificateRequest) => 
    apiService.createCertificate(data)
  );

  const renewMutation = useMutation((id: string) => 
    apiService.renewCertificate(id)
  );

  const revokeMutation = useMutation(({ id, reason }: { id: string; reason?: string }) =>
    apiService.revokeCertificate(id, reason)
  );

  const batchRenewMutation = useMutation((ids: string[]) =>
    apiService.bulkRenewCertificates(ids)
  );

  const batchRevokeMutation = useMutation(({ ids, reason }: { ids: string[]; reason?: string }) =>
    apiService.batchRevokeCertificates(ids, reason)
  );

  const downloadMutation = useMutation(({ id, format }: { id: string; format: 'pem' | 'key' | 'bundle' | 'multi-pqc' }) =>
    apiService.downloadCertificate(id, format)
  );

  const columns: TableColumn<Certificate>[] = [
    {
      key: 'common_name',
      title: 'Common Name',
      render: (commonName: string, cert: Certificate) => {
        return (
          <div>
            <div className="font-medium text-gray-900 dark:text-white">{commonName}</div>
            {cert.subject_alt_names && cert.subject_alt_names.length > 0 && (
              <div className="text-sm text-gray-500 dark:text-gray-400">
                +{cert.subject_alt_names.length} more
              </div>
            )}
          </div>
        );
      },
    },
    {
      key: 'status',
      title: 'Status',
      render: (status: string) => <StatusBadge status={status} />,
    },
    {
      key: 'algorithms',
      title: 'Algorithm',
      render: (algorithms: string[]) => (
        <div className="flex flex-col">
          <span className="font-medium">{algorithms[0] || 'Unknown'}</span>
          {algorithms.length > 1 && (
            <span className="text-xs text-gray-500">Multi-algorithm</span>
          )}
        </div>
      ),
    },
    {
      key: 'not_after',
      title: 'Expires',
      render: (date: string) => {
        const expiryDate = new Date(date);
        const daysLeft = Math.ceil((expiryDate.getTime() - Date.now()) / (1000 * 60 * 60 * 24));
        
        return (
          <div className="flex flex-col">
            <span className="text-sm">{formatDate(date)}</span>
            <span className={`text-xs ${
              daysLeft <= 7 ? 'text-red-600' : 
              daysLeft <= 30 ? 'text-yellow-600' : 
              'text-green-600'
            }`}>
              {daysLeft > 0 ? `${daysLeft} days left` : 'Expired'}
            </span>
          </div>
        );
      },
    },
    {
      key: 'created_at',
      title: 'Created',
      render: (date: string) => formatRelativeTime(date),
    },
    {
      key: 'actions',
      title: 'Actions',
      render: (_, cert: Certificate) => (
        <div className="flex space-x-2">
          <button
            onClick={(e) => {
              e.stopPropagation();
              handleDownloadCertificate(cert.id, 'bundle');
            }}
            className="text-blue-600 hover:text-blue-800 text-sm"
          >
            Download
          </button>
          {cert.status === 'active' && (
            <>
              <button
                onClick={(e) => {
                  e.stopPropagation();
                  handleRenewCertificate(cert.id);
                }}
                className="text-green-600 hover:text-green-800 text-sm"
              >
                Renew
              </button>
              <button
                onClick={(e) => {
                  e.stopPropagation();
                  handleRevokeCertificate(cert.id);
                }}
                className="text-red-600 hover:text-red-800 text-sm"
              >
                Revoke
              </button>
            </>
          )}
        </div>
      ),
    },
  ];

  const handleCreateCertificate = async (e: React.FormEvent) => {
    e.preventDefault();
    
    try {
      const validated = certificateFormSchema.parse(formData);
      await createMutation.mutate(validated);
      toast.success('Certificate created successfully');
      setShowCreateModal(false);
      refetch();
      resetForm();
    } catch (error) {
      toast.error('Failed to create certificate');
    }
  };

  const handleRenewCertificate = async (id: string) => {
    try {
      await renewMutation.mutate(id);
      toast.success('Certificate renewed successfully');
      refetch();
    } catch (error) {
      toast.error('Failed to renew certificate');
    }
  };

  const handleRevokeCertificate = async (id: string, reason?: string) => {
    if (!confirm('Are you sure you want to revoke this certificate?')) return;
    
    try {
      await revokeMutation.mutate({ id, reason });
      toast.success('Certificate revoked successfully');
      refetch();
    } catch (error) {
      toast.error('Failed to revoke certificate');
    }
  };

  const handleBatchRenew = async () => {
    try {
      await batchRenewMutation.mutate(selectedCerts);
      toast.success(`${selectedCerts.length} certificates renewed successfully`);
      setSelectedCerts([]);
      setShowBatchModal(false);
      refetch();
    } catch (error) {
      toast.error('Failed to renew certificates');
    }
  };

  const handleBatchRevoke = async (reason?: string) => {
    if (!confirm(`Are you sure you want to revoke ${selectedCerts.length} certificates?`)) return;
    
    try {
      await batchRevokeMutation.mutate({ ids: selectedCerts, reason });
      toast.success(`${selectedCerts.length} certificates revoked successfully`);
      setSelectedCerts([]);
      setShowBatchModal(false);
      refetch();
    } catch (error) {
      toast.error('Failed to revoke certificates');
    }
  };

  const handleDownloadCertificate = async (id: string, format: 'pem' | 'key' | 'bundle' | 'multi-pqc') => {
    try {
      const blob = await downloadMutation.mutate({ id, format });
      downloadFile(blob, `certificate.${format}`);
      toast.success('Certificate downloaded');
    } catch (error) {
      toast.error('Failed to download certificate');
    }
  };

  const resetForm = () => {
    setFormData({
      domains: [''],
      validityPeriod: 365,
      algorithm: 'RSA',
      keySize: 2048,
    });
  };

  const addDomainField = () => {
    setFormData(prev => ({
      ...prev,
      domains: [...prev.domains, '']
    }));
  };

  const removeDomainField = (index: number) => {
    setFormData(prev => ({
      ...prev,
      domains: prev.domains.filter((_, i) => i !== index)
    }));
  };

  const updateDomain = (index: number, value: string) => {
    setFormData(prev => ({
      ...prev,
      domains: prev.domains.map((domain, i) => i === index ? value : domain)
    }));
  };

  const bulkActions = [
    {
      label: 'Renew Selected',
      onClick: () => setShowBatchModal(true),
      icon: <ArrowPathIcon className="w-4 h-4" />,
    },
    {
      label: 'Revoke Selected',
      onClick: () => handleBatchRevoke(),
      icon: <XMarkIcon className="w-4 h-4" />,
    },
  ];

  const algorithmOptions = [
    { value: 'RSA', label: 'RSA' },
    { value: 'ECDSA', label: 'ECDSA' },
    { value: 'dilithium2', label: 'Dilithium2 (PQC)' },
    { value: 'dilithium3', label: 'Dilithium3 (PQC)' },
    { value: 'dilithium5', label: 'Dilithium5 (PQC)' },
  ];

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold text-gray-900 dark:text-white">Certificates</h1>
          <p className="text-sm text-gray-600 dark:text-gray-400 mt-1">
            Manage SSL/TLS certificates and post-quantum cryptography
          </p>
        </div>
        <button
          onClick={() => setShowCreateModal(true)}
          className="btn-primary"
        >
          <PlusIcon className="w-5 h-5 mr-2" />
          Issue Certificate
        </button>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
        <div className="card">
          <div className="card-body flex items-center">
            <DocumentTextIcon className="h-8 w-8 text-blue-600 mr-3" />
            <div>
              <p className="text-sm text-gray-600 dark:text-gray-400">Total</p>
              <p className="text-xl font-bold">{certificatesData?.total || 0}</p>
            </div>
          </div>
        </div>
        <div className="card">
          <div className="card-body flex items-center">
            <ShieldCheckIcon className="h-8 w-8 text-green-600 mr-3" />
            <div>
              <p className="text-sm text-gray-600 dark:text-gray-400">Active</p>
              <p className="text-xl font-bold">
                {certificatesData?.data?.filter(cert => cert.status === 'active').length || 0}
              </p>
            </div>
          </div>
        </div>
        <div className="card">
          <div className="card-body flex items-center">
            <ClockIcon className="h-8 w-8 text-yellow-600 mr-3" />
            <div>
              <p className="text-sm text-gray-600 dark:text-gray-400">Expiring Soon</p>
              <p className="text-xl font-bold">
                {certificatesData?.data?.filter(cert => {
                  const daysLeft = Math.ceil((new Date(cert.not_after).getTime() - Date.now()) / (1000 * 60 * 60 * 24));
                  return daysLeft <= 30 && daysLeft > 0;
                }).length || 0}
              </p>
            </div>
          </div>
        </div>
        <div className="card">
          <div className="card-body flex items-center">
            <ExclamationTriangleIcon className="h-8 w-8 text-red-600 mr-3" />
            <div>
              <p className="text-sm text-gray-600 dark:text-gray-400">Revoked</p>
              <p className="text-xl font-bold">
                {certificatesData?.data?.filter(cert => cert.status === 'revoked').length || 0}
              </p>
            </div>
          </div>
        </div>
      </div>

      <div className="card">
        <div className="card-body">
          <DataTable
            data={certificatesData?.data || []}
            columns={columns}
            loading={loading}
            pagination={{
              current: page,
              total: certificatesData?.total || 0,
              pageSize: 25,
              onChange: setPage,
            }}
            selectedRows={selectedCerts}
            onSelectionChange={setSelectedCerts}
            bulkActions={bulkActions}
            onRowClick={(cert) => {
              setSelectedCert(cert);
              setShowDetailsModal(true);
            }}
          />
        </div>
      </div>

      <Modal
        isOpen={showCreateModal}
        onClose={() => setShowCreateModal(false)}
        title="Issue New Certificate"
        size="lg"
      >
        <form onSubmit={handleCreateCertificate} className="space-y-4">
          <div>
            <label className="form-label">Domains</label>
            {formData.domains.map((domain, index) => (
              <div key={index} className="flex gap-2 mb-2">
                <input
                  type="text"
                  className="form-input flex-1"
                  placeholder="example.com"
                  value={domain}
                  onChange={(e) => updateDomain(index, e.target.value)}
                  required
                />
                {formData.domains.length > 1 && (
                  <button
                    type="button"
                    onClick={() => removeDomainField(index)}
                    className="btn-secondary btn-sm"
                  >
                    Remove
                  </button>
                )}
              </div>
            ))}
            <button
              type="button"
              onClick={addDomainField}
              className="btn-secondary btn-sm"
            >
              Add Domain
            </button>
          </div>

          <div className="grid grid-cols-2 gap-4">
            <div>
              <label className="form-label">Algorithm</label>
              <select
                className="form-input"
                value={formData.algorithm}
                onChange={(e) => setFormData(prev => ({ ...prev, algorithm: e.target.value as any }))}
              >
                {algorithmOptions.map(option => (
                  <option key={option.value} value={option.value}>
                    {option.label}
                  </option>
                ))}
              </select>
            </div>

            <div>
              <label className="form-label">Key Size</label>
              <select
                className="form-input"
                value={formData.keySize}
                onChange={(e) => setFormData(prev => ({ ...prev, keySize: parseInt(e.target.value) }))}
              >
                <option value={2048}>2048</option>
                <option value={4096}>4096</option>
                {formData.algorithm === 'ECDSA' && <option value={256}>256</option>}
              </select>
            </div>
          </div>

          <div className="grid grid-cols-2 gap-4">
            <div>
              <label className="form-label">Validity Period (days)</label>
              <input
                type="number"
                className="form-input"
                min={1}
                max={825}
                value={formData.validityPeriod}
                onChange={(e) => setFormData(prev => ({ ...prev, validityPeriod: parseInt(e.target.value) }))}
                required
              />
            </div>

            <div>
              <label className="form-label">Template</label>
              <select
                className="form-input"
                value={formData.templateId || ''}
                onChange={(e) => setFormData(prev => ({ ...prev, templateId: e.target.value }))}
              >
                <option value="">Select template</option>
                {templatesData?.map(template => (
                  <option key={template.id} value={template.id}>
                    {template.name}
                  </option>
                ))}
              </select>
            </div>
          </div>

          <div className="flex justify-end space-x-3">
            <button
              type="button"
              onClick={() => setShowCreateModal(false)}
              className="btn-secondary"
            >
              Cancel
            </button>
            <button
              type="submit"
              disabled={createMutation.loading}
              className="btn-primary"
            >
              {createMutation.loading ? <LoadingSpinner size="sm" /> : 'Issue Certificate'}
            </button>
          </div>
        </form>
      </Modal>

      <Modal
        isOpen={showDetailsModal}
        onClose={() => setShowDetailsModal(false)}
        title="Certificate Details"
        size="lg"
      >
        {selectedCert && (
          <div className="space-y-4">
            <div className="grid grid-cols-2 gap-4">
              <div>
                <label className="form-label">Common Name</label>
                <p className="text-sm text-gray-900 dark:text-white">
                  {selectedCert.common_name}
                </p>
              </div>
              <div>
                <label className="form-label">Status</label>
                <StatusBadge status={selectedCert.status} />
              </div>
              {selectedCert.subject_alt_names && selectedCert.subject_alt_names.length > 0 && (
                <div className="col-span-2">
                  <label className="form-label">Subject Alternative Names</label>
                  <p className="text-sm text-gray-900 dark:text-white">
                    {selectedCert.subject_alt_names.join(', ')}
                  </p>
                </div>
              )}
              <div>
                <label className="form-label">Serial Number</label>
                <p className="text-sm text-gray-900 dark:text-white font-mono">
                  {selectedCert.serial_number}
                </p>
              </div>
              <div>
                <label className="form-label">Algorithm</label>
                <p className="text-sm text-gray-900 dark:text-white">
                  {selectedCert.algorithms.join(', ')}
                </p>
              </div>
              <div>
                <label className="form-label">Valid From</label>
                <p className="text-sm text-gray-900 dark:text-white">
                  {formatDate(selectedCert.not_before)}
                </p>
              </div>
              <div>
                <label className="form-label">Valid To</label>
                <p className="text-sm text-gray-900 dark:text-white">
                  {formatDate(selectedCert.not_after)}
                </p>
              </div>
              <div>
                <label className="form-label">Fingerprint</label>
                <p className="text-sm text-gray-900 dark:text-white font-mono break-all">
                  {selectedCert.fingerprint}
                </p>
              </div>
              <div>
                <label className="form-label">Key ID</label>
                <p className="text-sm text-gray-900 dark:text-white font-mono break-all">
                  {selectedCert.key_id}
                </p>
              </div>
              <div>
                <label className="form-label">Multi-PQC</label>
                <p className="text-sm text-gray-900 dark:text-white">
                  {selectedCert.is_multi_pqc ? 'Yes' : 'No'}
                </p>
              </div>
              <div>
                <label className="form-label">Has KEM</label>
                <p className="text-sm text-gray-900 dark:text-white">
                  {selectedCert.has_kem ? 'Yes' : 'No'}
                </p>
              </div>
            </div>

            <div className="flex flex-wrap justify-end gap-2">
              <button
                onClick={() => handleDownloadCertificate(selectedCert.id, 'pem')}
                className="btn-secondary btn-sm"
              >
                <ArrowDownTrayIcon className="w-4 h-4 mr-1" />
                PEM
              </button>
              <button
                onClick={() => handleDownloadCertificate(selectedCert.id, 'key')}
                className="btn-secondary btn-sm"
              >
                <ArrowDownTrayIcon className="w-4 h-4 mr-1" />
                Key
              </button>
              <button
                onClick={() => handleDownloadCertificate(selectedCert.id, 'bundle')}
                className="btn-secondary btn-sm"
              >
                <ArrowDownTrayIcon className="w-4 h-4 mr-1" />
                Bundle
              </button>
              {selectedCert.is_multi_pqc && (
                <button
                  onClick={() => handleDownloadCertificate(selectedCert.id, 'multi-pqc')}
                  className="btn-secondary btn-sm"
                >
                  <ArrowDownTrayIcon className="w-4 h-4 mr-1" />
                  Multi-PQC
                </button>
              )}
              {selectedCert.status === 'active' && (
                <>
                  <button
                    onClick={() => handleRenewCertificate(selectedCert.id)}
                    className="btn-primary btn-sm"
                  >
                    <ArrowPathIcon className="w-4 h-4 mr-1" />
                    Renew
                  </button>
                  <button
                    onClick={() => handleRevokeCertificate(selectedCert.id)}
                    className="btn-danger btn-sm"
                  >
                    <XMarkIcon className="w-4 h-4 mr-1" />
                    Revoke
                  </button>
                </>
              )}
            </div>
          </div>
        )}
      </Modal>

      <Modal
        isOpen={showBatchModal}
        onClose={() => setShowBatchModal(false)}
        title="Bulk Certificate Operations"
      >
        <div className="space-y-4">
          <p className="text-sm text-gray-600 dark:text-gray-400">
            Selected {selectedCerts.length} certificates for bulk operation.
          </p>
          
          <div className="flex justify-end space-x-3">
            <button
              onClick={() => setShowBatchModal(false)}
              className="btn-secondary"
            >
              Cancel
            </button>
            <button
              onClick={handleBatchRenew}
              disabled={batchRenewMutation.loading}
              className="btn-primary"
            >
              {batchRenewMutation.loading ? <LoadingSpinner size="sm" /> : 'Renew All'}
            </button>
            <button
              onClick={() => handleBatchRevoke()}
              disabled={batchRevokeMutation.loading}
              className="btn-danger"
            >
              {batchRevokeMutation.loading ? <LoadingSpinner size="sm" /> : 'Revoke All'}
            </button>
          </div>
        </div>
      </Modal>
    </div>
  );
};

export default Certificates;