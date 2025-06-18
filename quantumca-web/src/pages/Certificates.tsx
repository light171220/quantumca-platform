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
import { PlusIcon, ArrowDownTrayIcon, ArrowPathIcon } from '@heroicons/react/24/outline';
import toast from 'react-hot-toast';

const Certificates: React.FC = () => {
  const [page, setPage] = useState(1);
  const [selectedCerts, setSelectedCerts] = useState<string[]>([]);
  const [showCreateModal, setShowCreateModal] = useState(false);
  const [showDetailsModal, setShowDetailsModal] = useState(false);
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

  const createMutation = useMutation((data: CreateCertificateRequest) => 
    apiService.createCertificate(data)
  );

  const renewMutation = useMutation((id: string) => 
    apiService.renewCertificate(id)
  );

  const downloadMutation = useMutation(({ id, format }: { id: string; format: 'pem' | 'key' | 'bundle' | 'multi-pqc' }) =>
    apiService.downloadCertificate(id, format)
  );

  const columns: TableColumn<Certificate>[] = [
    {
      key: 'common_name',
      title: 'Common Name',
      render: (commonName: string, cert: Certificate) => {
        const allDomains = [commonName, ...(cert.subject_alt_names || [])];
        return allDomains.join(', ');
      },
    },
    {
      key: 'status',
      title: 'Status',
      render: (status: string) => <StatusBadge status={status} />,
    },
    {
      key: 'not_before',
      title: 'Valid From',
      render: (date: string) => formatDate(date),
    },
    {
      key: 'not_after',
      title: 'Valid To',
      render: (date: string) => formatDate(date),
    },
    {
      key: 'algorithms',
      title: 'Algorithm',
      render: (algorithms: string[]) => algorithms[0] || 'Unknown',
    },
    {
      key: 'created_at',
      title: 'Created',
      render: (date: string) => formatRelativeTime(date),
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
      onClick: (ids: string[]) => {
        ids.forEach(id => handleRenewCertificate(id));
      },
      icon: <ArrowPathIcon className="w-4 h-4" />,
    },
  ];

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <h1 className="text-2xl font-bold text-gray-900 dark:text-white">Certificates</h1>
        <button
          onClick={() => setShowCreateModal(true)}
          className="btn-primary"
        >
          <PlusIcon className="w-5 h-5 mr-2" />
          Issue Certificate
        </button>
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
              <label className="form-label" htmlFor="algorithm-select">Algorithm</label>
              <select
                id="algorithm-select"
                className="form-input"
                value={formData.algorithm}
                onChange={(e) => setFormData(prev => ({ ...prev, algorithm: e.target.value as 'RSA' | 'ECDSA' }))}
              >
                <option value="RSA">RSA</option>
                <option value="ECDSA">ECDSA</option>
              </select>
            </div>

            <div>
              <label className="form-label" htmlFor="keysize-select">Key Size</label>
              <select
                id="keysize-select"
                className="form-input"
                value={formData.keySize}
                onChange={(e) => setFormData(prev => ({ ...prev, keySize: parseInt(e.target.value) }))}
                aria-label="Key Size"
              >
                <option value={2048}>2048</option>
                <option value={4096}>4096</option>
                {formData.algorithm === 'ECDSA' && <option value={256}>256</option>}
              </select>
            </div>
          </div>

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
              placeholder="Enter validity period in days"
            />
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
                  {selectedCert.serial_number || 'N/A'}
                </p>
              </div>
              <div>
                <label className="form-label">Algorithm</label>
                <p className="text-sm text-gray-900 dark:text-white">
                  {selectedCert.algorithms[0] || 'Unknown'}
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
                <label className="form-label">Multi-PQC</label>
                <p className="text-sm text-gray-900 dark:text-white">
                  {selectedCert.is_multi_pqc ? 'Yes' : 'No'}
                </p>
              </div>
            </div>

            <div className="flex justify-end space-x-3">
              <button
                onClick={() => handleDownloadCertificate(selectedCert.id, 'pem')}
                className="btn-secondary"
              >
                <ArrowDownTrayIcon className="w-4 h-4 mr-2" />
                Download PEM
              </button>
              <button
                onClick={() => handleDownloadCertificate(selectedCert.id, 'key')}
                className="btn-secondary"
              >
                <ArrowDownTrayIcon className="w-4 h-4 mr-2" />
                Download Key
              </button>
              <button
                onClick={() => handleDownloadCertificate(selectedCert.id, 'bundle')}
                className="btn-secondary"
              >
                <ArrowDownTrayIcon className="w-4 h-4 mr-2" />
                Download Bundle
              </button>
              {selectedCert.is_multi_pqc && (
                <button
                  onClick={() => handleDownloadCertificate(selectedCert.id, 'multi-pqc')}
                  className="btn-secondary"
                >
                  <ArrowDownTrayIcon className="w-4 h-4 mr-2" />
                  Download Multi-PQC
                </button>
              )}
              <button
                onClick={() => handleRenewCertificate(selectedCert.id)}
                className="btn-primary"
              >
                <ArrowPathIcon className="w-4 h-4 mr-2" />
                Renew
              </button>
            </div>
          </div>
        )}
      </Modal>
    </div>
  );
};

export default Certificates;