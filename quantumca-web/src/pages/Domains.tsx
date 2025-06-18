/* eslint-disable no-restricted-globals */
import React, { useState } from 'react';
import { useApi, useMutation } from '../hooks/useApi';
import { apiService } from '../services/api';
import { Domain, CreateDomainRequest } from '../types/api';
import { TableColumn } from '../types/common';
import DataTable from '../components/DataTable';
import StatusBadge from '../components/StatusBadge';
import Modal from '../components/Modal';
import LoadingSpinner from '../components/LoadingSpinner';
import { formatRelativeTime, copyToClipboard } from '../utils/helpers';
import { domainFormSchema, DomainFormData } from '../utils/validation';
import { PlusIcon, CheckIcon, ClipboardDocumentIcon } from '@heroicons/react/24/outline';
import toast from 'react-hot-toast';

const Domains: React.FC = () => {
  const [page, setPage] = useState(1);
  const [selectedDomains, setSelectedDomains] = useState<string[]>([]);
  const [showCreateModal, setShowCreateModal] = useState(false);
  const [showValidationModal, setShowValidationModal] = useState(false);
  const [selectedDomain, setSelectedDomain] = useState<Domain | null>(null);
  const [formData, setFormData] = useState<DomainFormData>({
    domain: '',
    validationType: 'dns-txt',
  });

  const { data: domainsData, loading, refetch } = useApi(() => 
    apiService.getDomains({ page, page_size: 25 })
  );

  const { data: validationInfo } = useApi(() => 
    selectedDomain ? apiService.getDomainValidationInfo(selectedDomain.id) : Promise.resolve(null),
    [selectedDomain?.id]
  );

  const createMutation = useMutation((data: CreateDomainRequest) => 
    apiService.createDomain(data)
  );

  const verifyMutation = useMutation((id: string) => 
    apiService.verifyDomain(id)
  );

  const deleteMutation = useMutation((id: string) => 
    apiService.deleteDomain(id)
  );

  const columns: TableColumn<Domain>[] = [
    {
      key: 'domain_name',
      title: 'Domain',
      sortable: true,
    },
    {
      key: 'is_verified',
      title: 'Status',
      render: (isVerified: boolean) => (
        <StatusBadge status={isVerified ? 'verified' : 'pending'} />
      ),
    },
    {
      key: 'validation_method',
      title: 'Validation Type',
      render: (type: string) => (
        <span className="px-2 py-1 text-xs font-medium bg-gray-100 dark:bg-gray-700 rounded">
          {type.toUpperCase()}
        </span>
      ),
    },
    {
      key: 'created_at',
      title: 'Created',
      render: (date: string) => formatRelativeTime(date),
    },
    {
      key: 'actions',
      title: 'Actions',
      render: (_, domain: Domain) => (
        <div className="flex space-x-2">
          {!domain.is_verified && (
            <>
              <button
                onClick={(e) => {
                  e.stopPropagation();
                  setSelectedDomain(domain);
                  setShowValidationModal(true);
                }}
                className="text-blue-600 hover:text-blue-800 text-sm"
              >
                View Instructions
              </button>
              <button
                onClick={(e) => {
                  e.stopPropagation();
                  handleVerifyDomain(domain.id);
                }}
                className="text-green-600 hover:text-green-800 text-sm"
              >
                Verify
              </button>
            </>
          )}
          <button
            onClick={(e) => {
              e.stopPropagation();
              handleDeleteDomain(domain.id);
            }}
            className="text-red-600 hover:text-red-800 text-sm"
          >
            Delete
          </button>
        </div>
      ),
    },
  ];

  const handleCreateDomain = async (e: React.FormEvent) => {
    e.preventDefault();
    
    try {
      const validated = domainFormSchema.parse(formData);
      await createMutation.mutate(validated);
      toast.success('Domain added successfully');
      setShowCreateModal(false);
      refetch();
      resetForm();
    } catch (error) {
      toast.error('Failed to add domain');
    }
  };

  const handleVerifyDomain = async (id: string) => {
    try {
      await verifyMutation.mutate(id);
      toast.success('Domain verification initiated');
      refetch();
    } catch (error) {
      toast.error('Failed to verify domain');
    }
  };

  const handleDeleteDomain = async (id: string) => {
    if (!confirm('Are you sure you want to delete this domain?')) return;
    
    try {
      await deleteMutation.mutate(id);
      toast.success('Domain deleted successfully');
      refetch();
    } catch (error) {
      toast.error('Failed to delete domain');
    }
  };

  const resetForm = () => {
    setFormData({
      domain: '',
      validationType: 'dns-txt',
    });
  };

  const copyValidationInfo = async (text: string) => {
    const success = await copyToClipboard(text);
    if (success) {
      toast.success('Copied to clipboard');
    } else {
      toast.error('Failed to copy');
    }
  };

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <h1 className="text-2xl font-bold text-gray-900 dark:text-white">Domains</h1>
        <button
          onClick={() => setShowCreateModal(true)}
          className="btn-primary"
        >
          <PlusIcon className="w-5 h-5 mr-2" />
          Add Domain
        </button>
      </div>

      <div className="card">
        <div className="card-body">
          <DataTable
            data={domainsData?.data || []}
            columns={columns}
            loading={loading}
            pagination={{
              current: page,
              total: domainsData?.total || 0,
              pageSize: 25,
              onChange: setPage,
            }}
            selectedRows={selectedDomains}
            onSelectionChange={setSelectedDomains}
          />
        </div>
      </div>

      <Modal
        isOpen={showCreateModal}
        onClose={() => setShowCreateModal(false)}
        title="Add New Domain"
      >
        <form onSubmit={handleCreateDomain} className="space-y-4">
          <div>
            <label className="form-label">Domain</label>
            <input
              type="text"
              className="form-input"
              placeholder="example.com"
              value={formData.domain}
              onChange={(e) => setFormData(prev => ({ ...prev, domain: e.target.value }))}
              required
            />
          </div>

          <div>
            <label className="form-label" htmlFor="validationType">Validation Type</label>
            <select
              id="validationType"
              className="form-input"
              value={formData.validationType}
              onChange={(e) => setFormData(prev => ({ ...prev, validationType: e.target.value as 'dns-txt' | 'http-01' }))}
            >
              <option value="dns-txt">DNS TXT</option>
              <option value="http-01">HTTP-01</option>
            </select>
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
              {createMutation.loading ? <LoadingSpinner size="sm" /> : 'Add Domain'}
            </button>
          </div>
        </form>
      </Modal>

      <Modal
        isOpen={showValidationModal}
        onClose={() => setShowValidationModal(false)}
        title="Domain Validation Instructions"
        size="lg"
      >
        {selectedDomain && validationInfo && (
          <div className="space-y-4">
            <div className="bg-blue-50 dark:bg-blue-900/20 p-4 rounded-lg">
              <h3 className="font-medium text-blue-900 dark:text-blue-100 mb-2">
                Validation for: {selectedDomain.domain_name}
              </h3>
              <p className="text-sm text-blue-700 dark:text-blue-300">
                Follow the instructions below to verify domain ownership.
              </p>
            </div>

            {validationInfo.validationType === 'dns-txt' && validationInfo.instructions.dnsRecord && (
              <div className="space-y-3">
                <h4 className="font-medium text-gray-900 dark:text-white">DNS TXT Record</h4>
                <div className="bg-gray-50 dark:bg-gray-700 p-3 rounded-md">
                  <div className="space-y-2">
                    <div className="flex justify-between items-center">
                      <span className="text-sm font-medium">Type:</span>
                      <span className="text-sm font-mono">{validationInfo.instructions.dnsRecord.type}</span>
                    </div>
                    <div className="flex justify-between items-center">
                      <span className="text-sm font-medium">Name:</span>
                      <div className="flex items-center space-x-2">
                        <span className="text-sm font-mono">{validationInfo.instructions.dnsRecord.name}</span>
                        <button
                          onClick={() => copyValidationInfo(validationInfo.instructions.dnsRecord!.name)}
                          className="text-gray-500 hover:text-gray-700"
                          title="Copy DNS record name"
                        >
                          <ClipboardDocumentIcon className="w-4 h-4" />
                        </button>
                      </div>
                    </div>
                    <div className="flex justify-between items-center">
                      <span className="text-sm font-medium">Value:</span>
                      <div className="flex items-center space-x-2">
                        <span className="text-sm font-mono break-all">{validationInfo.instructions.dnsRecord.value}</span>
                        <button
                          onClick={() => copyValidationInfo(validationInfo.instructions.dnsRecord!.value)}
                          className="text-gray-500 hover:text-gray-700"
                        >
                          <ClipboardDocumentIcon className="w-4 h-4" />
                        </button>
                      </div>
                    </div>
                  </div>
                </div>
              </div>
            )}

            {validationInfo.validationType === 'http-01' && validationInfo.instructions.httpFile && (
              <div className="space-y-3">
                <h4 className="font-medium text-gray-900 dark:text-white">HTTP File Validation</h4>
                <div className="bg-gray-50 dark:bg-gray-700 p-3 rounded-md">
                  <div className="space-y-2">
                    <div className="flex justify-between items-center">
                      <span className="text-sm font-medium">Path:</span>
                      <div className="flex items-center space-x-2">
                        <span className="text-sm font-mono">{validationInfo.instructions.httpFile.path}</span>
                        <button
                          onClick={() => copyValidationInfo(validationInfo.instructions.httpFile!.path)}
                          className="text-gray-500 hover:text-gray-700"
                        >
                          <ClipboardDocumentIcon className="w-4 h-4" />
                        </button>
                      </div>
                    </div>
                    <div className="flex justify-between items-center">
                      <span className="text-sm font-medium">Content:</span>
                      <div className="flex items-center space-x-2">
                        <span className="text-sm font-mono break-all">{validationInfo.instructions.httpFile.content}</span>
                        <button
                          onClick={() => copyValidationInfo(validationInfo.instructions.httpFile!.content)}
                          className="text-gray-500 hover:text-gray-700"
                        >
                          <ClipboardDocumentIcon className="w-4 h-4" />
                        </button>
                      </div>
                    </div>
                  </div>
                </div>
              </div>
            )}

            <div className="flex justify-end space-x-3">
              <button
                onClick={() => setShowValidationModal(false)}
                className="btn-secondary"
              >
                Close
              </button>
              <button
                onClick={() => handleVerifyDomain(selectedDomain.id)}
                className="btn-primary"
              >
                <CheckIcon className="w-4 h-4 mr-2" />
                Verify Domain
              </button>
            </div>
          </div>
        )}
      </Modal>
    </div>
  );
};

export default Domains;