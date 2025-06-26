/* eslint-disable no-restricted-globals */
import React, { useState } from 'react';
import { useApi, useMutation } from '../hooks/useApi';
import { apiService } from '../services/api';
import { IntermediateCA, CreateIntermediateCARequest } from '../types/api';
import { TableColumn } from '../types/common';
import DataTable from '../components/DataTable';
import StatusBadge from '../components/StatusBadge';
import Modal from '../components/Modal';
import LoadingSpinner from '../components/LoadingSpinner';
import { formatDate, truncateText } from '../utils/helpers';
import { intermediateCAFormSchema, IntermediateCAFormData } from '../utils/validation';
import { 
  PlusIcon, 
  BuildingLibraryIcon, 
  TrashIcon,
  ArrowDownTrayIcon,
  ShieldCheckIcon,
  ClockIcon,
  ExclamationTriangleIcon
} from '@heroicons/react/24/outline';
import toast from 'react-hot-toast';

const IntermediateCAPage: React.FC = () => {
  const [page, setPage] = useState(1);
  const [showCreateModal, setShowCreateModal] = useState(false);
  const [showDetailsModal, setShowDetailsModal] = useState(false);
  const [selectedCA, setSelectedCA] = useState<IntermediateCA | null>(null);
  const [formData, setFormData] = useState<IntermediateCAFormData>({
    name: '',
    description: '',
    validityPeriod: 1825,
  });

  const { data: caData, loading, refetch } = useApi(() => 
    apiService.getIntermediateCAs({ page, page_size: 25 })
  );

  const createMutation = useMutation((data: CreateIntermediateCARequest) => 
    apiService.createIntermediateCA(data)
  );

  const deleteMutation = useMutation((id: string) => 
    apiService.deleteIntermediateCA(id)
  );

  const getCAStats = () => {
    const cas = caData?.data || [];
    return {
      total: cas.length,
      active: cas.filter(ca => ca.status === 'active').length,
      expired: cas.filter(ca => ca.status === 'expired').length,
      revoked: cas.filter(ca => ca.status === 'revoked').length,
      multiPQC: cas.filter(ca => ca.is_multi_pqc).length,
    };
  };

  const stats = getCAStats();

  const columns: TableColumn<IntermediateCA>[] = [
    {
      key: 'common_name',
      title: 'Name',
      sortable: true,
      render: (name: string, ca: IntermediateCA) => (
        <div>
          <div className="font-medium text-gray-900 dark:text-white">{name}</div>
          {ca.is_multi_pqc && (
            <span className="inline-flex items-center px-2 py-0.5 rounded text-xs font-medium bg-purple-100 text-purple-800 dark:bg-purple-900 dark:text-purple-200">
              Multi-PQC
            </span>
          )}
        </div>
      ),
    },
    {
      key: 'algorithm',
      title: 'Algorithm',
      render: (algorithm: string, ca: IntermediateCA) => (
        <div className="flex flex-col">
          <span className="font-medium">{algorithm}</span>
          {ca.algorithms.length > 1 && (
            <span className="text-xs text-gray-500">+{ca.algorithms.length - 1} more</span>
          )}
        </div>
      ),
    },
    {
      key: 'serial_number',
      title: 'Serial Number',
      render: (serial: string) => (
        <span className="font-mono text-sm">{truncateText(serial, 16)}</span>
      ),
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
      render: (date: string) => {
        const expiryDate = new Date(date);
        const daysLeft = Math.ceil((expiryDate.getTime() - Date.now()) / (1000 * 60 * 60 * 24));
        
        return (
          <div className="flex flex-col">
            <span className="text-sm">{formatDate(date)}</span>
            <span className={`text-xs ${
              daysLeft <= 30 ? 'text-red-600' : 
              daysLeft <= 90 ? 'text-yellow-600' : 
              'text-green-600'
            }`}>
              {daysLeft > 0 ? `${daysLeft} days left` : 'Expired'}
            </span>
          </div>
        );
      },
    },
    {
      key: 'actions',
      title: 'Actions',
      render: (_, ca: IntermediateCA) => (
        <div className="flex space-x-2">
          <button
            onClick={(e) => {
              e.stopPropagation();
              setSelectedCA(ca);
              setShowDetailsModal(true);
            }}
            className="text-blue-600 hover:text-blue-800 text-sm"
          >
            View
          </button>
          <button
            onClick={(e) => {
              e.stopPropagation();
              handleDeleteCA(ca.id);
            }}
            className="text-red-600 hover:text-red-800 text-sm"
          >
            Revoke
          </button>
        </div>
      ),
    },
  ];

  const handleCreateCA = async (e: React.FormEvent) => {
    e.preventDefault();
    
    try {
      const validated = intermediateCAFormSchema.parse(formData);
      await createMutation.mutate({
        ...validated,
        country: 'US',
        state: 'California',
        city: 'San Francisco',
        organization: 'QuantumCA',
        organizationalUnit: 'Certificate Authority',
        algorithm: 'dilithium3',
        useMultiPQC: true,
        maxPathLen: 0,
      });
      toast.success('Intermediate CA created successfully');
      setShowCreateModal(false);
      refetch();
      resetForm();
    } catch (error) {
      toast.error('Failed to create intermediate CA');
    }
  };

  const handleDeleteCA = async (id: string) => {
    if (!confirm('Are you sure you want to revoke this intermediate CA? This action cannot be undone.')) {
      return;
    }
    
    try {
      await deleteMutation.mutate(id);
      toast.success('Intermediate CA revoked successfully');
      refetch();
    } catch (error) {
      toast.error('Failed to revoke intermediate CA');
    }
  };

  const resetForm = () => {
    setFormData({
      name: '',
      description: '',
      validityPeriod: 1825,
    });
  };

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold text-gray-900 dark:text-white">Intermediate Certificate Authorities</h1>
          <p className="text-sm text-gray-600 dark:text-gray-400 mt-1">
            Manage intermediate CAs for issuing end-entity certificates with post-quantum cryptography
          </p>
        </div>
        <button
          onClick={() => setShowCreateModal(true)}
          className="btn-primary"
        >
          <PlusIcon className="w-5 h-5 mr-2" />
          Create Intermediate CA
        </button>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-5 gap-4">
        <div className="card">
          <div className="card-body flex items-center">
            <BuildingLibraryIcon className="h-8 w-8 text-blue-600 mr-3" />
            <div>
              <p className="text-sm text-gray-600 dark:text-gray-400">Total CAs</p>
              <p className="text-xl font-bold">{stats.total}</p>
            </div>
          </div>
        </div>
        <div className="card">
          <div className="card-body flex items-center">
            <ShieldCheckIcon className="h-8 w-8 text-green-600 mr-3" />
            <div>
              <p className="text-sm text-gray-600 dark:text-gray-400">Active</p>
              <p className="text-xl font-bold">{stats.active}</p>
            </div>
          </div>
        </div>
        <div className="card">
          <div className="card-body flex items-center">
            <ClockIcon className="h-8 w-8 text-yellow-600 mr-3" />
            <div>
              <p className="text-sm text-gray-600 dark:text-gray-400">Expired</p>
              <p className="text-xl font-bold">{stats.expired}</p>
            </div>
          </div>
        </div>
        <div className="card">
          <div className="card-body flex items-center">
            <ExclamationTriangleIcon className="h-8 w-8 text-red-600 mr-3" />
            <div>
              <p className="text-sm text-gray-600 dark:text-gray-400">Revoked</p>
              <p className="text-xl font-bold">{stats.revoked}</p>
            </div>
          </div>
        </div>
        <div className="card">
          <div className="card-body flex items-center">
            <ShieldCheckIcon className="h-8 w-8 text-purple-600 mr-3" />
            <div>
              <p className="text-sm text-gray-600 dark:text-gray-400">Multi-PQC</p>
              <p className="text-xl font-bold">{stats.multiPQC}</p>
            </div>
          </div>
        </div>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-4 gap-6">
        <div className="lg:col-span-3">
          <div className="card">
            <div className="card-body">
              <DataTable
                data={caData?.data || []}
                columns={columns}
                loading={loading}
                pagination={{
                  current: page,
                  total: caData?.total || 0,
                  pageSize: 25,
                  onChange: setPage,
                }}
                onRowClick={(ca) => {
                  setSelectedCA(ca);
                  setShowDetailsModal(true);
                }}
              />
            </div>
          </div>
        </div>

        <div className="space-y-6">
          <div className="card">
            <div className="card-header">
              <h3 className="text-lg font-medium text-gray-900 dark:text-white">CA Hierarchy</h3>
            </div>
            <div className="card-body">
              <div className="space-y-3">
                <div className="flex items-center space-x-2">
                  <BuildingLibraryIcon className="w-5 h-5 text-blue-600" />
                  <span className="text-sm font-medium">QuantumCA Root CA</span>
                  <span className="px-2 py-0.5 text-xs bg-blue-100 text-blue-800 rounded">Root</span>
                </div>
                {(caData?.data || []).map((ca) => (
                  <div key={ca.id} className="ml-6 flex items-center space-x-2">
                    <div className="w-4 h-0.5 bg-gray-300"></div>
                    <BuildingLibraryIcon className="w-4 h-4 text-green-600" />
                    <span className="text-sm">{ca.common_name}</span>
                    <StatusBadge status={ca.status} size="sm" />
                  </div>
                ))}
              </div>
            </div>
          </div>

          <div className="card">
            <div className="card-header">
              <h3 className="text-lg font-medium text-gray-900 dark:text-white">Algorithm Distribution</h3>
            </div>
            <div className="card-body space-y-3">
              {stats.total > 0 ? (
                <>
                  <div className="flex justify-between">
                    <span className="text-sm text-gray-600 dark:text-gray-400">Multi-PQC Enabled</span>
                    <span className="font-medium">{stats.multiPQC}/{stats.total}</span>
                  </div>
                  <div className="w-full bg-gray-200 rounded-full h-2">
                    <div 
                      className="bg-purple-600 h-2 rounded-full" 
                      style={{ width: `${(stats.multiPQC / stats.total) * 100}%` }}
                    ></div>
                  </div>
                  <div className="text-xs text-gray-500 dark:text-gray-400">
                    {((stats.multiPQC / stats.total) * 100).toFixed(1)}% using post-quantum cryptography
                  </div>
                </>
              ) : (
                <div className="text-center text-gray-500 dark:text-gray-400 py-4">
                  No intermediate CAs created yet
                </div>
              )}
            </div>
          </div>
        </div>
      </div>

      <Modal
        isOpen={showCreateModal}
        onClose={() => setShowCreateModal(false)}
        title="Create Intermediate CA"
        size="lg"
      >
        <form onSubmit={handleCreateCA} className="space-y-4">
          <div>
            <label className="form-label">Common Name</label>
            <input
              type="text"
              className="form-input"
              placeholder="e.g., QuantumCA Production Intermediate"
              value={formData.name}
              onChange={(e) => setFormData(prev => ({ ...prev, name: e.target.value }))}
              required
            />
            <p className="text-xs text-gray-500 mt-1">
              This will be the CN field in the certificate subject
            </p>
          </div>

          <div>
            <label className="form-label">Description (Optional)</label>
            <textarea
              className="form-input"
              rows={3}
              placeholder="Purpose and scope of this intermediate CA"
              value={formData.description}
              onChange={(e) => setFormData(prev => ({ ...prev, description: e.target.value }))}
            />
          </div>

          <div>
            <label className="form-label">Validity Period</label>
            <select
              className="form-input"
              value={formData.validityPeriod}
              onChange={(e) => setFormData(prev => ({ ...prev, validityPeriod: parseInt(e.target.value) }))}
            >
              <option value={1095}>3 years (1095 days)</option>
              <option value={1825}>5 years (1825 days)</option>
              <option value={2555}>7 years (2555 days)</option>
              <option value={3650}>10 years (3650 days)</option>
            </select>
            <p className="text-xs text-gray-500 mt-1">
              Longer validity periods reduce operational overhead but increase risk
            </p>
          </div>

          <div className="bg-blue-50 dark:bg-blue-900/20 p-4 rounded-lg">
            <h4 className="font-medium text-blue-900 dark:text-blue-100 mb-2">
              Post-Quantum Cryptography
            </h4>
            <div className="text-sm text-blue-700 dark:text-blue-300 space-y-2">
              <p>This intermediate CA will be created with:</p>
              <ul className="list-disc list-inside space-y-1">
                <li>Dilithium3 signature algorithm (NIST Level 3)</li>
                <li>Multi-algorithm support for hybrid certificates</li>
                <li>Future-proof quantum-resistant cryptography</li>
                <li>Path length constraint of 0 (end-entity certificates only)</li>
              </ul>
            </div>
          </div>

          <div className="bg-yellow-50 dark:bg-yellow-900/20 p-4 rounded-lg">
            <div className="flex">
              <div className="flex-shrink-0">
                <ExclamationTriangleIcon className="h-5 w-5 text-yellow-400" />
              </div>
              <div className="ml-3">
                <h3 className="text-sm font-medium text-yellow-800 dark:text-yellow-200">
                  Security Notice
                </h3>
                <div className="mt-2 text-sm text-yellow-700 dark:text-yellow-300">
                  <p>Creating an intermediate CA is a critical security operation. Ensure you have proper authorization and follow your organization's security policies.</p>
                </div>
              </div>
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
              {createMutation.loading ? <LoadingSpinner size="sm" /> : 'Create Intermediate CA'}
            </button>
          </div>
        </form>
      </Modal>

      <Modal
        isOpen={showDetailsModal}
        onClose={() => setShowDetailsModal(false)}
        title="Intermediate CA Details"
        size="lg"
      >
        {selectedCA && (
          <div className="space-y-6">
            <div className="grid grid-cols-2 gap-4">
              <div>
                <label className="form-label">Common Name</label>
                <p className="text-sm text-gray-900 dark:text-white">{selectedCA.common_name}</p>
              </div>
              <div>
                <label className="form-label">Status</label>
                <StatusBadge status={selectedCA.status} />
              </div>
              <div>
                <label className="form-label">Algorithm</label>
                <p className="text-sm text-gray-900 dark:text-white">{selectedCA.algorithm}</p>
              </div>
              <div>
                <label className="form-label">Multi-PQC</label>
                <p className="text-sm text-gray-900 dark:text-white">
                  {selectedCA.is_multi_pqc ? 'Yes' : 'No'}
                </p>
              </div>
              <div>
                <label className="form-label">Has KEM</label>
                <p className="text-sm text-gray-900 dark:text-white">
                  {selectedCA.has_kem ? 'Yes' : 'No'}
                </p>
              </div>
              <div>
                <label className="form-label">Max Path Length</label>
                <p className="text-sm text-gray-900 dark:text-white">{selectedCA.max_path_len}</p>
              </div>
              <div className="col-span-2">
                <label className="form-label">Serial Number</label>
                <p className="text-sm font-mono text-gray-900 dark:text-white break-all">
                  {selectedCA.serial_number}
                </p>
              </div>
              <div className="col-span-2">
                <label className="form-label">Fingerprint</label>
                <p className="text-sm font-mono text-gray-900 dark:text-white break-all">
                  {selectedCA.fingerprint}
                </p>
              </div>
              <div>
                <label className="form-label">Valid From</label>
                <p className="text-sm text-gray-900 dark:text-white">
                  {formatDate(selectedCA.not_before)}
                </p>
              </div>
              <div>
                <label className="form-label">Valid To</label>
                <p className="text-sm text-gray-900 dark:text-white">
                  {formatDate(selectedCA.not_after)}
                </p>
              </div>
              {selectedCA.algorithms.length > 1 && (
                <div className="col-span-2">
                  <label className="form-label">All Algorithms</label>
                  <p className="text-sm text-gray-900 dark:text-white">
                    {selectedCA.algorithms.join(', ')}
                  </p>
                </div>
              )}
            </div>

            <div className="flex justify-end space-x-3">
              <button
                onClick={() => setShowDetailsModal(false)}
                className="btn-secondary"
              >
                Close
              </button>
              {selectedCA.certificate && (
                <button
                  onClick={() => {
                    const blob = new Blob([selectedCA.certificate!], { type: 'application/x-pem-file' });
                    const url = URL.createObjectURL(blob);
                    const a = document.createElement('a');
                    a.href = url;
                    a.download = `${selectedCA.common_name.replace(/[^a-zA-Z0-9]/g, '_')}_ca.pem`;
                    a.click();
                    URL.revokeObjectURL(url);
                  }}
                  className="btn-secondary"
                >
                  <ArrowDownTrayIcon className="w-4 h-4 mr-2" />
                  Download Certificate
                </button>
              )}
              {selectedCA.status === 'active' && (
                <button
                  onClick={() => handleDeleteCA(selectedCA.id)}
                  className="btn-danger"
                >
                  <TrashIcon className="w-4 h-4 mr-2" />
                  Revoke CA
                </button>
              )}
            </div>
          </div>
        )}
      </Modal>
    </div>
  );
};

export default IntermediateCAPage;