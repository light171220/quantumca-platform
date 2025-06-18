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
import { PlusIcon, BuildingLibraryIcon, TrashIcon } from '@heroicons/react/24/outline';
import toast from 'react-hot-toast';

const IntermediateCAPage: React.FC = () => {
  const [showCreateModal, setShowCreateModal] = useState(false);
  const [showDetailsModal, setShowDetailsModal] = useState(false);
  const [selectedCA, setSelectedCA] = useState<IntermediateCA | null>(null);
  const [formData, setFormData] = useState<IntermediateCAFormData>({
    name: '',
    description: '',
    validityPeriod: 1825,
  });

  const { data: caData, loading, refetch } = useApi(() => apiService.getIntermediateCAs());

  const createMutation = useMutation((data: CreateIntermediateCARequest) => 
    apiService.createIntermediateCA(data)
  );

  const deleteMutation = useMutation((id: string) => 
    apiService.deleteIntermediateCA(id)
  );

  const columns: TableColumn<IntermediateCA>[] = [
    {
      key: 'name',
      title: 'Name',
      sortable: true,
    },
    {
      key: 'subject',
      title: 'Subject',
      render: (subject: string) => (
        <span className="font-mono text-sm" title={subject}>
          {truncateText(subject, 40)}
        </span>
      ),
    },
    {
      key: 'serialNumber',
      title: 'Serial Number',
      render: (serial: string) => (
        <span className="font-mono text-sm">{truncateText(serial, 20)}</span>
      ),
    },
    {
      key: 'status',
      title: 'Status',
      render: (status: string) => <StatusBadge status={status} />,
    },
    {
      key: 'validFrom',
      title: 'Valid From',
      render: (date: string) => formatDate(date),
    },
    {
      key: 'validTo',
      title: 'Valid To',
      render: (date: string) => formatDate(date),
    },
    {
      key: 'tier',
      title: 'Tier',
      render: (tier: string) => (
        <span className={`px-2 py-1 text-xs font-medium rounded-full ${
          tier === 'enterprise' ? 'bg-purple-100 text-purple-800' :
          'bg-blue-100 text-blue-800'
        }`}>
          {tier.charAt(0).toUpperCase() + tier.slice(1)}
        </span>
      ),
    },
    {
      key: 'actions',
      title: 'Actions',
      render: (_, ca: IntermediateCA) => (
        <button
          onClick={(e) => {
            e.stopPropagation();
            handleDeleteCA(ca.id);
          }}
          className="text-red-600 hover:text-red-800 text-sm"
        >
          Delete
        </button>
      ),
    },
  ];

  const handleCreateCA = async (e: React.FormEvent) => {
    e.preventDefault();
    
    try {
      const validated = intermediateCAFormSchema.parse(formData);
      await createMutation.mutate(validated);
      toast.success('Intermediate CA created successfully');
      setShowCreateModal(false);
      refetch();
      resetForm();
    } catch (error) {
      toast.error('Failed to create intermediate CA');
    }
  };

  const handleDeleteCA = async (id: string) => {
    if (!confirm('Are you sure you want to delete this intermediate CA? This action cannot be undone.')) {
      return;
    }
    
    try {
      await deleteMutation.mutate(id);
      toast.success('Intermediate CA deleted successfully');
      refetch();
    } catch (error) {
      toast.error('Failed to delete intermediate CA');
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
            Manage intermediate CAs for issuing certificates
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

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        <div className="lg:col-span-2">
          <div className="card">
            <div className="card-body">
              <DataTable
                data={caData || []}
                columns={columns}
                loading={loading}
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
                </div>
                {(caData || []).map((ca) => (
                  <div key={ca.id} className="ml-6 flex items-center space-x-2">
                    <div className="w-4 h-0.5 bg-gray-300"></div>
                    <BuildingLibraryIcon className="w-4 h-4 text-green-600" />
                    <span className="text-sm">{ca.name}</span>
                  </div>
                ))}
              </div>
            </div>
          </div>

          <div className="card">
            <div className="card-header">
              <h3 className="text-lg font-medium text-gray-900 dark:text-white">Statistics</h3>
            </div>
            <div className="card-body space-y-3">
              <div className="flex justify-between">
                <span className="text-sm text-gray-600 dark:text-gray-400">Total CAs</span>
                <span className="font-medium">{(caData || []).length}</span>
              </div>
              <div className="flex justify-between">
                <span className="text-sm text-gray-600 dark:text-gray-400">Active CAs</span>
                <span className="font-medium">{(caData || []).filter(ca => ca.status === 'active').length}</span>
              </div>
              <div className="flex justify-between">
                <span className="text-sm text-gray-600 dark:text-gray-400">Enterprise Tier</span>
                <span className="font-medium">{(caData || []).filter(ca => ca.tier === 'enterprise').length}</span>
              </div>
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
            <label className="form-label">Name</label>
            <input
              type="text"
              className="form-input"
              placeholder="e.g., Production Intermediate CA"
              value={formData.name}
              onChange={(e) => setFormData(prev => ({ ...prev, name: e.target.value }))}
              required
            />
          </div>

          <div>
            <label className="form-label">Description (Optional)</label>
            <textarea
              className="form-input"
              rows={3}
              placeholder="Description of the intermediate CA"
              value={formData.description}
              onChange={(e) => setFormData(prev => ({ ...prev, description: e.target.value }))}
            />
          </div>

          <div>
            <label className="form-label" htmlFor="validityPeriod">Validity Period (days)</label>
            <select
              id="validityPeriod"
              className="form-input"
              value={formData.validityPeriod}
              onChange={(e) => setFormData(prev => ({ ...prev, validityPeriod: parseInt(e.target.value) }))}
            >
              <option value={1825}>5 years (1825 days)</option>
              <option value={3650}>10 years (3650 days)</option>
              <option value={1095}>3 years (1095 days)</option>
              <option value={730}>2 years (730 days)</option>
            </select>
          </div>

          <div className="bg-yellow-50 dark:bg-yellow-900/20 p-4 rounded-lg">
            <div className="flex">
              <div className="flex-shrink-0">
                <svg className="h-5 w-5 text-yellow-400" viewBox="0 0 20 20" fill="currentColor">
                  <path fillRule="evenodd" d="M8.257 3.099c.765-1.36 2.722-1.36 3.486 0l5.58 9.92c.75 1.334-.213 2.98-1.742 2.98H4.42c-1.53 0-2.493-1.646-1.743-2.98l5.58-9.92zM11 13a1 1 0 11-2 0 1 1 0 012 0zm-1-8a1 1 0 00-1 1v3a1 1 0 002 0V6a1 1 0 00-1-1z" clipRule="evenodd" />
                </svg>
              </div>
              <div className="ml-3">
                <h3 className="text-sm font-medium text-yellow-800 dark:text-yellow-200">
                  Important Notice
                </h3>
                <div className="mt-2 text-sm text-yellow-700 dark:text-yellow-300">
                  <p>Creating an intermediate CA is a significant security operation. Ensure you have proper authorization and security measures in place.</p>
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
                <label className="form-label">Name</label>
                <p className="text-sm text-gray-900 dark:text-white">{selectedCA.name}</p>
              </div>
              <div>
                <label className="form-label">Status</label>
                <StatusBadge status={selectedCA.status} />
              </div>
              <div className="col-span-2">
                <label className="form-label">Description</label>
                <p className="text-sm text-gray-900 dark:text-white">
                  {selectedCA.description || 'No description provided'}
                </p>
              </div>
              <div className="col-span-2">
                <label className="form-label">Subject</label>
                <p className="text-sm font-mono text-gray-900 dark:text-white break-all">
                  {selectedCA.subject}
                </p>
              </div>
              <div className="col-span-2">
                <label className="form-label">Issuer</label>
                <p className="text-sm font-mono text-gray-900 dark:text-white break-all">
                  {selectedCA.issuer}
                </p>
              </div>
              <div>
                <label className="form-label">Serial Number</label>
                <p className="text-sm font-mono text-gray-900 dark:text-white">
                  {selectedCA.serialNumber}
                </p>
              </div>
              <div>
                <label className="form-label">Tier</label>
                <span className={`inline-flex px-2 py-1 text-xs font-medium rounded-full ${
                  selectedCA.tier === 'enterprise' ? 'bg-purple-100 text-purple-800' :
                  'bg-blue-100 text-blue-800'
                }`}>
                  {selectedCA.tier.charAt(0).toUpperCase() + selectedCA.tier.slice(1)}
                </span>
              </div>
              <div>
                <label className="form-label">Valid From</label>
                <p className="text-sm text-gray-900 dark:text-white">
                  {formatDate(selectedCA.validFrom)}
                </p>
              </div>
              <div>
                <label className="form-label">Valid To</label>
                <p className="text-sm text-gray-900 dark:text-white">
                  {formatDate(selectedCA.validTo)}
                </p>
              </div>
            </div>

            <div className="flex justify-end space-x-3">
              <button
                onClick={() => setShowDetailsModal(false)}
                className="btn-secondary"
              >
                Close
              </button>
              <button
                onClick={() => handleDeleteCA(selectedCA.id)}
                className="btn-danger"
              >
                <TrashIcon className="w-4 h-4 mr-2" />
                Delete CA
              </button>
            </div>
          </div>
        )}
      </Modal>
    </div>
  );
};

export default IntermediateCAPage;