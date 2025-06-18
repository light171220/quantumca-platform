import React, { useState } from 'react';
import { useApi, useMutation } from '../hooks/useApi';
import { apiService } from '../services/api';
import { Customer, CreateCustomerRequest } from '../types/api';
import { TableColumn } from '../types/common';
import DataTable from '../components/DataTable';
import StatusBadge from '../components/StatusBadge';
import Modal from '../components/Modal';
import LoadingSpinner from '../components/LoadingSpinner';
import { formatDate, formatRelativeTime, copyToClipboard } from '../utils/helpers';
import { customerFormSchema, CustomerFormData } from '../utils/validation';
import { PlusIcon, EyeIcon, EyeSlashIcon, ClipboardDocumentIcon } from '@heroicons/react/24/outline';
import toast from 'react-hot-toast';

const Customers: React.FC = () => {
  const [page, setPage] = useState(1);
  const [showCreateModal, setShowCreateModal] = useState(false);
  const [showDetailsModal, setShowDetailsModal] = useState(false);
  const [selectedCustomer, setSelectedCustomer] = useState<Customer | null>(null);
  const [showApiKey, setShowApiKey] = useState(false);
  const [formData, setFormData] = useState<CustomerFormData>({
    name: '',
    email: '',
    organization: '',
    tier: 'basic',
  });

  const { data: customersData, loading, refetch } = useApi(() => 
    apiService.getCustomers({ page, page_size: 25 })
  );

  const createMutation = useMutation((data: CreateCustomerRequest) => 
    apiService.createCustomer(data)
  );

  const updateMutation = useMutation(({ id, data }: { id: string; data: Partial<Customer> }) => 
    apiService.updateCustomer(id, data)
  );

  const columns: TableColumn<Customer>[] = [
    {
      key: 'company_name',
      title: 'Name',
      sortable: true,
    },
    {
      key: 'email',
      title: 'Email',
      sortable: true,
    },
    {
      key: 'tier',
      title: 'Tier',
      render: (tier: number) => {
        const tierName = tier === 1 ? 'basic' : tier === 2 ? 'premium' : 'enterprise';
        return (
          <span className={`px-2 py-1 text-xs font-medium rounded-full ${
            tier === 3 ? 'bg-purple-100 text-purple-800' :
            tier === 2 ? 'bg-blue-100 text-blue-800' :
            'bg-gray-100 text-gray-800'
          }`}>
            {tierName.charAt(0).toUpperCase() + tierName.slice(1)}
          </span>
        );
      },
    },
    {
      key: 'status',
      title: 'Status',
      render: (status: string) => <StatusBadge status={status} />,
    },
    {
      key: 'created_at',
      title: 'Created',
      render: (date: string) => formatRelativeTime(date),
    },
  ];

  const handleCreateCustomer = async (e: React.FormEvent) => {
    e.preventDefault();
    
    try {
      const validated = customerFormSchema.parse(formData);
      await createMutation.mutate(validated);
      toast.success('Customer created successfully');
      setShowCreateModal(false);
      refetch();
      resetForm();
    } catch (error) {
      toast.error('Failed to create customer');
    }
  };

  const handleUpdateCustomer = async (id: string, updates: Partial<Customer>) => {
    try {
      await updateMutation.mutate({ id, data: updates });
      toast.success('Customer updated successfully');
      refetch();
    } catch (error) {
      toast.error('Failed to update customer');
    }
  };

  const resetForm = () => {
    setFormData({
      name: '',
      email: '',
      organization: '',
      tier: 'basic',
    });
  };

  const copyApiKey = async (apiKey: string) => {
    const success = await copyToClipboard(apiKey);
    if (success) {
      toast.success('API key copied to clipboard');
    } else {
      toast.error('Failed to copy API key');
    }
  };

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <h1 className="text-2xl font-bold text-gray-900 dark:text-white">Customers</h1>
        <button
          onClick={() => setShowCreateModal(true)}
          className="btn-primary"
        >
          <PlusIcon className="w-5 h-5 mr-2" />
          Create Customer
        </button>
      </div>

      <div className="card">
        <div className="card-body">
          <DataTable
            data={customersData?.data || []}
            columns={columns}
            loading={loading}
            pagination={{
              current: page,
              total: customersData?.total || 0,
              pageSize: 25,
              onChange: setPage,
            }}
            onRowClick={(customer) => {
              setSelectedCustomer(customer);
              setShowDetailsModal(true);
            }}
          />
        </div>
      </div>

      <Modal
        isOpen={showCreateModal}
        onClose={() => setShowCreateModal(false)}
        title="Create New Customer"
      >
        <form onSubmit={handleCreateCustomer} className="space-y-4">
          <div>
            <label className="form-label">Company Name</label>
            <input
              type="text"
              className="form-input"
              value={formData.name}
              onChange={(e) => setFormData(prev => ({ ...prev, name: e.target.value }))}
              required
              placeholder="Enter company name"
              title="Company Name"
            />
          </div>

          <div>
            <label className="form-label">Email</label>
            <input
              type="email"
              className="form-input"
              value={formData.email}
              onChange={(e) => setFormData(prev => ({ ...prev, email: e.target.value }))}
              required
              title="Email"
              placeholder="Enter email address"
            />
          </div>

          <div>
            <label className="form-label" htmlFor="customer-tier-select">Tier</label>
            <select
              id="customer-tier-select"
              className="form-input"
              value={formData.tier}
              onChange={(e) => setFormData(prev => ({ ...prev, tier: e.target.value as 'basic' | 'premium' | 'enterprise' }))}
            >
              <option value="basic">Basic (Tier 1)</option>
              <option value="premium">Premium (Tier 2)</option>
              <option value="enterprise">Enterprise (Tier 3)</option>
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
              {createMutation.loading ? <LoadingSpinner size="sm" /> : 'Create Customer'}
            </button>
          </div>
        </form>
      </Modal>

      <Modal
        isOpen={showDetailsModal}
        onClose={() => setShowDetailsModal(false)}
        title="Customer Details"
        size="lg"
      >
        {selectedCustomer && (
          <div className="space-y-6">
            <div className="grid grid-cols-2 gap-4">
              <div>
                <label className="form-label">Company Name</label>
                <p className="text-sm text-gray-900 dark:text-white">{selectedCustomer.company_name}</p>
              </div>
              <div>
                <label className="form-label">Email</label>
                <p className="text-sm text-gray-900 dark:text-white">{selectedCustomer.email}</p>
              </div>
              <div>
                <label className="form-label">Tier</label>
                <span className={`inline-flex px-2 py-1 text-xs font-medium rounded-full ${
                  selectedCustomer.tier === 3 ? 'bg-purple-100 text-purple-800' :
                  selectedCustomer.tier === 2 ? 'bg-blue-100 text-blue-800' :
                  'bg-gray-100 text-gray-800'
                }`}>
                  {selectedCustomer.tier === 1 ? 'Basic' : selectedCustomer.tier === 2 ? 'Premium' : 'Enterprise'}
                </span>
              </div>
              <div>
                <label className="form-label">Status</label>
                <StatusBadge status={selectedCustomer.status} />
              </div>
              <div>
                <label className="form-label">Created</label>
                <p className="text-sm text-gray-900 dark:text-white">
                  {formatDate(selectedCustomer.created_at)}
                </p>
              </div>
              <div>
                <label className="form-label">Last Updated</label>
                <p className="text-sm text-gray-900 dark:text-white">
                  {formatDate(selectedCustomer.updated_at)}
                </p>
              </div>
            </div>

            <div className="border-t pt-4">
              <label className="form-label">API Key</label>
              <div className="flex items-center space-x-2">
                <div className="flex-1 font-mono text-sm bg-gray-50 dark:bg-gray-700 px-3 py-2 rounded">
                  {showApiKey ? selectedCustomer.api_key : '••••••••••••••••••••••••••••••••'}
                </div>
                <button
                  onClick={() => setShowApiKey(!showApiKey)}
                  className="p-2 text-gray-500 hover:text-gray-700"
                  title={showApiKey ? "Hide API Key" : "Show API Key"}
                >
                  {showApiKey ? <EyeSlashIcon className="w-5 h-5" /> : <EyeIcon className="w-5 h-5" />}
                </button>
                <button
                  onClick={() => copyApiKey(selectedCustomer.api_key)}
                  className="p-2 text-gray-500 hover:text-gray-700"
                  title="Copy API Key"
                >
                  <ClipboardDocumentIcon className="w-5 h-5" />
                </button>
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
                onClick={() => {
                  const newStatus = selectedCustomer.status === 'active' ? 'inactive' : 'active';
                  handleUpdateCustomer(selectedCustomer.id, { status: newStatus });
                }}
                className={`btn ${selectedCustomer.status === 'active' ? 'btn-danger' : 'btn-success'}`}
              >
                {selectedCustomer.status === 'active' ? 'Deactivate' : 'Activate'}
              </button>
            </div>
          </div>
        )}
      </Modal>
    </div>
  );
};

export default Customers;