import React, { useState } from 'react';
import { useApi } from '../hooks/useApi';
import { apiService } from '../services/api';
import { AuditLog } from '../types/api';
import { TableColumn } from '../types/common';
import DataTable from '../components/DataTable';
import Modal from '../components/Modal';
import { formatDate } from '../utils/helpers';
import { MagnifyingGlassIcon, FunnelIcon } from '@heroicons/react/24/outline';

const AuditLogs: React.FC = () => {
  const [page, setPage] = useState(1);
  const [showDetailsModal, setShowDetailsModal] = useState(false);
  const [showFiltersModal, setShowFiltersModal] = useState(false);
  const [selectedLog, setSelectedLog] = useState<AuditLog | null>(null);
  const [filters, setFilters] = useState({
    action: '',
    from: '',
    search: '',
  });

  const { data: auditData, loading, refetch } = useApi(() => 
    apiService.getAuditLogs({ page, page_size: 25, ...filters })
  );

  const columns: TableColumn<AuditLog>[] = [
    {
      key: 'created_at',
      title: 'Timestamp',
      sortable: true,
      render: (date: string) => formatDate(date, 'MMM dd, HH:mm:ss'),
    },
    {
      key: 'action',
      title: 'Action',
      render: (action: string) => (
        <span className="font-medium text-gray-900 dark:text-white">{action}</span>
      ),
    },
    {
      key: 'resource',
      title: 'Resource',
      render: (resource: string) => (
        <span className="px-2 py-1 text-xs font-medium bg-gray-100 dark:bg-gray-700 rounded">
          {resource}
        </span>
      ),
    },
    {
      key: 'customer_id',
      title: 'Customer',
      render: (customerId: number | null) => customerId ? `Customer ${customerId}` : 'System',
    },
    {
      key: 'ip_address',
      title: 'IP Address',
      render: (ip: string) => (
        <span className="font-mono text-sm">{ip}</span>
      ),
    },
  ];

  const handleApplyFilters = () => {
    setPage(1);
    refetch();
    setShowFiltersModal(false);
  };

  const handleClearFilters = () => {
    setFilters({
      action: '',
      from: '',
      search: '',
    });
    setPage(1);
    refetch();
  };

  const filteredLogs = (auditData?.data || []).filter(log => {
    if (filters.search && !log.action.toLowerCase().includes(filters.search.toLowerCase()) &&
        !log.resource.toLowerCase().includes(filters.search.toLowerCase())) {
      return false;
    }
    if (filters.action && log.action !== filters.action) return false;
    return true;
  });

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <h1 className="text-2xl font-bold text-gray-900 dark:text-white">Audit Logs</h1>
        <div className="flex items-center space-x-3">
          <div className="relative">
            <MagnifyingGlassIcon className="absolute left-3 top-1/2 transform -translate-y-1/2 text-gray-400 w-5 h-5" />
            <input
              type="text"
              placeholder="Search logs..."
              className="pl-10 pr-4 py-2 border border-gray-300 dark:border-gray-600 rounded-md focus:ring-quantum-500 focus:border-quantum-500 dark:bg-gray-700 dark:text-white"
              value={filters.search}
              onChange={(e) => setFilters(prev => ({ ...prev, search: e.target.value }))}
            />
          </div>
          <button
            onClick={() => setShowFiltersModal(true)}
            className="btn-secondary"
          >
            <FunnelIcon className="w-5 h-5 mr-2" />
            Filters
          </button>
        </div>
      </div>

      {Object.values(filters).some(value => value) && (
        <div className="flex items-center gap-2 p-4 bg-blue-50 dark:bg-blue-900/20 rounded-lg">
          <span className="text-sm text-blue-700 dark:text-blue-300">Active filters:</span>
          {filters.action && (
            <span className="px-2 py-1 text-xs bg-blue-100 dark:bg-blue-800 text-blue-800 dark:text-blue-200 rounded">
              Action: {filters.action}
            </span>
          )}
          {filters.search && (
            <span className="px-2 py-1 text-xs bg-blue-100 dark:bg-blue-800 text-blue-800 dark:text-blue-200 rounded">
              Search: {filters.search}
            </span>
          )}
          <button
            onClick={handleClearFilters}
            className="text-xs text-blue-600 hover:text-blue-800 dark:text-blue-400 dark:hover:text-blue-200"
          >
            Clear all
          </button>
        </div>
      )}

      <div className="card">
        <div className="card-body">
          <DataTable
            data={filteredLogs}
            columns={columns}
            loading={loading}
            pagination={{
              current: page,
              total: filteredLogs.length,
              pageSize: 25,
              onChange: setPage,
            }}
            onRowClick={(log) => {
              setSelectedLog(log);
              setShowDetailsModal(true);
            }}
          />
        </div>
      </div>

      <Modal
        isOpen={showFiltersModal}
        onClose={() => setShowFiltersModal(false)}
        title="Filter Audit Logs"
      >
        <div className="space-y-4">
          <div>
            <label className="form-label">Action</label>
            <select
              className="form-input"
              value={filters.action}
              onChange={(e) => setFilters(prev => ({ ...prev, action: e.target.value }))}
              aria-label="Filter by action"
            >
              <option value="">All actions</option>
              <option value="certificate_issued">Certificate Issued</option>
              <option value="certificate_revoked">Certificate Revoked</option>
              <option value="domain_verified">Domain Verified</option>
              <option value="customer_created">Customer Created</option>
            </select>
          </div>

          <div>
            <label className="form-label">From Date</label>
            <input
              type="datetime-local"
              className="form-input"
              value={filters.from}
              onChange={(e) => setFilters(prev => ({ ...prev, from: e.target.value }))}
              placeholder="Select start date and time"
              title="Start Date and Time"
            />
          </div>

          <div className="flex justify-end space-x-3">
            <button
              type="button"
              onClick={() => setShowFiltersModal(false)}
              className="btn-secondary"
            >
              Cancel
            </button>
            <button
              onClick={handleClearFilters}
              className="btn-secondary"
            >
              Clear All
            </button>
            <button
              onClick={handleApplyFilters}
              className="btn-primary"
            >
              Apply Filters
            </button>
          </div>
        </div>
      </Modal>

      <Modal
        isOpen={showDetailsModal}
        onClose={() => setShowDetailsModal(false)}
        title="Audit Log Details"
        size="lg"
      >
        {selectedLog && (
          <div className="space-y-6">
            <div className="grid grid-cols-2 gap-4">
              <div>
                <label className="form-label">Timestamp</label>
                <p className="text-sm text-gray-900 dark:text-white">
                  {formatDate(selectedLog.created_at, 'MMM dd, yyyy HH:mm:ss')}
                </p>
              </div>
              <div>
                <label className="form-label">Action</label>
                <p className="text-sm font-medium text-gray-900 dark:text-white">
                  {selectedLog.action}
                </p>
              </div>
              <div>
                <label className="form-label">Resource</label>
                <span className="px-2 py-1 text-xs font-medium bg-gray-100 dark:bg-gray-700 rounded">
                  {selectedLog.resource}
                </span>
              </div>
              <div>
                <label className="form-label">Customer ID</label>
                <p className="text-sm font-mono text-gray-900 dark:text-white">
                  {selectedLog.customer_id || 'System'}
                </p>
              </div>
              <div>
                <label className="form-label">Resource ID</label>
                <p className="text-sm font-mono text-gray-900 dark:text-white">
                  {selectedLog.resource_id || 'N/A'}
                </p>
              </div>
              <div>
                <label className="form-label">IP Address</label>
                <p className="text-sm font-mono text-gray-900 dark:text-white">
                  {selectedLog.ip_address}
                </p>
              </div>
              <div className="col-span-2">
                <label className="form-label">User Agent</label>
                <p className="text-sm text-gray-900 dark:text-white break-all">
                  {selectedLog.user_agent}
                </p>
              </div>
            </div>

            <div>
              <label className="form-label">Details</label>
              <div className="bg-gray-50 dark:bg-gray-700 rounded-lg p-4">
                <pre className="text-sm text-gray-900 dark:text-white whitespace-pre-wrap">
                  {JSON.stringify(selectedLog.details, null, 2)}
                </pre>
              </div>
            </div>

            <div className="flex justify-end">
              <button
                onClick={() => setShowDetailsModal(false)}
                className="btn-secondary"
              >
                Close
              </button>
            </div>
          </div>
        )}
      </Modal>
    </div>
  );
};

export default AuditLogs;