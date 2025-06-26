import React, { useState } from 'react';
import { useApi } from '../hooks/useApi';
import { apiService } from '../services/api';
import { CertificateTemplate } from '../types/api';
import StatusBadge from '../components/StatusBadge';
import Modal from '../components/Modal';
import LoadingSpinner from '../components/LoadingSpinner';
import { DocumentTextIcon } from '@heroicons/react/24/outline';

const Templates: React.FC = () => {
  const [showDetailsModal, setShowDetailsModal] = useState(false);
  const [selectedTemplate, setSelectedTemplate] = useState<CertificateTemplate | null>(null);

  const { data: templatesData, loading } = useApi(() => apiService.getTemplates());

  if (loading) {
    return (
      <div className="flex items-center justify-center min-h-96">
        <LoadingSpinner size="lg" text="Loading templates..." />
      </div>
    );
  }

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <h1 className="text-2xl font-bold text-gray-900 dark:text-white">Certificate Templates</h1>
        <div className="flex items-center space-x-2">
          <DocumentTextIcon className="w-5 h-5 text-gray-400" />
          <span className="text-sm text-gray-600 dark:text-gray-400">
            {(templatesData || []).length} templates available
          </span>
        </div>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
        {(templatesData || []).map((template) => (
          <div
            key={template.id}
            className="card cursor-pointer hover:shadow-lg transition-shadow duration-200"
            onClick={() => {
              setSelectedTemplate(template);
              setShowDetailsModal(true);
            }}
          >
            <div className="card-body">
              <div className="flex items-start justify-between">
                <div className="flex-1">
                  <h3 className="text-lg font-medium text-gray-900 dark:text-white mb-2">
                    {template.name}
                  </h3>
                  <p className="text-sm text-gray-600 dark:text-gray-400 mb-4">
                    {template.description}
                  </p>
                </div>
                <StatusBadge 
                  status={template.status} 
                  variant={template.status === 'active' ? 'success' : 'default'}
                  size="sm" 
                />
              </div>
              
              <div className="space-y-2">
                <div className="flex justify-between text-sm">
                  <span className="text-gray-500 dark:text-gray-400">Key Usage:</span>
                  <span className="font-medium text-right">
                    {template.key_usages.length > 0 ? template.key_usages.join(', ') : 'None'}
                  </span>
                </div>
                <div className="flex justify-between text-sm">
                  <span className="text-gray-500 dark:text-gray-400">Max Validity:</span>
                  <span className="font-medium">{template.max_validity_days} days</span>
                </div>
                <div className="flex justify-between text-sm">
                  <span className="text-gray-500 dark:text-gray-400">Is CA:</span>
                  <span className="font-medium">{template.is_ca ? 'Yes' : 'No'}</span>
                </div>
              </div>
            </div>
          </div>
        ))}
      </div>

      {!loading && (!templatesData || templatesData.length === 0) && (
        <div className="text-center py-12">
          <DocumentTextIcon className="mx-auto h-12 w-12 text-gray-400" />
          <h3 className="mt-2 text-sm font-medium text-gray-900 dark:text-white">No templates</h3>
          <p className="mt-1 text-sm text-gray-500 dark:text-gray-400">
            No certificate templates are currently available.
          </p>
        </div>
      )}

      <Modal
        isOpen={showDetailsModal}
        onClose={() => setShowDetailsModal(false)}
        title="Template Details"
        size="lg"
      >
        {selectedTemplate && (
          <div className="space-y-6">
            <div className="grid grid-cols-2 gap-4">
              <div>
                <label className="form-label">Name</label>
                <p className="text-sm text-gray-900 dark:text-white">{selectedTemplate.name}</p>
              </div>
              <div>
                <label className="form-label">Status</label>
                <StatusBadge 
                  status={selectedTemplate.status}
                  variant={selectedTemplate.status === 'active' ? 'success' : 'default'}
                />
              </div>
              <div className="col-span-2">
                <label className="form-label">Description</label>
                <p className="text-sm text-gray-900 dark:text-white">
                  {selectedTemplate.description || 'No description provided'}
                </p>
              </div>
              <div>
                <label className="form-label">Validity Period</label>
                <p className="text-sm text-gray-900 dark:text-white">{selectedTemplate.validity_days} days</p>
              </div>
              <div>
                <label className="form-label">Max Validity</label>
                <p className="text-sm text-gray-900 dark:text-white">{selectedTemplate.max_validity_days} days</p>
              </div>
              <div>
                <label className="form-label">Is CA</label>
                <p className="text-sm text-gray-900 dark:text-white">{selectedTemplate.is_ca ? 'Yes' : 'No'}</p>
              </div>
              {selectedTemplate.path_length !== undefined && selectedTemplate.path_length !== null && (
                <div>
                  <label className="form-label">Path Length</label>
                  <p className="text-sm text-gray-900 dark:text-white">{selectedTemplate.path_length}</p>
                </div>
              )}
              <div className="col-span-2">
                <label className="form-label">Key Usages</label>
                <p className="text-sm text-gray-900 dark:text-white">
                  {selectedTemplate.key_usages.length > 0 ? selectedTemplate.key_usages.join(', ') : 'None specified'}
                </p>
              </div>
              <div className="col-span-2">
                <label className="form-label">Extended Key Usages</label>
                <p className="text-sm text-gray-900 dark:text-white">
                  {selectedTemplate.ext_key_usages.length > 0 ? selectedTemplate.ext_key_usages.join(', ') : 'None specified'}
                </p>
              </div>
              {selectedTemplate.policies && Object.keys(selectedTemplate.policies).length > 0 && (
                <div className="col-span-2">
                  <label className="form-label">Policies</label>
                  <div className="bg-gray-50 dark:bg-gray-700 rounded-lg p-3">
                    <pre className="text-sm text-gray-900 dark:text-white whitespace-pre-wrap">
                      {JSON.stringify(selectedTemplate.policies, null, 2)}
                    </pre>
                  </div>
                </div>
              )}
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

export default Templates;