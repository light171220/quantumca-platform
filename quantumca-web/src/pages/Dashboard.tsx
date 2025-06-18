import React from 'react';
import { useApi } from '../hooks/useApi';
import { apiService } from '../services/api';
import LoadingSpinner from '../components/LoadingSpinner';
import StatusBadge from '../components/StatusBadge';
import { formatNumber, formatRelativeTime } from '../utils/helpers';
import {
  DocumentTextIcon,
  UsersIcon,
  CheckCircleIcon,
  ClockIcon,
} from '@heroicons/react/24/outline';
import { LineChart, Line, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer } from 'recharts';

const Dashboard: React.FC = () => {
  const { data: healthData, loading: healthLoading, error: healthError } = useApi(() => apiService.getHealth());
  const { data: metricsData, loading: metricsLoading, error: metricsError } = useApi(() => apiService.getHealthMetrics());
  const { data: certificatesData, loading: certLoading, error: certError } = useApi(() => 
    apiService.getCertificates({ page_size: 5 })
  );

  const loading = healthLoading || metricsLoading || certLoading;

  const dashboardCards = [
    {
      title: 'Active Certificates',
      value: metricsData?.active_certificates || 0,
      icon: DocumentTextIcon,
      color: 'text-blue-600',
      bgColor: 'bg-blue-100',
    },
    {
      title: 'Total Customers',
      value: metricsData?.total_customers || 0,
      icon: UsersIcon,
      color: 'text-green-600',
      bgColor: 'bg-green-100',
    },
    {
      title: 'Database Connections',
      value: metricsData?.database_connections || 0,
      icon: CheckCircleIcon,
      color: 'text-purple-600',
      bgColor: 'bg-purple-100',
    },
    {
      title: 'System Status',
      value: healthData?.status || 'Unknown',
      icon: ClockIcon,
      color: 'text-indigo-600',
      bgColor: 'bg-indigo-100',
    },
  ];

  const chartData = [
    { name: 'Jan', certificates: 120, domains: 85 },
    { name: 'Feb', certificates: 135, domains: 92 },
    { name: 'Mar', certificates: 148, domains: 98 },
    { name: 'Apr', certificates: 162, domains: 105 },
    { name: 'May', certificates: 175, domains: 112 },
    { name: 'Jun', certificates: 188, domains: 118 },
  ];

  if (loading) {
    return (
      <div className="flex items-center justify-center min-h-96">
        <LoadingSpinner size="lg" text="Loading dashboard..." />
      </div>
    );
  }

  if (healthError || metricsError || certError) {
    return (
      <div className="flex items-center justify-center min-h-96">
        <div className="text-center">
          <h2 className="text-xl font-semibold text-gray-900 dark:text-white mb-2">Error Loading Dashboard</h2>
          <p className="text-gray-600 dark:text-gray-400">
            {healthError || metricsError || certError}
          </p>
          <button 
            onClick={() => window.location.reload()} 
            className="mt-4 btn-primary"
          >
            Retry
          </button>
        </div>
      </div>
    );
  }

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <h1 className="text-2xl font-bold text-gray-900 dark:text-white">Dashboard</h1>
        <div className="flex items-center space-x-2">
          <StatusBadge status={healthData?.status || 'unknown'} />
          <span className="text-sm text-gray-500 dark:text-gray-400">
            Last updated: {formatRelativeTime(healthData?.timestamp || new Date())}
          </span>
        </div>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6">
        {dashboardCards.map((card, index) => (
          <div key={index} className="card">
            <div className="card-body">
              <div className="flex items-center">
                <div className={`p-3 rounded-lg ${card.bgColor} dark:bg-gray-700`}>
                  <card.icon className={`h-6 w-6 ${card.color} dark:text-gray-300`} />
                </div>
                <div className="ml-4">
                  <p className="text-sm font-medium text-gray-600 dark:text-gray-400">
                    {card.title}
                  </p>
                  <p className="text-2xl font-bold text-gray-900 dark:text-white">
                    {typeof card.value === 'number' ? formatNumber(card.value) : card.value}
                  </p>
                </div>
              </div>
            </div>
          </div>
        ))}
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        <div className="card">
          <div className="card-header">
            <h3 className="text-lg font-medium text-gray-900 dark:text-white">
              Certificate Growth
            </h3>
          </div>
          <div className="card-body">
            <ResponsiveContainer width="100%" height={300}>
              <LineChart data={chartData}>
                <CartesianGrid strokeDasharray="3 3" />
                <XAxis dataKey="name" />
                <YAxis />
                <Tooltip />
                <Line 
                  type="monotone" 
                  dataKey="certificates" 
                  stroke="#0ea5e9" 
                  strokeWidth={2}
                  name="Certificates"
                />
                <Line 
                  type="monotone" 
                  dataKey="domains" 
                  stroke="#22c55e" 
                  strokeWidth={2}
                  name="Domains"
                />
              </LineChart>
            </ResponsiveContainer>
          </div>
        </div>

        <div className="card">
          <div className="card-header">
            <h3 className="text-lg font-medium text-gray-900 dark:text-white">
              System Status
            </h3>
          </div>
          <div className="card-body space-y-4">
            {healthData?.checks && Object.entries(healthData.checks).map(([service, status]) => (
              <div key={service} className="flex items-center justify-between">
                <span className="text-sm font-medium text-gray-700 dark:text-gray-300 capitalize">
                  {service.replace('_', ' ')}
                </span>
                <StatusBadge status={status === 'healthy' ? 'up' : 'down'} />
              </div>
            ))}
            
            {healthData?.uptime && (
              <div className="mt-6 space-y-3">
                <div className="flex justify-between text-sm">
                  <span className="text-gray-600 dark:text-gray-400">Uptime</span>
                  <span className="font-medium">{healthData.uptime}</span>
                </div>
                <div className="flex justify-between text-sm">
                  <span className="text-gray-600 dark:text-gray-400">Version</span>
                  <span className="font-medium">{healthData.version || 'Unknown'}</span>
                </div>
              </div>
            )}
          </div>
        </div>
      </div>

      <div className="card">
        <div className="card-header">
          <h3 className="text-lg font-medium text-gray-900 dark:text-white">
            Recent Certificates
          </h3>
        </div>
        <div className="card-body">
          {certificatesData?.data && certificatesData.data.length > 0 ? (
            <div className="space-y-3">
              {certificatesData.data.map((cert) => (
                <div key={cert.id} className="flex items-center justify-between p-3 bg-gray-50 dark:bg-gray-700 rounded-lg">
                  <div>
                    <p className="font-medium text-gray-900 dark:text-white">
                      {cert.common_name}
                    </p>
                    <p className="text-sm text-gray-600 dark:text-gray-400">
                      Valid until: {new Date(cert.not_after).toLocaleDateString()}
                    </p>
                  </div>
                  <StatusBadge status={cert.status} />
                </div>
              ))}
            </div>
          ) : (
            <div className="text-center py-8">
              <DocumentTextIcon className="mx-auto h-12 w-12 text-gray-400" />
              <h3 className="mt-2 text-sm font-medium text-gray-900 dark:text-white">No certificates</h3>
              <p className="mt-1 text-sm text-gray-500 dark:text-gray-400">
                No certificates have been issued yet.
              </p>
            </div>
          )}
        </div>
      </div>
    </div>
  );
};

export default Dashboard;