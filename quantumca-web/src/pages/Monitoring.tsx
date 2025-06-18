import React from 'react';
import { useApi } from '../hooks/useApi';
import { apiService } from '../services/api';
import LoadingSpinner from '../components/LoadingSpinner';
import StatusBadge from '../components/StatusBadge';
import { formatRelativeTime, formatNumber } from '../utils/helpers';
import {
  ServerIcon,
  CircleStackIcon,
  ClockIcon,
  SignalIcon,
  ExclamationTriangleIcon,
} from '@heroicons/react/24/outline';
import { LineChart, Line, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer, BarChart, Bar } from 'recharts';

const Monitoring: React.FC = () => {
  const { data: healthData, loading: healthLoading } = useApi(() => apiService.getHealth());
  const { data: metricsData, loading: metricsLoading } = useApi(() => apiService.getHealthMetrics());
  const { data: versionData } = useApi(() => apiService.getVersion());

  const loading = healthLoading || metricsLoading;

  const performanceData = [
    { time: '00:00', responseTime: 45, requests: 120, errors: 2 },
    { time: '04:00', responseTime: 42, requests: 98, errors: 1 },
    { time: '08:00', responseTime: 55, requests: 180, errors: 5 },
    { time: '12:00', responseTime: 48, requests: 220, errors: 3 },
    { time: '16:00', responseTime: 52, requests: 195, errors: 4 },
    { time: '20:00', responseTime: 46, requests: 160, errors: 2 },
  ];

  const certificateStatsData = [
    { name: 'Active', value: metricsData?.active_certificates || 0 },
    { name: 'Total', value: metricsData?.active_certificates || 0 },
  ];

  if (loading) {
    return (
      <div className="flex items-center justify-center min-h-96">
        <LoadingSpinner size="lg" text="Loading monitoring data..." />
      </div>
    );
  }

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <h1 className="text-2xl font-bold text-gray-900 dark:text-white">System Monitoring</h1>
        <div className="flex items-center space-x-2">
          <StatusBadge status={healthData?.status || 'unknown'} />
          <span className="text-sm text-gray-500 dark:text-gray-400">
            Last updated: {formatRelativeTime(healthData?.timestamp || new Date())}
          </span>
        </div>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-4 gap-6">
        <div className="card">
          <div className="card-body">
            <div className="flex items-center justify-between">
              <div>
                <p className="text-sm font-medium text-gray-600 dark:text-gray-400">System Status</p>
                <p className="text-2xl font-bold text-gray-900 dark:text-white">
                  {healthData?.status || 'Unknown'}
                </p>
              </div>
              <ServerIcon className="h-8 w-8 text-blue-600" />
            </div>
          </div>
        </div>

        <div className="card">
          <div className="card-body">
            <div className="flex items-center justify-between">
              <div>
                <p className="text-sm font-medium text-gray-600 dark:text-gray-400">Uptime</p>
                <p className="text-2xl font-bold text-gray-900 dark:text-white">
                  {healthData?.uptime || '0h'}
                </p>
              </div>
              <ClockIcon className="h-8 w-8 text-green-600" />
            </div>
          </div>
        </div>

        <div className="card">
          <div className="card-body">
            <div className="flex items-center justify-between">
              <div>
                <p className="text-sm font-medium text-gray-600 dark:text-gray-400">Database Connections</p>
                <p className="text-2xl font-bold text-gray-900 dark:text-white">
                  {formatNumber(metricsData?.database_connections || 0)}
                </p>
              </div>
              <SignalIcon className="h-8 w-8 text-purple-600" />
            </div>
          </div>
        </div>

        <div className="card">
          <div className="card-body">
            <div className="flex items-center justify-between">
              <div>
                <p className="text-sm font-medium text-gray-600 dark:text-gray-400">Active Certificates</p>
                <p className="text-2xl font-bold text-gray-900 dark:text-white">
                  {formatNumber(metricsData?.active_certificates || 0)}
                </p>
              </div>
              <ExclamationTriangleIcon className="h-8 w-8 text-red-600" />
            </div>
          </div>
        </div>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        <div className="card">
          <div className="card-header">
            <h3 className="text-lg font-medium text-gray-900 dark:text-white">Service Status</h3>
          </div>
          <div className="card-body space-y-4">
            {healthData?.checks && Object.entries(healthData.checks).map(([service, status]) => (
              <div key={service} className="flex items-center justify-between p-3 bg-gray-50 dark:bg-gray-700 rounded-lg">
                <div className="flex items-center space-x-3">
                  <div className="p-2 bg-white dark:bg-gray-800 rounded-lg">
                    <CircleStackIcon className="h-5 w-5 text-gray-600 dark:text-gray-400" />
                  </div>
                  <div>
                    <p className="font-medium text-gray-900 dark:text-white capitalize">
                      {service.replace('_', ' ')}
                    </p>
                    <p className="text-sm text-gray-600 dark:text-gray-400">
                      Service component
                    </p>
                  </div>
                </div>
                <StatusBadge status={status === 'healthy' ? 'up' : 'down'} />
              </div>
            ))}
          </div>
        </div>

        <div className="card">
          <div className="card-header">
            <h3 className="text-lg font-medium text-gray-900 dark:text-white">Performance Metrics</h3>
          </div>
          <div className="card-body">
            <ResponsiveContainer width="100%" height={300}>
              <LineChart data={performanceData}>
                <CartesianGrid strokeDasharray="3 3" />
                <XAxis dataKey="time" />
                <YAxis />
                <Tooltip />
                <Line 
                  type="monotone" 
                  dataKey="responseTime" 
                  stroke="#0ea5e9" 
                  strokeWidth={2}
                  name="Response Time (ms)"
                />
                <Line 
                  type="monotone" 
                  dataKey="requests" 
                  stroke="#22c55e" 
                  strokeWidth={2}
                  name="Requests/min"
                />
              </LineChart>
            </ResponsiveContainer>
          </div>
        </div>
      </div>

      <div className="card">
        <div className="card-header">
          <h3 className="text-lg font-medium text-gray-900 dark:text-white">System Information</h3>
        </div>
        <div className="card-body">
          <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
            <div>
              <h4 className="font-medium text-gray-900 dark:text-white mb-3">Version Information</h4>
              <div className="space-y-2 text-sm">
                <div className="flex justify-between">
                  <span className="text-gray-600 dark:text-gray-400">Version:</span>
                  <span className="font-mono">{healthData?.version || versionData?.version || 'N/A'}</span>
                </div>
                <div className="flex justify-between">
                  <span className="text-gray-600 dark:text-gray-400">Build:</span>
                  <span className="font-mono">{versionData?.gitCommit?.slice(0, 8) || 'N/A'}</span>
                </div>
                <div className="flex justify-between">
                  <span className="text-gray-600 dark:text-gray-400">Environment:</span>
                  <span className="font-mono">{versionData?.environment || 'N/A'}</span>
                </div>
              </div>
            </div>

            <div>
              <h4 className="font-medium text-gray-900 dark:text-white mb-3">Database Status</h4>
              <div className="space-y-2 text-sm">
                <div className="flex justify-between">
                  <span className="text-gray-600 dark:text-gray-400">Status:</span>
                  <StatusBadge status={healthData?.checks?.database === 'healthy' ? 'up' : 'down'} size="sm" />
                </div>
                <div className="flex justify-between">
                  <span className="text-gray-600 dark:text-gray-400">Connections:</span>
                  <span>{metricsData?.database_connections || 0}</span>
                </div>
                <div className="flex justify-between">
                  <span className="text-gray-600 dark:text-gray-400">Query Status:</span>
                  <StatusBadge status={healthData?.checks?.database_query === 'healthy' ? 'up' : 'down'} size="sm" />
                </div>
              </div>
            </div>

            <div>
              <h4 className="font-medium text-gray-900 dark:text-white mb-3">Resource Stats</h4>
              <div className="space-y-2 text-sm">
                <div className="flex justify-between">
                  <span className="text-gray-600 dark:text-gray-400">Total Certificates:</span>
                  <span>{formatNumber(metricsData?.active_certificates || 0)}</span>
                </div>
                <div className="flex justify-between">
                  <span className="text-gray-600 dark:text-gray-400">Total Customers:</span>
                  <span>{formatNumber(metricsData?.total_customers || 0)}</span>
                </div>
                <div className="flex justify-between">
                  <span className="text-gray-600 dark:text-gray-400">Timestamp:</span>
                  <span className="font-mono text-xs">{metricsData?.timestamp ? formatRelativeTime(metricsData.timestamp) : 'N/A'}</span>
                </div>
              </div>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
};

export default Monitoring;