import React, { useState } from 'react';
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
  ShieldCheckIcon,
  DocumentTextIcon,
  ChartBarIcon,
} from '@heroicons/react/24/outline';
import { LineChart, Line, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer, PieChart, Pie, Cell } from 'recharts';

const Monitoring: React.FC = () => {
  const [activeTab, setActiveTab] = useState<'overview' | 'analytics' | 'ocsp' | 'performance'>('overview');
  
  const { data: healthData, loading: healthLoading } = useApi(() => apiService.getHealth());
  const { data: metricsData, loading: metricsLoading } = useApi(() => apiService.getHealthMetrics());
  const { data: versionData } = useApi(() => apiService.getVersion());
  const { data: analyticsData } = useApi(() => apiService.getAnalyticsDashboard());
  const { data: ocspHealth } = useApi(() => apiService.getOCSPHealth());
  const { data: ocspStats } = useApi(() => apiService.getOCSPStats());
  const { data: crlInfo } = useApi(() => apiService.getCRLInfo());
  const { data: algorithmUsage } = useApi(() => apiService.getAlgorithmUsage());
  const { data: revocationStats } = useApi(() => apiService.getRevocationStats());

  const loading = healthLoading || metricsLoading;

  const performanceData = [
    { time: '00:00', responseTime: 45, requests: 120, errors: 2 },
    { time: '04:00', responseTime: 42, requests: 98, errors: 1 },
    { time: '08:00', responseTime: 55, requests: 180, errors: 5 },
    { time: '12:00', responseTime: 48, requests: 220, errors: 3 },
    { time: '16:00', responseTime: 52, requests: 195, errors: 4 },
    { time: '20:00', responseTime: 46, requests: 160, errors: 2 },
  ];

  const COLORS = ['#0ea5e9', '#22c55e', '#f59e0b', '#ef4444', '#8b5cf6'];

  const tabs = [
    { id: 'overview', label: 'System Overview', icon: ServerIcon },
    { id: 'analytics', label: 'Analytics', icon: ChartBarIcon },
    { id: 'ocsp', label: 'OCSP & CRL', icon: ShieldCheckIcon },
    { id: 'performance', label: 'Performance', icon: SignalIcon },
  ];

  if (loading) {
    return (
      <div className="flex items-center justify-center min-h-96">
        <LoadingSpinner size="lg" text="Loading monitoring data..." />
      </div>
    );
  }

  const renderOverview = () => (
    <div className="space-y-6">
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
                <p className="text-sm font-medium text-gray-600 dark:text-gray-400">DB Connections</p>
                <p className="text-2xl font-bold text-gray-900 dark:text-white">
                  {formatNumber(metricsData?.database_connections || 0)}
                </p>
              </div>
              <CircleStackIcon className="h-8 w-8 text-purple-600" />
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
              <DocumentTextIcon className="h-8 w-8 text-indigo-600" />
            </div>
          </div>
        </div>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        <div className="card">
          <div className="card-header">
            <h3 className="text-lg font-medium text-gray-900 dark:text-white">Service Health</h3>
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
                      Core service component
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
            <h3 className="text-lg font-medium text-gray-900 dark:text-white">System Information</h3>
          </div>
          <div className="card-body">
            <div className="space-y-4">
              <div>
                <h4 className="font-medium text-gray-900 dark:text-white mb-3">Version Information</h4>
                <div className="space-y-2 text-sm">
                  <div className="flex justify-between">
                    <span className="text-gray-600 dark:text-gray-400">Version:</span>
                    <span className="font-mono">{healthData?.version || versionData?.version || 'N/A'}</span>
                  </div>
                  <div className="flex justify-between">
                    <span className="text-gray-600 dark:text-gray-400">Build:</span>
                    <span className="font-mono">{versionData?.commit?.slice(0, 8) || 'N/A'}</span>
                  </div>
                  <div className="flex justify-between">
                    <span className="text-gray-600 dark:text-gray-400">Service:</span>
                    <span className="font-mono">{versionData?.service || 'quantumca-platform'}</span>
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
                    <span className="text-gray-600 dark:text-gray-400">Last Update:</span>
                    <span className="font-mono text-xs">
                      {metricsData?.timestamp ? formatRelativeTime(metricsData.timestamp) : 'N/A'}
                    </span>
                  </div>
                </div>
              </div>
            </div>
          </div>
        </div>
      </div>
    </div>
  );

  const renderAnalytics = () => (
    <div className="space-y-6">
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        <div className="card">
          <div className="card-header">
            <h3 className="text-lg font-medium text-gray-900 dark:text-white">Algorithm Usage</h3>
          </div>
          <div className="card-body">
            {algorithmUsage?.algorithm_usage && algorithmUsage.algorithm_usage.length > 0 ? (
              <ResponsiveContainer width="100%" height={300}>
                <PieChart>
                  <Pie
                    data={algorithmUsage.algorithm_usage}
                    cx="50%"
                    cy="50%"
                    labelLine={false}
                    label={({ algorithm, percentage }) => `${algorithm} ${percentage.toFixed(1)}%`}
                    outerRadius={80}
                    fill="#8884d8"
                    dataKey="count"
                  >
                    {algorithmUsage.algorithm_usage.map((entry: any, index: number) => (
                      <Cell key={`cell-${index}`} fill={COLORS[index % COLORS.length]} />
                    ))}
                  </Pie>
                  <Tooltip />
                </PieChart>
              </ResponsiveContainer>
            ) : (
              <div className="flex items-center justify-center h-64 text-gray-500">
                No algorithm usage data available
              </div>
            )}
          </div>
        </div>

        <div className="card">
          <div className="card-header">
            <h3 className="text-lg font-medium text-gray-900 dark:text-white">Revocation Statistics</h3>
          </div>
          <div className="card-body">
            {revocationStats?.overview ? (
              <div className="space-y-4">
                <div className="grid grid-cols-2 gap-4">
                  <div className="text-center">
                    <p className="text-2xl font-bold text-red-600">{revocationStats.overview.total_revoked}</p>
                    <p className="text-sm text-gray-600 dark:text-gray-400">Total Revoked</p>
                  </div>
                  <div className="text-center">
                    <p className="text-2xl font-bold text-yellow-600">{revocationStats.overview.revoked_last_30_days}</p>
                    <p className="text-sm text-gray-600 dark:text-gray-400">Last 30 Days</p>
                  </div>
                </div>
                <div className="text-center">
                  <p className="text-lg font-semibold">{revocationStats.overview.revocation_rate.toFixed(2)}%</p>
                  <p className="text-sm text-gray-600 dark:text-gray-400">Revocation Rate</p>
                </div>
              </div>
            ) : (
              <div className="flex items-center justify-center h-64 text-gray-500">
                No revocation data available
              </div>
            )}
          </div>
        </div>
      </div>

      {analyticsData?.expiration_trends && (
        <div className="card">
          <div className="card-header">
            <h3 className="text-lg font-medium text-gray-900 dark:text-white">Certificate Expiration Trends</h3>
          </div>
          <div className="card-body">
            <ResponsiveContainer width="100%" height={300}>
              <LineChart data={analyticsData.expiration_trends}>
                <CartesianGrid strokeDasharray="3 3" />
                <XAxis dataKey="date" />
                <YAxis />
                <Tooltip />
                <Line 
                  type="monotone" 
                  dataKey="count" 
                  stroke="#0ea5e9" 
                  strokeWidth={2}
                  name="Expiring Certificates"
                />
              </LineChart>
            </ResponsiveContainer>
          </div>
        </div>
      )}
    </div>
  );

  const renderOCSP = () => (
    <div className="space-y-6">
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        <div className="card">
          <div className="card-header">
            <h3 className="text-lg font-medium text-gray-900 dark:text-white">OCSP Responder Status</h3>
          </div>
          <div className="card-body">
            {ocspHealth ? (
              <div className="space-y-4">
                <div className="flex items-center justify-between">
                  <span className="text-sm font-medium">Status</span>
                  <StatusBadge status={ocspHealth.status} />
                </div>
                <div className="flex items-center justify-between">
                  <span className="text-sm font-medium">Uptime</span>
                  <span className="text-sm">{ocspHealth.uptime}</span>
                </div>
                <div className="flex items-center justify-between">
                  <span className="text-sm font-medium">Version</span>
                  <span className="text-sm font-mono">{ocspHealth.version}</span>
                </div>
                {ocspHealth.requests && (
                  <div className="space-y-2">
                    <h4 className="font-medium">Request Statistics</h4>
                    <div className="grid grid-cols-2 gap-4 text-sm">
                      <div>
                        <span className="text-gray-600">Total:</span>
                        <span className="ml-2 font-medium">{formatNumber(ocspHealth.requests.total)}</span>
                      </div>
                      <div>
                        <span className="text-gray-600">Success Rate:</span>
                        <span className="ml-2 font-medium">{ocspHealth.requests.success_rate}%</span>
                      </div>
                    </div>
                  </div>
                )}
              </div>
            ) : (
              <div className="flex items-center justify-center h-32 text-gray-500">
                OCSP data not available
              </div>
            )}
          </div>
        </div>

        <div className="card">
          <div className="card-header">
            <h3 className="text-lg font-medium text-gray-900 dark:text-white">CRL Information</h3>
          </div>
          <div className="card-body">
            {crlInfo ? (
              <div className="space-y-3">
                <div className="flex justify-between">
                  <span className="text-sm text-gray-600">Version:</span>
                  <span className="text-sm font-medium">{crlInfo.version}</span>
                </div>
                <div className="flex justify-between">
                  <span className="text-sm text-gray-600">Issuer:</span>
                  <span className="text-sm font-medium">{crlInfo.issuer}</span>
                </div>
                <div className="flex justify-between">
                  <span className="text-sm text-gray-600">Entries:</span>
                  <span className="text-sm font-medium">{crlInfo.entry_count}</span>
                </div>
                <div className="flex justify-between">
                  <span className="text-sm text-gray-600">Size:</span>
                  <span className="text-sm font-medium">{(crlInfo.size_bytes / 1024).toFixed(1)} KB</span>
                </div>
                <div className="flex justify-between">
                  <span className="text-sm text-gray-600">Next Update:</span>
                  <span className="text-sm font-medium">{formatRelativeTime(crlInfo.next_update)}</span>
                </div>
              </div>
            ) : (
              <div className="flex items-center justify-center h-32 text-gray-500">
                CRL data not available
              </div>
            )}
          </div>
        </div>
      </div>

      {ocspStats && (
        <div className="card">
          <div className="card-header">
            <h3 className="text-lg font-medium text-gray-900 dark:text-white">OCSP Response Statistics</h3>
          </div>
          <div className="card-body">
            <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
              <div className="text-center">
                <p className="text-2xl font-bold text-green-600">{ocspStats.responses?.good || 0}</p>
                <p className="text-sm text-gray-600 dark:text-gray-400">Good Responses</p>
              </div>
              <div className="text-center">
                <p className="text-2xl font-bold text-red-600">{ocspStats.responses?.revoked || 0}</p>
                <p className="text-sm text-gray-600 dark:text-gray-400">Revoked</p>
              </div>
              <div className="text-center">
                <p className="text-2xl font-bold text-yellow-600">{ocspStats.responses?.unknown || 0}</p>
                <p className="text-sm text-gray-600 dark:text-gray-400">Unknown</p>
              </div>
            </div>
          </div>
        </div>
      )}
    </div>
  );

  const renderPerformance = () => (
    <div className="space-y-6">
      <div className="card">
        <div className="card-header">
          <h3 className="text-lg font-medium text-gray-900 dark:text-white">Performance Metrics</h3>
        </div>
        <div className="card-body">
          <ResponsiveContainer width="100%" height={300}>
            <LineChart data={performanceData}>
              <CartesianGrid strokeDasharray="3 3" />
              <XAxis dataKey="time" />
              <YAxis yAxisId="left" />
              <YAxis yAxisId="right" orientation="right" />
              <Tooltip />
              <Line 
                yAxisId="left"
                type="monotone" 
                dataKey="responseTime" 
                stroke="#0ea5e9" 
                strokeWidth={2}
                name="Response Time (ms)"
              />
              <Line 
                yAxisId="right"
                type="monotone" 
                dataKey="requests" 
                stroke="#22c55e" 
                strokeWidth={2}
                name="Requests/min"
              />
              <Line 
                yAxisId="right"
                type="monotone" 
                dataKey="errors" 
                stroke="#ef4444" 
                strokeWidth={2}
                name="Errors/min"
              />
            </LineChart>
          </ResponsiveContainer>
        </div>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
        <div className="card">
          <div className="card-body text-center">
            <SignalIcon className="h-8 w-8 text-blue-600 mx-auto mb-2" />
            <p className="text-2xl font-bold">45ms</p>
            <p className="text-sm text-gray-600 dark:text-gray-400">Avg Response Time</p>
          </div>
        </div>
        <div className="card">
          <div className="card-body text-center">
            <ExclamationTriangleIcon className="h-8 w-8 text-green-600 mx-auto mb-2" />
            <p className="text-2xl font-bold">99.9%</p>
            <p className="text-sm text-gray-600 dark:text-gray-400">Uptime</p>
          </div>
        </div>
        <div className="card">
          <div className="card-body text-center">
            <DocumentTextIcon className="h-8 w-8 text-purple-600 mx-auto mb-2" />
            <p className="text-2xl font-bold">0.1%</p>
            <p className="text-sm text-gray-600 dark:text-gray-400">Error Rate</p>
          </div>
        </div>
      </div>
    </div>
  );

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold text-gray-900 dark:text-white">System Monitoring</h1>
          <p className="text-sm text-gray-600 dark:text-gray-400 mt-1">
            Monitor system health, performance, and certificate operations
          </p>
        </div>
        <div className="flex items-center space-x-2">
          <StatusBadge status={healthData?.status || 'unknown'} />
          <span className="text-sm text-gray-500 dark:text-gray-400">
            Last updated: {formatRelativeTime(healthData?.timestamp || new Date())}
          </span>
        </div>
      </div>

      <div className="border-b border-gray-200 dark:border-gray-700">
        <nav className="-mb-px flex space-x-8">
          {tabs.map((tab) => (
            <button
              key={tab.id}
              onClick={() => setActiveTab(tab.id as any)}
              className={`flex items-center py-2 px-1 border-b-2 font-medium text-sm ${
                activeTab === tab.id
                  ? 'border-quantum-500 text-quantum-600 dark:text-quantum-400'
                  : 'border-transparent text-gray-500 hover:text-gray-700 hover:border-gray-300 dark:text-gray-400 dark:hover:text-gray-300'
              }`}
            >
              <tab.icon className="h-5 w-5 mr-2" />
              {tab.label}
            </button>
          ))}
        </nav>
      </div>

      <div className="mt-6">
        {activeTab === 'overview' && renderOverview()}
        {activeTab === 'analytics' && renderAnalytics()}
        {activeTab === 'ocsp' && renderOCSP()}
        {activeTab === 'performance' && renderPerformance()}
      </div>
    </div>
  );
};

export default Monitoring;