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
  BuildingLibraryIcon,
  GlobeAltIcon,
  ExclamationTriangleIcon,
  ShieldCheckIcon,
} from '@heroicons/react/24/outline';
import { LineChart, Line, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer, PieChart, Pie, Cell } from 'recharts';

const Dashboard: React.FC = () => {
  const { data: healthData, loading: healthLoading } = useApi(() => apiService.getHealth());
  const { data: metricsData, loading: metricsLoading } = useApi(() => apiService.getHealthMetrics());
  const { data: analyticsData, loading: analyticsLoading } = useApi(() => apiService.getAnalyticsDashboard());
  const { data: expiringCerts } = useApi(() => apiService.getExpiringCertificates(30));

  const loading = healthLoading || metricsLoading || analyticsLoading;

  const dashboardCards = [
    {
      title: 'Active Certificates',
      value: analyticsData?.summary?.active_certificates || metricsData?.active_certificates || 0,
      icon: DocumentTextIcon,
      color: 'text-blue-600',
      bgColor: 'bg-blue-100',
      change: analyticsData?.summary?.certificates_issued_24h || 0,
    },
    {
      title: 'Total Customers',
      value: analyticsData?.summary?.total_customers || metricsData?.total_customers || 0,
      icon: UsersIcon,
      color: 'text-green-600',
      bgColor: 'bg-green-100',
    },
    {
      title: 'Expiring Soon',
      value: analyticsData?.summary?.expiring_soon || 0,
      icon: ExclamationTriangleIcon,
      color: 'text-yellow-600',
      bgColor: 'bg-yellow-100',
    },
    {
      title: 'Intermediate CAs',
      value: analyticsData?.summary?.intermediate_cas || 0,
      icon: BuildingLibraryIcon,
      color: 'text-purple-600',
      bgColor: 'bg-purple-100',
    },
    {
      title: 'Verified Domains',
      value: analyticsData?.summary?.domains_validated || 0,
      icon: GlobeAltIcon,
      color: 'text-indigo-600',
      bgColor: 'bg-indigo-100',
    },
    {
      title: 'System Status',
      value: healthData?.status || 'Unknown',
      icon: ShieldCheckIcon,
      color: 'text-emerald-600',
      bgColor: 'bg-emerald-100',
    },
  ];

  const certificateStatusData = analyticsData?.certificates_by_status ? 
    Object.entries(analyticsData.certificates_by_status).map(([status, count]) => ({
      name: status.charAt(0).toUpperCase() + status.slice(1),
      value: count,
    })) : [];

  const COLORS = ['#0ea5e9', '#22c55e', '#f59e0b', '#ef4444', '#8b5cf6'];

  if (loading) {
    return (
      <div className="flex items-center justify-center min-h-96">
        <LoadingSpinner size="lg" text="Loading dashboard..." />
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

      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
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
                  {card.change !== undefined && card.change > 0 && (
                    <p className="text-sm text-green-600 dark:text-green-400">
                      +{card.change} today
                    </p>
                  )}
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
              Certificate Expiration Trends
            </h3>
          </div>
          <div className="card-body">
            {analyticsData?.expiration_trends && analyticsData.expiration_trends.length > 0 ? (
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
            ) : (
              <div className="flex items-center justify-center h-64 text-gray-500">
                No expiration data available
              </div>
            )}
          </div>
        </div>

        <div className="card">
          <div className="card-header">
            <h3 className="text-lg font-medium text-gray-900 dark:text-white">
              Certificate Status Distribution
            </h3>
          </div>
          <div className="card-body">
            {certificateStatusData.length > 0 ? (
              <ResponsiveContainer width="100%" height={300}>
                <PieChart>
                  <Pie
                    data={certificateStatusData}
                    cx="50%"
                    cy="50%"
                    labelLine={false}
                    label={({ name, percent }) => `${name} ${(percent * 100).toFixed(0)}%`}
                    outerRadius={80}
                    fill="#8884d8"
                    dataKey="value"
                  >
                    {certificateStatusData.map((entry, index) => (
                      <Cell key={`cell-${index}`} fill={COLORS[index % COLORS.length]} />
                    ))}
                  </Pie>
                  <Tooltip />
                </PieChart>
              </ResponsiveContainer>
            ) : (
              <div className="flex items-center justify-center h-64 text-gray-500">
                No certificate data available
              </div>
            )}
          </div>
        </div>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        <div className="card">
          <div className="card-header">
            <h3 className="text-lg font-medium text-gray-900 dark:text-white">
              System Health
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
                <div className="flex justify-between text-sm">
                  <span className="text-gray-600 dark:text-gray-400">Database Connections</span>
                  <span className="font-medium">{metricsData?.database_connections || 0}</span>
                </div>
              </div>
            )}
          </div>
        </div>

        <div className="card">
          <div className="card-header">
            <h3 className="text-lg font-medium text-gray-900 dark:text-white">
              Certificates Expiring Soon
            </h3>
          </div>
          <div className="card-body">
            {expiringCerts?.certificates && expiringCerts.certificates.length > 0 ? (
              <div className="space-y-3">
                {expiringCerts.certificates.slice(0, 5).map((cert: any) => (
                  <div key={cert.id} className="flex items-center justify-between p-3 bg-gray-50 dark:bg-gray-700 rounded-lg">
                    <div>
                      <p className="font-medium text-gray-900 dark:text-white">
                        {cert.common_name}
                      </p>
                      <p className="text-sm text-gray-600 dark:text-gray-400">
                        Expires in {cert.days_left} days
                      </p>
                    </div>
                    <StatusBadge 
                      status={cert.days_left <= 7 ? 'critical' : cert.days_left <= 30 ? 'warning' : 'good'} 
                    />
                  </div>
                ))}
                {expiringCerts.total > 5 && (
                  <div className="text-center text-sm text-gray-500 dark:text-gray-400">
                    And {expiringCerts.total - 5} more certificates expiring soon
                  </div>
                )}
              </div>
            ) : (
              <div className="text-center py-8">
                <CheckCircleIcon className="mx-auto h-12 w-12 text-green-400" />
                <h3 className="mt-2 text-sm font-medium text-gray-900 dark:text-white">No certificates expiring soon</h3>
                <p className="mt-1 text-sm text-gray-500 dark:text-gray-400">
                  All certificates are valid for more than 30 days.
                </p>
              </div>
            )}
          </div>
        </div>
      </div>

      {analyticsData?.recent_activity && analyticsData.recent_activity.length > 0 && (
        <div className="card">
          <div className="card-header">
            <h3 className="text-lg font-medium text-gray-900 dark:text-white">
              Recent Activity
            </h3>
          </div>
          <div className="card-body">
            <div className="space-y-3">
              {analyticsData.recent_activity.slice(0, 10).map((activity: { description: string | number | boolean | React.ReactElement<any, string | React.JSXElementConstructor<any>> | Iterable<React.ReactNode> | React.ReactPortal | null | undefined; timestamp: string | Date; type: string | number | boolean | React.ReactElement<any, string | React.JSXElementConstructor<any>> | Iterable<React.ReactNode> | React.ReactPortal | null | undefined; }, index: React.Key | null | undefined) => (
                <div key={index} className="flex items-center justify-between p-3 bg-gray-50 dark:bg-gray-700 rounded-lg">
                  <div>
                    <p className="font-medium text-gray-900 dark:text-white">
                      {activity.description}
                    </p>
                    <p className="text-sm text-gray-600 dark:text-gray-400">
                      {formatRelativeTime(activity.timestamp)}
                    </p>
                  </div>
                  <span className="px-2 py-1 text-xs font-medium bg-blue-100 dark:bg-blue-900 text-blue-800 dark:text-blue-200 rounded">
                    {activity.type}
                  </span>
                </div>
              ))}
            </div>
          </div>
        </div>
      )}
    </div>
  );
};

export default Dashboard;