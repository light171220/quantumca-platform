import React from 'react';
import { StatusBadgeProps } from '../types/common';
import { classNames } from '../utils/helpers';

const StatusBadge: React.FC<StatusBadgeProps> = ({ 
  status, 
  variant = 'default', 
  size = 'md' 
}) => {
  const getVariantClasses = () => {
    switch (variant) {
      case 'success':
        return 'bg-green-100 text-green-800 dark:bg-green-900/20 dark:text-green-400';
      case 'warning':
        return 'bg-yellow-100 text-yellow-800 dark:bg-yellow-900/20 dark:text-yellow-400';
      case 'danger':
        return 'bg-red-100 text-red-800 dark:bg-red-900/20 dark:text-red-400';
      case 'info':
        return 'bg-blue-100 text-blue-800 dark:bg-blue-900/20 dark:text-blue-400';
      default:
        return 'bg-gray-100 text-gray-800 dark:bg-gray-700 dark:text-gray-300';
    }
  };

  const getSizeClasses = () => {
    switch (size) {
      case 'sm':
        return 'px-2 py-0.5 text-xs';
      case 'lg':
        return 'px-3 py-1 text-sm';
      default:
        return 'px-2.5 py-0.5 text-xs';
    }
  };

  const getStatusVariant = (status: string) => {
    const lowerStatus = status.toLowerCase();
    
    if (['issued', 'verified', 'active', 'healthy', 'up'].includes(lowerStatus)) {
      return 'success';
    }
    
    if (['pending', 'expiring', 'degraded'].includes(lowerStatus)) {
      return 'warning';
    }
    
    if (['expired', 'revoked', 'failed', 'suspended', 'unhealthy', 'down'].includes(lowerStatus)) {
      return 'danger';
    }
    
    if (['info', 'ready'].includes(lowerStatus)) {
      return 'info';
    }
    
    return 'default';
  };

  const finalVariant = variant === 'default' ? getStatusVariant(status) : variant;

  return (
    <span
      className={classNames(
        'inline-flex items-center font-medium rounded-full',
        getVariantClasses(),
        getSizeClasses()
      )}
    >
      {status}
    </span>
  );
};

export default StatusBadge;