import React from 'react';
import { classNames } from '../utils/helpers';

interface LoadingSpinnerProps {
  size?: 'sm' | 'md' | 'lg' | 'xl';
  className?: string;
  text?: string;
}

const LoadingSpinner: React.FC<LoadingSpinnerProps> = ({ 
  size = 'md', 
  className = '',
  text 
}) => {
  const getSizeClasses = () => {
    switch (size) {
      case 'sm':
        return 'w-4 h-4';
      case 'lg':
        return 'w-8 h-8';
      case 'xl':
        return 'w-12 h-12';
      default:
        return 'w-6 h-6';
    }
  };

  const getTextSize = () => {
    switch (size) {
      case 'sm':
        return 'text-sm';
      case 'lg':
        return 'text-lg';
      case 'xl':
        return 'text-xl';
      default:
        return 'text-base';
    }
  };

  return (
    <div className={classNames('flex items-center justify-center', className)}>
      <div className="flex flex-col items-center space-y-2">
        <div
          className={classNames(
            'animate-spin rounded-full border-2 border-gray-300 border-t-quantum-600',
            getSizeClasses()
          )}
        />
        {text && (
          <span className={classNames('text-gray-600 dark:text-gray-400', getTextSize())}>
            {text}
          </span>
        )}
      </div>
    </div>
  );
};

export default LoadingSpinner;