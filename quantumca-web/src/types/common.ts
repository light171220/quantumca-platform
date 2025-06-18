import * as React from 'react';

export interface TableColumn<T> {
  key: keyof T | string;
  title: string;
  sortable?: boolean;
  render?: (value: any, record: T) => React.ReactNode;
  width?: string;
}

export interface TableProps<T> {
  data: T[];
  columns: TableColumn<T>[];
  loading?: boolean;
  pagination?: {
    current: number;
    total: number;
    pageSize: number;
    onChange: (page: number) => void;
  };
  onRowClick?: (record: T) => void;
  selectedRows?: string[];
  onSelectionChange?: (selectedIds: string[]) => void;
  bulkActions?: Array<{
    label: string;
    onClick: (selectedIds: string[]) => void;
    icon?: React.ReactNode;
  }>;
}

export interface FilterOption {
  label: string;
  value: string;
}

export interface SortOption {
  field: string;
  direction: 'asc' | 'desc';
}

export interface PaginationState {
  page: number;
  limit: number;
  total: number;
}

export interface ApiError {
  message: string;
  code?: string;
  status?: number;
  details?: Record<string, any>;
}

export interface Toast {
  id: string;
  type: 'success' | 'error' | 'warning' | 'info';
  title: string;
  message?: string;
  duration?: number;
}

export interface ModalProps {
  isOpen: boolean;
  onClose: () => void;
  title: string;
  children: React.ReactNode;
  size?: 'sm' | 'md' | 'lg' | 'xl';
  showCloseButton?: boolean;
}

export interface StatusBadgeProps {
  status: string;
  variant?: 'default' | 'success' | 'warning' | 'danger' | 'info';
  size?: 'sm' | 'md' | 'lg';
}

export interface NavItem {
  id: string;
  label: string;
  path: string;
  icon: React.ReactNode;
  active?: boolean;
  badge?: string | number;
  children?: NavItem[];
}

export interface DashboardCard {
  title: string;
  value: string | number;
  change?: {
    value: number;
    type: 'increase' | 'decrease';
  };
  icon?: React.ReactNode;
  color?: string;
}

export interface ChartDataPoint {
  name: string;
  value: number;
  date?: string;
}

export interface FormField {
  name: string;
  label: string;
  type: 'text' | 'email' | 'password' | 'select' | 'textarea' | 'checkbox' | 'radio';
  required?: boolean;
  placeholder?: string;
  options?: Array<{ label: string; value: string }>;
  validation?: {
    pattern?: RegExp;
    minLength?: number;
    maxLength?: number;
    min?: number;
    max?: number;
  };
}