import React, { useState } from 'react';
import { ChevronUpDownIcon, ChevronUpIcon, ChevronDownIcon } from '@heroicons/react/24/outline';
import { TableProps, TableColumn, SortOption } from '../types/common';
import { classNames } from '../utils/helpers';
import LoadingSpinner from './LoadingSpinner';

function DataTable<T extends Record<string, any>>({
  data,
  columns,
  loading = false,
  pagination,
  onRowClick,
  selectedRows = [],
  onSelectionChange,
  bulkActions = [],
}: TableProps<T>) {
  const [sortConfig, setSortConfig] = useState<SortOption | null>(null);

  const handleSort = (column: TableColumn<T>) => {
    if (!column.sortable) return;

    const field = column.key as string;
    let direction: 'asc' | 'desc' = 'asc';

    if (sortConfig?.field === field && sortConfig.direction === 'asc') {
      direction = 'desc';
    }

    setSortConfig({ field, direction });
  };

  const sortedData = React.useMemo(() => {
    if (!sortConfig) return data;

    return [...data].sort((a, b) => {
      const aValue = a[sortConfig.field];
      const bValue = b[sortConfig.field];

      if (aValue < bValue) {
        return sortConfig.direction === 'asc' ? -1 : 1;
      }
      if (aValue > bValue) {
        return sortConfig.direction === 'asc' ? 1 : -1;
      }
      return 0;
    });
  }, [data, sortConfig]);

  const handleSelectAll = (checked: boolean) => {
    if (!onSelectionChange) return;
    
    if (checked) {
      const allIds = data.map(item => item.id);
      onSelectionChange(allIds);
    } else {
      onSelectionChange([]);
    }
  };

  const handleSelectRow = (id: string, checked: boolean) => {
    if (!onSelectionChange) return;
    
    if (checked) {
      onSelectionChange([...selectedRows, id]);
    } else {
      onSelectionChange(selectedRows.filter(rowId => rowId !== id));
    }
  };

  const getSortIcon = (column: TableColumn<T>) => {
    if (!column.sortable) return null;

    const field = column.key as string;
    if (sortConfig?.field !== field) {
      return <ChevronUpDownIcon className="w-4 h-4" />;
    }

    return sortConfig.direction === 'asc' 
      ? <ChevronUpIcon className="w-4 h-4" />
      : <ChevronDownIcon className="w-4 h-4" />;
  };

  if (loading) {
    return (
      <div className="flex justify-center items-center py-8">
        <LoadingSpinner size="lg" />
      </div>
    );
  }

  return (
    <div className="space-y-4">
      {bulkActions.length > 0 && selectedRows.length > 0 && (
        <div className="flex items-center gap-2 p-4 bg-blue-50 dark:bg-blue-900/20 rounded-lg">
          <span className="text-sm text-blue-700 dark:text-blue-300">
            {selectedRows.length} selected
          </span>
          {bulkActions.map((action, index) => (
            <button
              key={index}
              onClick={() => action.onClick(selectedRows)}
              className="inline-flex items-center px-3 py-1.5 border border-transparent text-xs font-medium rounded text-blue-700 bg-blue-100 hover:bg-blue-200 dark:bg-blue-800 dark:text-blue-200 dark:hover:bg-blue-700"
            >
              {action.icon && <span className="mr-1">{action.icon}</span>}
              {action.label}
            </button>
          ))}
        </div>
      )}

      <div className="table-container">
        <table className="table">
          <thead className="table-header">
            <tr>
              {onSelectionChange && (
                <th className="table-header-cell w-4">
                  <input
                    type="checkbox"
                    className="rounded border-gray-300 text-quantum-600 focus:ring-quantum-500"
                    checked={selectedRows.length === data.length && data.length > 0}
                    onChange={(e) => handleSelectAll(e.target.checked)}
                  />
                </th>
              )}
              {columns.map((column, index) => (
                <th
                  key={index}
                  className={classNames(
                    'table-header-cell',
                    column.sortable && 'cursor-pointer hover:bg-gray-100 dark:hover:bg-gray-600',
                    column.width ? `col-width-${index}` : ''
                  )}
                  onClick={() => handleSort(column)}
                >
                  <div className="flex items-center space-x-1">
                    <span>{column.title}</span>
                    {getSortIcon(column)}
                  </div>
                </th>
              ))}
            </tr>
          </thead>
          <tbody className="table-body">
            {sortedData.map((row, rowIndex) => (
              <tr
                key={rowIndex}
                className={classNames(
                  onRowClick && 'cursor-pointer hover:bg-gray-50 dark:hover:bg-gray-700'
                )}
                onClick={() => onRowClick?.(row)}
              >
                {onSelectionChange && (
                  <td className="table-cell">
                    <input
                        type="checkbox"
                        className="rounded border-gray-300 text-quantum-600 focus:ring-quantum-500"
                        checked={selectedRows.includes(row.id)}
                        aria-label="Select row"
                        title="Select row"
                        onChange={(e) => {
                          e.stopPropagation();
                          handleSelectRow(row.id, e.target.checked);
                        }}
                      />
                  </td>
                )}
                {columns.map((column, colIndex) => (
                  <td key={colIndex} className="table-cell">
                    {column.render 
                      ? column.render(row[column.key], row)
                      : row[column.key]
                    }
                  </td>
                ))}
              </tr>
            ))}
          </tbody>
        </table>
      </div>

      {data.length === 0 && !loading && (
        <div className="text-center py-8 text-gray-500 dark:text-gray-400">
          No data available
        </div>
      )}

      {pagination && (
        <div className="flex items-center justify-between px-4 py-3 bg-white dark:bg-gray-800 border-t border-gray-200 dark:border-gray-700">
          <div className="flex items-center text-sm text-gray-700 dark:text-gray-300">
            Showing {((pagination.current - 1) * pagination.pageSize) + 1} to{' '}
            {Math.min(pagination.current * pagination.pageSize, pagination.total)} of{' '}
            {pagination.total} results
          </div>
          <div className="flex items-center space-x-2">
            <button
              onClick={() => pagination.onChange(pagination.current - 1)}
              disabled={pagination.current === 1}
              className="px-3 py-1 text-sm border border-gray-300 dark:border-gray-600 rounded-md disabled:opacity-50 disabled:cursor-not-allowed hover:bg-gray-50 dark:hover:bg-gray-700"
            >
              Previous
            </button>
            <span className="text-sm text-gray-700 dark:text-gray-300">
              Page {pagination.current} of {Math.ceil(pagination.total / pagination.pageSize)}
            </span>
            <button
              onClick={() => pagination.onChange(pagination.current + 1)}
              disabled={pagination.current >= Math.ceil(pagination.total / pagination.pageSize)}
              className="px-3 py-1 text-sm border border-gray-300 dark:border-gray-600 rounded-md disabled:opacity-50 disabled:cursor-not-allowed hover:bg-gray-50 dark:hover:bg-gray-700"
            >
              Next
            </button>
          </div>
        </div>
      )}
    </div>
  );
}

export default DataTable;