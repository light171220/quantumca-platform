import React from 'react';
import { NavLink, useLocation } from 'react-router-dom';
import { useAuth } from '../hooks/useAuth';
import {
  HomeIcon,
  DocumentTextIcon,
  GlobeAltIcon,
  UsersIcon,
  DocumentDuplicateIcon,
  BuildingLibraryIcon,
  ClipboardDocumentListIcon,
  ChartBarIcon,
  ArrowRightOnRectangleIcon,
  XMarkIcon,
} from '@heroicons/react/24/outline';
import { classNames } from '../utils/helpers';

interface SidebarProps {
  isOpen: boolean;
  onClose: () => void;
}

const navigation = [
  { name: 'Dashboard', href: '/dashboard', icon: HomeIcon },
  { name: 'Certificates', href: '/certificates', icon: DocumentTextIcon },
  { name: 'Domains', href: '/domains', icon: GlobeAltIcon },
  { name: 'Customers', href: '/customers', icon: UsersIcon },
  { name: 'Templates', href: '/templates', icon: DocumentDuplicateIcon },
  { name: 'Intermediate CA', href: '/intermediate-ca', icon: BuildingLibraryIcon },
  { name: 'Audit Logs', href: '/audit-logs', icon: ClipboardDocumentListIcon },
  { name: 'Monitoring', href: '/monitoring', icon: ChartBarIcon },
];

const Sidebar: React.FC<SidebarProps> = ({ isOpen, onClose }) => {
  const location = useLocation();
  const { logout } = useAuth();

  const handleLogout = () => {
    logout();
    onClose();
  };

  return (
    <>
      {isOpen && (
        <div className="fixed inset-0 z-40 lg:hidden" onClick={onClose}>
          <div className="absolute inset-0 bg-gray-600 opacity-75" />
        </div>
      )}

      <div
        className={classNames(
          'fixed inset-y-0 left-0 z-50 w-64 bg-white dark:bg-gray-800 border-r border-gray-200 dark:border-gray-700 transform transition-transform duration-300 ease-in-out',
          isOpen ? 'translate-x-0' : '-translate-x-full',
          'lg:translate-x-0 lg:static lg:inset-0'
        )}
      >
        <div className="flex items-center justify-between h-16 px-6 border-b border-gray-200 dark:border-gray-700">
          <div className="flex items-center">
            <div className="flex-shrink-0">
              <div className="w-8 h-8 bg-quantum-600 rounded-lg flex items-center justify-center">
                <span className="text-white font-bold text-lg">Q</span>
              </div>
            </div>
            <span className="ml-3 text-lg font-semibold text-gray-900 dark:text-white">
              QuantumCA
            </span>
          </div>
          <button
            onClick={onClose}
            className="lg:hidden text-gray-400 hover:text-gray-600 dark:hover:text-gray-300"
            aria-label="Close sidebar"
            title="Close sidebar"
          >
            <XMarkIcon className="h-6 w-6" />
          </button>
        </div>

        <nav className="mt-6 px-3">
          <div className="space-y-1">
            {navigation.map((item) => {
              const isActive = location.pathname === item.href;
              return (
                <NavLink
                  key={item.name}
                  to={item.href}
                  onClick={onClose}
                  className={classNames(
                    'group flex items-center px-3 py-2 text-sm font-medium rounded-md transition-colors duration-200',
                    isActive
                      ? 'bg-quantum-100 dark:bg-quantum-900 text-quantum-700 dark:text-quantum-300'
                      : 'text-gray-700 dark:text-gray-300 hover:bg-gray-100 dark:hover:bg-gray-700'
                  )}
                >
                  <item.icon
                    className={classNames(
                      'mr-3 h-5 w-5 flex-shrink-0',
                      isActive
                        ? 'text-quantum-600 dark:text-quantum-400'
                        : 'text-gray-400 group-hover:text-gray-500 dark:group-hover:text-gray-300'
                    )}
                  />
                  {item.name}
                </NavLink>
              );
            })}
          </div>
        </nav>

        <div className="absolute bottom-0 left-0 right-0 p-3">
          <button
            onClick={handleLogout}
            className="w-full flex items-center px-3 py-2 text-sm font-medium text-gray-700 dark:text-gray-300 hover:bg-gray-100 dark:hover:bg-gray-700 rounded-md transition-colors duration-200"
          >
            <ArrowRightOnRectangleIcon className="mr-3 h-5 w-5 text-gray-400" />
            Sign out
          </button>
        </div>
      </div>
    </>
  );
};

export default Sidebar;