import React, { useState } from 'react';
import Sidebar from './Sidebar';
import { Bars3Icon } from '@heroicons/react/24/outline';

interface LayoutProps {
  children: React.ReactNode;
}

const Layout: React.FC<LayoutProps> = ({ children }) => {
  const [sidebarOpen, setSidebarOpen] = useState(false);

  return (
    <div className="flex h-screen bg-gray-50 dark:bg-gray-900">
      <Sidebar isOpen={sidebarOpen} onClose={() => setSidebarOpen(false)} />
      
      <div className="flex-1 flex flex-col overflow-hidden lg:pl-64">
        <header className="bg-white dark:bg-gray-800 shadow-sm border-b border-gray-200 dark:border-gray-700 lg:hidden">
          <div className="px-4 py-3 flex items-center justify-between">
            <button
              onClick={() => setSidebarOpen(true)}
              className="text-gray-600 dark:text-gray-300 hover:text-gray-900 dark:hover:text-white"
              aria-label="Open sidebar"
              title="Open sidebar"
            >
              <Bars3Icon className="h-6 w-6" />
            </button>
            <h1 className="text-lg font-semibold text-gray-900 dark:text-white">
              QuantumCA Platform
            </h1>
          </div>
        </header>

        <main className="flex-1 overflow-y-auto p-6">
          <div className="max-w-7xl mx-auto">
            {children}
          </div>
        </main>
      </div>
    </div>
  );
};

export default Layout;