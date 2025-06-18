import React, { useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { useAuth } from '../hooks/useAuth';
import { validateApiKey } from '../utils/validation';
import LoadingSpinner from '../components/LoadingSpinner';
import toast from 'react-hot-toast';

const LoginPage: React.FC = () => {
  const [apiKey, setApiKey] = useState('');
  const [errors, setErrors] = useState<{ apiKey?: string }>({});
  const { login, isLoading, error } = useAuth();
  const navigate = useNavigate();

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    
    const newErrors: { apiKey?: string } = {};
    
    if (!apiKey) {
      newErrors.apiKey = 'API key is required';
    } else if (!validateApiKey(apiKey)) {
      newErrors.apiKey = 'Invalid API key format';
    }
    
    setErrors(newErrors);
    
    if (Object.keys(newErrors).length > 0) {
      return;
    }
    
    try {
      await login(apiKey);
      toast.success('Login successful!');
      navigate('/dashboard');
    } catch (err) {
      toast.error('Login failed. Please check your API key.');
    }
  };

  return (
    <div className="min-h-screen flex items-center justify-center bg-gray-50 dark:bg-gray-900 py-12 px-4 sm:px-6 lg:px-8">
      <div className="max-w-md w-full space-y-8">
        <div>
          <div className="mx-auto h-16 w-16 bg-quantum-600 rounded-xl flex items-center justify-center">
            <span className="text-white font-bold text-2xl">Q</span>
          </div>
          <h2 className="mt-6 text-center text-3xl font-extrabold text-gray-900 dark:text-white">
            Sign in to QuantumCA
          </h2>
          <p className="mt-2 text-center text-sm text-gray-600 dark:text-gray-400">
            Enter your API key to access the platform
          </p>
        </div>
        
        <form className="mt-8 space-y-6" onSubmit={handleSubmit}>
          <div>
            <label htmlFor="apiKey" className="form-label">
              API Key
            </label>
            <input
              id="apiKey"
              name="apiKey"
              type="password"
              autoComplete="current-password"
              required
              className="form-input"
              placeholder="Enter your API key"
              value={apiKey}
              onChange={(e) => setApiKey(e.target.value)}
            />
            {errors.apiKey && (
              <p className="form-error">{errors.apiKey}</p>
            )}
            {error && (
              <p className="form-error">{error}</p>
            )}
          </div>

          <div>
            <button
              type="submit"
              disabled={isLoading}
              className="group relative w-full flex justify-center py-2 px-4 border border-transparent text-sm font-medium rounded-md text-white bg-quantum-600 hover:bg-quantum-700 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-quantum-500 disabled:opacity-50 disabled:cursor-not-allowed"
            >
              {isLoading ? (
                <LoadingSpinner size="sm" />
              ) : (
                'Sign in'
              )}
            </button>
          </div>

          <div className="text-sm text-center text-gray-600 dark:text-gray-400">
            <p>Need an API key? Contact your administrator.</p>
          </div>
        </form>
      </div>
    </div>
  );
};

export default LoginPage;