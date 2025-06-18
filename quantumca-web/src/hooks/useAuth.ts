import { useState, useEffect } from 'react';
import { authService } from '../services/auth';
import { AuthResponse } from '../types/api';

interface UseAuthReturn {
  isAuthenticated: boolean;
  isLoading: boolean;
  login: (apiKey: string) => Promise<AuthResponse>;
  logout: () => void;
  error: string | null;
}

export const useAuth = (): UseAuthReturn => {
  const [isAuthenticated, setIsAuthenticated] = useState(false);
  const [isLoading, setIsLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    const checkAuth = async () => {
      setIsLoading(true);
      
      if (authService.isAuthenticated()) {
        setIsAuthenticated(true);
      } else {
        const refreshToken = authService.getRefreshToken();
        if (refreshToken) {
          try {
            await authService.refreshToken();
            setIsAuthenticated(true);
          } catch {
            setIsAuthenticated(false);
          }
        } else {
          setIsAuthenticated(false);
        }
      }
      
      setIsLoading(false);
    };

    checkAuth();
  }, []);

  const login = async (apiKey: string): Promise<AuthResponse> => {
    setIsLoading(true);
    setError(null);
    
    try {
      const response = await authService.login(apiKey);
      setIsAuthenticated(true);
      return response;
    } catch (err: any) {
      setError(err.response?.data?.message || 'Login failed');
      throw err;
    } finally {
      setIsLoading(false);
    }
  };

  const logout = () => {
    authService.logout();
    setIsAuthenticated(false);
  };

  return {
    isAuthenticated,
    isLoading,
    login,
    logout,
    error,
  };
};