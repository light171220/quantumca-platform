import { useState, useEffect, useCallback } from 'react';
import { apiService } from '../services/api';

interface UseApiState<T> {
  data: T | null;
  loading: boolean;
  error: string | null;
}

interface UseApiReturn<T> extends UseApiState<T> {
  refetch: () => Promise<void>;
  mutate: (newData: T) => void;
}

export const useApi = <T>(
  apiCall: () => Promise<T>,
  dependencies: any[] = []
): UseApiReturn<T> => {
  const [state, setState] = useState<UseApiState<T>>({
    data: null,
    loading: true,
    error: null,
  });

  const fetchData = useCallback(async () => {
    setState(prev => ({ ...prev, loading: true, error: null }));
    
    try {
      const data = await apiCall();
      setState({ data, loading: false, error: null });
    } catch (err: any) {
      setState({
        data: null,
        loading: false,
        error: err.response?.data?.message || err.message || 'An error occurred',
      });
    }
  }, dependencies);

  useEffect(() => {
    fetchData();
  }, [fetchData]);

  const mutate = useCallback((newData: T) => {
    setState(prev => ({ ...prev, data: newData }));
  }, []);

  return {
    ...state,
    refetch: fetchData,
    mutate,
  };
};

export const useMutation = <T, P>(
  mutationFn: (params: P) => Promise<T>
) => {
  const [state, setState] = useState<UseApiState<T>>({
    data: null,
    loading: false,
    error: null,
  });

  const mutate = useCallback(async (params: P) => {
    setState({ data: null, loading: true, error: null });
    
    try {
      const data = await mutationFn(params);
      setState({ data, loading: false, error: null });
      return data;
    } catch (err: any) {
      const error = err.response?.data?.message || err.message || 'An error occurred';
      setState({ data: null, loading: false, error });
      throw err;
    }
  }, [mutationFn]);

  return {
    ...state,
    mutate,
    reset: () => setState({ data: null, loading: false, error: null }),
  };
};