import { format, isAfter, isBefore, addDays } from 'date-fns';

export const formatDate = (date: string | Date, formatStr: string = 'MMM dd, yyyy'): string => {
  return format(new Date(date), formatStr);
};

export const formatDateTime = (date: string | Date): string => {
  return format(new Date(date), 'MMM dd, yyyy HH:mm');
};

export const formatRelativeTime = (date: string | Date): string => {
  return formatDistanceToNow(new Date(date), { addSuffix: true });
};

export const isExpiringSoon = (expiryDate: string | Date, days: number = 30): boolean => {
  const expiry = new Date(expiryDate);
  const threshold = addDays(new Date(), days);
  return isAfter(expiry, new Date()) && isBefore(expiry, threshold);
};

export const isExpired = (expiryDate: string | Date): boolean => {
  return isBefore(new Date(expiryDate), new Date());
};

export const truncateText = (text: string, maxLength: number): string => {
  if (text.length <= maxLength) return text;
  return `${text.slice(0, maxLength)}...`;
};

export const generateId = (): string => {
  return Math.random().toString(36).substr(2, 9);
};

export const copyToClipboard = async (text: string): Promise<boolean> => {
  try {
    await navigator.clipboard.writeText(text);
    return true;
  } catch {
    const textArea = document.createElement('textarea');
    textArea.value = text;
    document.body.appendChild(textArea);
    textArea.select();
    const success = document.execCommand('copy');
    document.body.removeChild(textArea);
    return success;
  }
};

export const downloadFile = (blob: Blob, filename: string): void => {
  const url = window.URL.createObjectURL(blob);
  const link = document.createElement('a');
  link.href = url;
  link.download = filename;
  document.body.appendChild(link);
  link.click();
  document.body.removeChild(link);
  window.URL.revokeObjectURL(url);
};

export const formatBytes = (bytes: number, decimals: number = 2): string => {
  if (bytes === 0) return '0 Bytes';
  
  const k = 1024;
  const dm = decimals < 0 ? 0 : decimals;
  const sizes = ['Bytes', 'KB', 'MB', 'GB', 'TB'];
  
  const i = Math.floor(Math.log(bytes) / Math.log(k));
  
  return parseFloat((bytes / Math.pow(k, i)).toFixed(dm)) + ' ' + sizes[i];
};

export const formatNumber = (num: number): string => {
  return new Intl.NumberFormat().format(num);
};

export const formatPercentage = (value: number, total: number): string => {
  if (total === 0) return '0%';
  return `${Math.round((value / total) * 100)}%`;
};

export const debounce = <T extends (...args: any[]) => any>(
  func: T,
  wait: number
): ((...args: Parameters<T>) => void) => {
  let timeout: NodeJS.Timeout;
  
  return (...args: Parameters<T>) => {
    clearTimeout(timeout);
    timeout = setTimeout(() => func(...args), wait);
  };
};

export const throttle = <T extends (...args: any[]) => any>(
  func: T,
  limit: number
): ((...args: Parameters<T>) => void) => {
  let inThrottle: boolean;
  
  return (...args: Parameters<T>) => {
    if (!inThrottle) {
      func(...args);
      inThrottle = true;
      setTimeout(() => (inThrottle = false), limit);
    }
  };
};

export const parseJSON = <T>(str: string, fallback: T): T => {
  try {
    return JSON.parse(str);
  } catch {
    return fallback;
  }
};

export const classNames = (...classes: (string | undefined | null | false)[]): string => {
  return classes.filter(Boolean).join(' ');
};

export const getInitials = (name: string): string => {
  return name
    .split(' ')
    .map(word => word.charAt(0).toUpperCase())
    .slice(0, 2)
    .join('');
};