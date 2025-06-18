import { apiService } from './api';
import { AuthResponse } from '../types/api';

class AuthService {
  private tokenKey = 'auth_token';
  private refreshTokenKey = 'refresh_token';

  async login(apiKey: string): Promise<AuthResponse> {
    const request = { api_key: apiKey };
    const response = await apiService.login(request);
    
    if (!response.token || !response.refreshToken) {
      throw new Error('Missing token or refresh token in response');
    }
    this.setTokens(response.token, response.refreshToken);
    return response;
  }

  async logout(): Promise<void> {
    this.clearTokens();
  }

  async refreshToken(): Promise<AuthResponse | null> {
    try {
      const token = this.getToken();
      if (!token) return null;
      
      const response = await apiService.refreshToken(token);
      this.setTokens(response.token, response.refreshToken!);
      return response;
    } catch (error) {
      this.clearTokens();
      return null;
    }
  }

  getToken(): string | null {
    return localStorage.getItem(this.tokenKey);
  }

  getRefreshToken(): string | null {
    return localStorage.getItem(this.refreshTokenKey);
  }

  isAuthenticated(): boolean {
    const token = this.getToken();
    if (!token) return false;

    try {
      const payload = JSON.parse(atob(token.split('.')[1]));
      return payload.exp * 1000 > Date.now();
    } catch {
      return false;
    }
  }

  private setTokens(token: string, refreshToken: string): void {
    localStorage.setItem(this.tokenKey, token);
    localStorage.setItem(this.refreshTokenKey, refreshToken);
  }

  private clearTokens(): void {
    localStorage.removeItem(this.tokenKey);
    localStorage.removeItem(this.refreshTokenKey);
  }
}

export const authService = new AuthService();