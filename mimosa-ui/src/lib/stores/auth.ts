import { writable } from 'svelte/store';

export type AuthUser = {
  username: string;
  role: string;
};

type AuthState = {
  user: AuthUser | null;
  loading: boolean;
  error: string | null;
};

const { subscribe, update, set } = writable<AuthState>({
  user: null,
  loading: true,
  error: null
});

async function request<T>(path: string, options?: RequestInit): Promise<T> {
  const response = await fetch(path, {
    headers: {
      'Content-Type': 'application/json',
      ...(options?.headers || {})
    },
    credentials: 'include',
    ...options
  });

  if (!response.ok) {
    const payload = await response.json().catch(() => ({}));
    const message = payload?.detail || 'Error de autenticacion';
    throw new Error(message);
  }

  if (response.status === 204) {
    return {} as T;
  }

  return response.json() as Promise<T>;
}

export const authStore = {
  subscribe,
  async checkSession() {
    update((state) => ({ ...state, loading: true, error: null }));
    try {
      const payload = await request<{ user: AuthUser | null }>(
        '/api/auth/session'
      );
      set({ user: payload.user, loading: false, error: null });
    } catch (error) {
      set({ user: null, loading: false, error: error instanceof Error ? error.message : null });
    }
  },
  async login(username: string, password: string) {
    update((state) => ({ ...state, loading: true, error: null }));
    try {
      const payload = await request<{ user: AuthUser }>(
        '/api/auth/login',
        {
          method: 'POST',
          body: JSON.stringify({ username, password })
        }
      );
      set({ user: payload.user, loading: false, error: null });
      return payload.user;
    } catch (error) {
      update((state) => ({
        ...state,
        loading: false,
        error: error instanceof Error ? error.message : 'Error de autenticacion'
      }));
      throw error;
    }
  },
  async logout() {
    update((state) => ({ ...state, loading: true, error: null }));
    try {
      await request('/api/auth/logout', { method: 'POST' });
    } finally {
      set({ user: null, loading: false, error: null });
    }
  }
};
