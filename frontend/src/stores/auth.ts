import { defineStore } from "pinia";
import { api, configureApiClient, ApiError } from "../api/client";

export type UserScopes = {
  calendar: boolean;
  tracker: boolean;
};

export type User = {
  id: string;
  username: string;
  role: "admin" | "user";
  active: boolean;
  locked: boolean;
  scopes: UserScopes;
  created_at: string;
  updated_at: string;
};

type TokenResponse = {
  access_token: string;
  refresh_token: string;
  expires_in: number;
  refresh_expires_in: number;
};

const ACCESS_TOKEN_KEY = "legacy_auth_access_token";
const REFRESH_TOKEN_KEY = "legacy_auth_refresh_token";

export const useAuthStore = defineStore("auth", {
  state: () => ({
    accessToken: localStorage.getItem(ACCESS_TOKEN_KEY) as string | null,
    refreshToken: localStorage.getItem(REFRESH_TOKEN_KEY) as string | null,
    user: null as User | null,
    initialized: false,
  }),
  getters: {
    isAuthenticated: (state) => Boolean(state.accessToken),
    isAdmin: (state) => state.user?.role === "admin",
  },
  actions: {
    setTokens(tokens: TokenResponse | null) {
      this.accessToken = tokens?.access_token ?? null;
      this.refreshToken = tokens?.refresh_token ?? null;
      if (tokens) {
        localStorage.setItem(ACCESS_TOKEN_KEY, tokens.access_token);
        localStorage.setItem(REFRESH_TOKEN_KEY, tokens.refresh_token);
      } else {
        localStorage.removeItem(ACCESS_TOKEN_KEY);
        localStorage.removeItem(REFRESH_TOKEN_KEY);
      }
    },
    async login(username: string, password: string) {
      const tokens = await api.post<TokenResponse>("/auth/login", { username, password });
      this.setTokens(tokens);
      await this.fetchMe();
    },
    async logout() {
      try {
        if (this.refreshToken) {
          await api.post("/auth/logout", { refresh_token: this.refreshToken });
        }
      } catch {
        // best effort
      }
      this.setTokens(null);
      this.user = null;
    },
    async fetchMe() {
      this.user = await api.get<User>("/auth/me");
    },
    async tryRefresh(): Promise<boolean> {
      if (!this.refreshToken) return false;
      try {
        const tokens = await api.post<TokenResponse>("/auth/refresh", { refresh_token: this.refreshToken });
        this.setTokens(tokens);
        return true;
      } catch {
        this.setTokens(null);
        this.user = null;
        return false;
      }
    },
    async initialize() {
      if (this.initialized) return;
      this.initialized = true;
      if (!this.accessToken) return;
      try {
        await this.fetchMe();
      } catch (error) {
        if (error instanceof ApiError && error.status === 401) {
          const refreshed = await this.tryRefresh();
          if (refreshed) {
            await this.fetchMe();
          }
        }
      }
    },
  },
});

export function installApiClient(authStore: ReturnType<typeof useAuthStore>) {
  configureApiClient({
    getAccessToken: () => authStore.accessToken,
    onUnauthorizedRefresh: () => authStore.tryRefresh(),
    onSessionExpired: () => {
      authStore.setTokens(null);
      authStore.user = null;
    },
  });
}
