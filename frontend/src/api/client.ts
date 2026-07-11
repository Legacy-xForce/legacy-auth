// Defaults to same-origin (relative) requests, which is correct when the
// backend serves the built frontend itself (see Dockerfile). Local dev with
// a separate Vite dev server must set VITE_API_URL to the backend's origin.
const API_URL = import.meta.env.VITE_API_URL ?? "";

export class ApiError extends Error {
  status: number;
  constructor(message: string, status: number) {
    super(message);
    this.status = status;
  }
}

type TokenGetter = () => string | null;
type RefreshHandler = () => Promise<boolean>;
type LogoutHandler = () => void;

let getAccessToken: TokenGetter = () => null;
let onUnauthorizedRefresh: RefreshHandler = async () => false;
let onSessionExpired: LogoutHandler = () => {};

export function configureApiClient(options: {
  getAccessToken: TokenGetter;
  onUnauthorizedRefresh: RefreshHandler;
  onSessionExpired: LogoutHandler;
}) {
  getAccessToken = options.getAccessToken;
  onUnauthorizedRefresh = options.onUnauthorizedRefresh;
  onSessionExpired = options.onSessionExpired;
}

async function request<T>(path: string, init: RequestInit = {}, retry = true): Promise<T> {
  const headers = new Headers(init.headers);
  const isFormData = init.body instanceof FormData;
  if (!isFormData && init.body && !headers.has("Content-Type")) {
    headers.set("Content-Type", "application/json");
  }
  const token = getAccessToken();
  if (token) {
    headers.set("Authorization", `Bearer ${token}`);
  }

  const response = await fetch(`${API_URL}${path}`, { ...init, headers });

  if (response.status === 401 && retry && token) {
    const refreshed = await onUnauthorizedRefresh();
    if (refreshed) {
      return request<T>(path, init, false);
    }
    onSessionExpired();
    throw new ApiError("Session expired", 401);
  }

  const contentType = response.headers.get("content-type") ?? "";
  const data = contentType.includes("application/json") ? await response.json() : null;

  if (!response.ok) {
    throw new ApiError(data?.error ?? response.statusText, response.status);
  }

  return data as T;
}

export const api = {
  get: <T>(path: string) => request<T>(path, { method: "GET" }),
  post: <T>(path: string, body?: unknown) =>
    request<T>(path, { method: "POST", body: body instanceof FormData ? body : JSON.stringify(body ?? {}) }),
  patch: <T>(path: string, body?: unknown) =>
    request<T>(path, { method: "PATCH", body: JSON.stringify(body ?? {}) }),
  delete: <T>(path: string) => request<T>(path, { method: "DELETE" }),
  postForm: <T>(path: string, formData: FormData) => request<T>(path, { method: "POST", body: formData }),
};

export function avatarUrl(userId: string) {
  return `${API_URL}/auth/profile-picture/${userId}`;
}
