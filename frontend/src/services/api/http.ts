import axios, {
  AxiosError,
  AxiosHeaders,
  AxiosInstance,
  AxiosRequestConfig,
  AxiosResponse,
} from "axios";

export class ApiError extends Error {
  status?: number;
  data?: unknown;
  details?: string;

  constructor(message: string, opts?: { status?: number; data?: unknown }) {
    super(message);
    this.name = "ApiError";
    this.status = opts?.status;
    this.data = opts?.data;
  }
}

export type ApiOk<T> = {
  ok: true;
  status: number;
  data: T;
  message?: string;
};

export type ApiErr = {
  ok: false;
  status?: number;
  message: string;
  details?: string;
  data?: unknown;
};

export type ApiResult<T> = ApiOk<T> | ApiErr;

function normalizeBaseURL(raw: string): string {
  const v = raw.trim();
  if (!v) return v;
  return v.endsWith("/") ? v.slice(0, -1) : v;
}

const API_BASE_URL = normalizeBaseURL(
  process.env.NEXT_PUBLIC_API_URL || "http://localhost:5000"
);
const API_TIMEOUT_MS = Number(
  process.env.NEXT_PUBLIC_API_TIMEOUT_MS || 600_000
);
const WITH_CREDENTIALS = (
  process.env.NEXT_PUBLIC_WITH_CREDENTIALS || ""
).toLowerCase();

const DEFAULT_WITH_CREDENTIALS =
  WITH_CREDENTIALS !== "0" &&
  WITH_CREDENTIALS !== "false" &&
  WITH_CREDENTIALS != "no";

export const api: AxiosInstance = axios.create({
  baseURL: API_BASE_URL,
  timeout: Number.isFinite(API_TIMEOUT_MS) ? API_TIMEOUT_MS : 600_000,
  // Cookie-based sessions require credentials for cross-origin dev (localhost:3000 -> localhost:5000).
  // Default to on unless explicitly disabled.
  withCredentials: DEFAULT_WITH_CREDENTIALS,
  headers: {
    "Content-Type": "application/json",
  },
});

const TOKEN_STORAGE_KEY = "napscan_auth_token";

function getAuthTokenFromStorage(): string | undefined {
  // Note: HttpOnly cookies cannot be read from JS.
  // Cookie sessions are sent automatically by the browser when allowed (CORS + withCredentials).
  // This storage token is a fallback for token-based auth.
  if (typeof window === "undefined") return undefined;
  try {
    return window.localStorage.getItem(TOKEN_STORAGE_KEY) ?? undefined;
  } catch {
    return undefined;
  }
}

function hasAuthorizationHeader(headers: unknown): boolean {
  if (!headers) return false;
  if (headers instanceof AxiosHeaders) {
    const v = headers.get("Authorization");
    return typeof v === "string" && v.length > 0;
  }
  const h = headers as Record<string, unknown>;
  const v = h.Authorization ?? h.authorization;
  return typeof v === "string" && v.length > 0;
}

function setAuthorizationHeader(headers: unknown, value: string): unknown {
  if (!headers) {
    return { Authorization: value };
  }
  if (headers instanceof AxiosHeaders) {
    headers.set("Authorization", value);
    return headers;
  }
  const h = headers as Record<string, unknown>;
  return { ...h, Authorization: value };
}

api.interceptors.request.use(
  (config) => {
    // Skip auth header for login endpoints
    const isLoginEndpoint =
      config.url?.includes("/api/auth/google") ||
      config.url?.includes("/api/auth/google/login") ||
      config.url?.includes("/api/auth/google/callback");

    if (isLoginEndpoint) {
      return config;
    }

    // Prefer cookie-based sessions (HttpOnly) when available; browsers send them automatically.
    // As a fallback (e.g. if cookies are blocked), attach the stored JWT as Bearer.
    if (!hasAuthorizationHeader(config.headers)) {
      const token = getAuthTokenFromStorage();
      if (token) {
        config.headers = setAuthorizationHeader(
          config.headers,
          `Bearer ${token}`
        ) as typeof config.headers;
      }
    }

    return config;
  },
  (error) => Promise.reject(error)
);

function toApiError(error: unknown): ApiError {
  if (axios.isAxiosError(error)) {
    const ax = error as AxiosError;
    const status = ax.response?.status;
    const data = ax.response?.data;

    const dataObj =
      typeof data === "object" && data !== null
        ? (data as Record<string, unknown>)
        : null;

    const message =
      (dataObj &&
        (typeof dataObj.message === "string" ? dataObj.message : undefined)) ||
      (dataObj &&
        (typeof dataObj.error === "string" ? dataObj.error : undefined)) ||
      ax.message ||
      "Request failed";

    const details =
      dataObj && typeof dataObj.details === "string"
        ? dataObj.details
        : undefined;

    const err = new ApiError(message, { status, data });

    // If the browser blocks the response (CORS), Axios typically surfaces it as a Network Error
    // with no `response` object. Add a helpful hint for development.
    if (!ax.response && typeof window !== "undefined") {
      const hint =
        "No response received by browser. This is commonly caused by CORS/preflight blocking (check DevTools Network for OPTIONS + response headers).";
      err.details = err.details ? `${err.details} | ${hint}` : hint;
    }
    if (details) {
      err.details = details;
    }
    return err;
  }

  if (error instanceof Error) {
    return new ApiError(error.message);
  }

  return new ApiError("Unknown error");
}

api.interceptors.response.use(
  (response: AxiosResponse) => response,
  (error) => Promise.reject(toApiError(error))
);

export async function request<T>(
  config: AxiosRequestConfig
): Promise<ApiResult<T>> {
  try {
    const res = await api.request<T>(config);

    let message: string | undefined;
    const dataObj =
      typeof res.data === "object" && res.data !== null
        ? (res.data as Record<string, unknown>)
        : null;
    if (dataObj && typeof dataObj.message === "string") {
      message = dataObj.message;
    }

    return {
      ok: true,
      status: res.status,
      data: res.data,
      message,
    };
  } catch (err) {
    const apiErr = err instanceof ApiError ? err : toApiError(err);
    const details = apiErr.details;

    return {
      ok: false,
      status: apiErr.status,
      message: apiErr.message,
      details,
      data: apiErr.data,
    };
  }
}
