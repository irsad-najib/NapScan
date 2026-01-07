import axios, {
  AxiosError,
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

export const api: AxiosInstance = axios.create({
  baseURL: API_BASE_URL,
  timeout: Number.isFinite(API_TIMEOUT_MS) ? API_TIMEOUT_MS : 600_000,
  withCredentials:
    WITH_CREDENTIALS === "1" ||
    WITH_CREDENTIALS === "true" ||
    WITH_CREDENTIALS === "yes",
  headers: {
    "Content-Type": "application/json",
  },
});

api.interceptors.request.use(
  (config) => {
    // If you later add auth, keep this SSR-safe.
    // Example:
    // if (typeof window !== 'undefined') {
    //   const token = window.localStorage.getItem('authToken');
    //   if (token) config.headers.Authorization = `Bearer ${token}`;
    // }
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
