import { api } from "@/services/api/http";

// Backend API base URL
const API_BASE_URL = process.env.NEXT_PUBLIC_API_URL || "http://localhost:5000";

export interface User {
  email: string;
  name: string;
  picture: string;
}

export interface AuthResponse {
  access_token: string;
  user: User;
}

const TOKEN_KEY = "napscan_auth_token";
const USER_KEY = "napscan_user";

/**
 * Store authentication data in localStorage
 */
export function setAuthData(token: string, user: User): void {
  if (typeof window === "undefined") return;
  localStorage.setItem(TOKEN_KEY, token);
  localStorage.setItem(USER_KEY, JSON.stringify(user));
}

/**
 * Store user data only (cookie-based sessions).
 */
export function setUserData(user: User): void {
  if (typeof window === "undefined") return;
  localStorage.setItem(USER_KEY, JSON.stringify(user));
}

/**
 * Get stored JWT token
 */
export function getStoredToken(): string | null {
  if (typeof window === "undefined") return null;
  return localStorage.getItem(TOKEN_KEY);
}

/**
 * Get stored user data
 */
export function getStoredUser(): User | null {
  if (typeof window === "undefined") return null;
  const data = localStorage.getItem(USER_KEY);
  if (!data) return null;
  try {
    return JSON.parse(data) as User;
  } catch {
    return null;
  }
}

/**
 * Clear all auth data (logout)
 */
export function clearAuthData(): void {
  if (typeof window === "undefined") return;
  localStorage.removeItem(TOKEN_KEY);
  localStorage.removeItem(USER_KEY);
}

/**
 * Fetch current user session from backend (cookie-based).
 */
export async function fetchMe(): Promise<User | null> {
  try {
    const response = await api.get<User>("/api/auth/me");
    return response.data;
  } catch {
    return null;
  }
}

/**
 * Logout on backend (clears HTTPOnly cookie) and remove local storage.
 */
export async function logout(): Promise<void> {
  try {
    await api.post("/api/auth/logout");
  } catch {
    // ignore
  } finally {
    clearAuthData();
  }
}

/**
 * Send Google ID token to backend and receive JWT (Client-side flow)
 */
export async function loginWithGoogleToken(
  idToken: string
): Promise<AuthResponse> {
  const response = await api.post<AuthResponse>("/api/auth/google", {
    id_token: idToken,
  });
  return response.data;
}

/**
 * Get Google OAuth login redirect URL (Server-side redirect flow)
 */
export function getGoogleLoginUrl(): string {
  return `${API_BASE_URL}/api/auth/google/login`;
}

/**
 * Redirect to Google OAuth login (Server-side redirect flow)
 */
export function redirectToGoogleLogin(): void {
  if (typeof window === "undefined") return;
  const loginUrl = getGoogleLoginUrl();
  console.log("[Auth] Redirecting to Google login:", loginUrl);
  window.location.href = loginUrl;
}

/**
 * Handle Google OAuth callback - extract token from URL params
 * Call this function on the callback page to process the auth response
 */
export async function handleGoogleCallback(): Promise<AuthResponse | null> {
  if (typeof window === "undefined") return null;

  // Redirect-flow: backend already handled `code` and set HTTPOnly cookie,
  // then redirected here. We can't read HTTPOnly cookies in JS, so we fetch the
  // current session user from `/auth/me`.
  const user = await fetchMe();
  if (!user) return null;

  // Keep any existing token (ID-token flow) if present.
  const storedToken = getStoredToken() || "";
  setUserData(user);
  return { access_token: storedToken, user };
}

/**
 * Check if user is currently authenticated
 */
export function isAuthenticated(): boolean {
  // Token might not be present when using cookie-based sessions.
  return !!getStoredUser();
}
