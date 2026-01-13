import { api } from "@/services/api/http";

// Backend API base URL
const API_BASE_URL = process.env.NEXT_PUBLIC_API_URL || "http://localhost:5000";

export interface User {
    id: string;
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
 * Send Google ID token to backend and receive JWT (Client-side flow)
 */
export async function loginWithGoogleToken(
    idToken: string
): Promise<AuthResponse> {
    const response = await api.post<AuthResponse>("/auth/google", {
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

    const urlParams = new URLSearchParams(window.location.search);
    const token = urlParams.get("token");
    const userParam = urlParams.get("user");
    const error = urlParams.get("error");

    if (error) {
        console.error("Google OAuth error:", error);
        return null;
    }

    if (token && userParam) {
        try {
            const user = JSON.parse(decodeURIComponent(userParam)) as User;
            setAuthData(token, user);
            return { access_token: token, user };
        } catch (e) {
            console.error("Failed to parse user data:", e);
            return null;
        }
    }

    // If no inline params, check if callback returns JSON
    // Try fetching from callback endpoint with code
    const code = urlParams.get("code");
    if (code) {
        try {
            const response = await api.get<AuthResponse>(`/auth/google/callback?code=${code}`);
            if (response.data) {
                setAuthData(response.data.access_token, response.data.user);
                return response.data;
            }
        } catch (e) {
            console.error("Failed to exchange code:", e);
            return null;
        }
    }

    return null;
}

/**
 * Check if user is currently authenticated
 */
export function isAuthenticated(): boolean {
    return !!getStoredToken();
}
