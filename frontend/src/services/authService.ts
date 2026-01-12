import { api } from "@/services/api/http";

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
 * Send Google ID token to backend and receive JWT
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
 * Check if user is currently authenticated
 */
export function isAuthenticated(): boolean {
    return !!getStoredToken();
}
