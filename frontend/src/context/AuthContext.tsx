"use client";

import {
    createContext,
    useContext,
    useState,
    useEffect,
    useCallback,
    ReactNode,
} from "react";
import {
    User,
    getStoredUser,
    getStoredToken,
    setAuthData,
    clearAuthData,
    loginWithGoogleToken,
    redirectToGoogleLogin,
} from "@/services/authService";

interface AuthContextType {
    user: User | null;
    loading: boolean;
    isAuthenticated: boolean;
    login: () => void;
    loginWithRedirect: () => void;
    logout: () => void;
    refreshUser: () => void;
}

const AuthContext = createContext<AuthContextType | undefined>(undefined);

// Extend window for Google Sign-In
declare global {
    interface Window {
        google?: {
            accounts: {
                id: {
                    initialize: (config: {
                        client_id: string;
                        callback: (response: { credential: string }) => void;
                        auto_select?: boolean;
                    }) => void;
                    prompt: () => void;
                    renderButton: (
                        element: HTMLElement,
                        config: {
                            theme?: "outline" | "filled_blue" | "filled_black";
                            size?: "large" | "medium" | "small";
                            type?: "standard" | "icon";
                            shape?: "rectangular" | "pill" | "circle" | "square";
                            text?: "signin_with" | "signup_with" | "continue_with" | "signin";
                            logo_alignment?: "left" | "center";
                            width?: number;
                        }
                    ) => void;
                    disableAutoSelect: () => void;
                };
            };
        };
    }
}

const GOOGLE_CLIENT_ID = process.env.NEXT_PUBLIC_GOOGLE_CLIENT_ID || "";

export function AuthProvider({ children }: { children: ReactNode }) {
    const [user, setUser] = useState<User | null>(null);
    const [loading, setLoading] = useState(true);

    // Handle Google credential response
    const handleCredentialResponse = useCallback(
        async (response: { credential: string }) => {
            try {
                setLoading(true);
                const authResponse = await loginWithGoogleToken(response.credential);
                setAuthData(authResponse.access_token, authResponse.user);
                setUser(authResponse.user);
            } catch (error) {
                console.error("Login failed:", error);
                clearAuthData();
                setUser(null);
            } finally {
                setLoading(false);
            }
        },
        []
    );

    // Initialize Google Sign-In and restore session
    useEffect(() => {
        // Restore user from storage
        const storedUser = getStoredUser();
        const storedToken = getStoredToken();

        if (storedUser && storedToken) {
            setUser(storedUser);
        }
        setLoading(false);

        // Initialize Google Sign-In when script loads
        const initializeGoogleSignIn = () => {
            if (window.google && GOOGLE_CLIENT_ID) {
                window.google.accounts.id.initialize({
                    client_id: GOOGLE_CLIENT_ID,
                    callback: handleCredentialResponse,
                });
            }
        };

        // Check if already loaded
        if (window.google) {
            initializeGoogleSignIn();
        } else {
            // Wait for script to load
            const checkGoogle = setInterval(() => {
                if (window.google) {
                    initializeGoogleSignIn();
                    clearInterval(checkGoogle);
                }
            }, 100);

            // Cleanup after 10 seconds
            setTimeout(() => clearInterval(checkGoogle), 10000);
        }
    }, [handleCredentialResponse]);

    const login = useCallback(() => {
        if (window.google) {
            window.google.accounts.id.prompt();
        } else {
            console.error("Google Sign-In not loaded");
        }
    }, []);

    const loginWithRedirect = useCallback(() => {
        redirectToGoogleLogin();
    }, []);

    const logout = useCallback(() => {
        clearAuthData();
        setUser(null);
        if (window.google) {
            window.google.accounts.id.disableAutoSelect();
        }
    }, []);

    const refreshUser = useCallback(() => {
        const storedUser = getStoredUser();
        if (storedUser) {
            setUser(storedUser);
        }
    }, []);

    const value: AuthContextType = {
        user,
        loading,
        isAuthenticated: !!user,
        login,
        loginWithRedirect,
        logout,
        refreshUser,
    };

    return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>;
}

export function useAuth(): AuthContextType {
    const context = useContext(AuthContext);
    if (context === undefined) {
        throw new Error("useAuth must be used within an AuthProvider");
    }
    return context;
}
