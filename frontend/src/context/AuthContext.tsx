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
  fetchMe,
  logout as backendLogout,
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

        // Persist token first so subsequent requests can use it.
        setAuthData(authResponse.access_token, authResponse.user);

        // If we have a token, fetch the canonical profile from backend.
        // (This also verifies the token/cookie session is usable.)
        if (authResponse.access_token) {
          const me = await fetchMe();
          if (me) {
            // Keep the token, but update user/profile from /me.
            setAuthData(authResponse.access_token, me);
            setUser(me);
            return;
          }
        }

        // Fallback: use user from login response.
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

  // Initialize and restore session
  useEffect(() => {
    // Fast path: restore from storage for instant UI.
    const storedUser = getStoredUser();
    if (storedUser) {
      setUser(storedUser);
    }

    // Authoritative path: validate cookie session via backend.
    (async () => {
      const me = await fetchMe();
      if (me) {
        const storedToken = getStoredToken();
        if (storedToken) {
          setAuthData(storedToken, me);
        } else {
          // Cookie-based session: store user only.
          localStorage.setItem("napscan_user", JSON.stringify(me));
        }
        setUser(me);
      } else {
        // No valid cookie session; keep token-based session if it exists.
        const t = getStoredToken();
        const u = getStoredUser();
        if (!(t && u)) {
          clearAuthData();
          setUser(null);
        }
      }
      setLoading(false);
    })();

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
    (async () => {
      await backendLogout();
      clearAuthData();
      setUser(null);
      if (window.google) {
        window.google.accounts.id.disableAutoSelect();
      }
    })();
  }, []);

  const refreshUser = useCallback(() => {
    (async () => {
      const me = await fetchMe();
      if (me) {
        localStorage.setItem("napscan_user", JSON.stringify(me));
        setUser(me);
        return;
      }
      clearAuthData();
      setUser(null);
    })();
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
