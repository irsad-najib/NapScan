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
  loginWithPopup: () => void;
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

  const loginWithPopup = useCallback(() => {
    const API_URL = process.env.NEXT_PUBLIC_API_URL || "http://localhost:5000";
    const popupCallback = `${window.location.origin}/auth/popup-callback`;

    const width = 500;
    const height = 600;
    const left = window.screen.width / 2 - width / 2;
    const top = window.screen.height / 2 - height / 2;

    const popup = window.open(
      `${API_URL}/api/auth/google/login?redirect_to=${encodeURIComponent(popupCallback)}`,
      "google_login",
      `width=${width},height=${height},left=${left},top=${top}`
    );

    const handleMessage = async (event: MessageEvent) => {
      if (event.origin !== window.location.origin) return;
      if (event.data?.type === "AUTH_SUCCESS") {
        window.removeEventListener("message", handleMessage);
        setLoading(true);

        // Check if popup passed a token
        const tokenFromPopup = event.data?.token;
        if (tokenFromPopup) {
          console.log("[Auth] Received token from popup, storing...");
          localStorage.setItem("napscan_auth_token", tokenFromPopup);
        }

        // Refresh user session from backend
        const me = await fetchMe();
        if (me) {
          const storedToken = getStoredToken();
          if (storedToken) {
            setAuthData(storedToken, me);
          } else {
            localStorage.setItem("napscan_user", JSON.stringify(me));
          }
          setUser(me);
          setLoading(false);
        } else {
          // fetchMe failed - if we have token, try to use it anyway
          const token = getStoredToken();
          if (token) {
            console.log("[Auth] fetchMe failed but have token, storing user from token");
            // Decode JWT to get user info (basic decode without verification)
            try {
              const payload = JSON.parse(atob(token.split('.')[1]));
              const userFromToken = {
                email: payload.email || '',
                name: payload.name || payload.email || '',
                picture: payload.picture || '',
              };
              setAuthData(token, userFromToken);
              setUser(userFromToken);
            } catch (e) {
              console.error("[Auth] Failed to decode token:", e);
            }
          }
          setLoading(false);
        }
      }
    };

    window.addEventListener("message", handleMessage);

    // Cleanup if popup is closed without completing auth
    const checkPopupClosed = setInterval(() => {
      if (popup?.closed) {
        clearInterval(checkPopupClosed);
        window.removeEventListener("message", handleMessage);
      }
    }, 500);
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
    loginWithPopup,
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
