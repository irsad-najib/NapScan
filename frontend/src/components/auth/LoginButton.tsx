"use client";

import { useEffect, useRef } from "react";
import { useAuth } from "@/context/AuthContext";

interface LoginButtonProps {
  className?: string;
}

export default function LoginButton({ className = "" }: LoginButtonProps) {
  const buttonRef = useRef<HTMLDivElement>(null);
  const { login, loginWithPopup, loading, isAuthenticated, user } = useAuth();

  useEffect(() => {
    if (isAuthenticated) return;
    // Render Google button when available
    const renderButton = () => {
      if (window.google && buttonRef.current) {
        window.google.accounts.id.renderButton(buttonRef.current, {
          theme: "filled_blue",
          size: "large",
          type: "standard",
          shape: "rectangular",
          text: "signin_with",
          logo_alignment: "left",
        });
      }
    };

    // Check if already loaded
    if (window.google) {
      renderButton();
    } else {
      // Poll for Google library
      const checkGoogle = setInterval(() => {
        if (window.google) {
          renderButton();
          clearInterval(checkGoogle);
        }
      }, 100);

      setTimeout(() => clearInterval(checkGoogle), 10000);
    }
  }, [isAuthenticated]);

  // Don't render anything if already authenticated - parent component shows UserMenu instead
  if (isAuthenticated) {
    return null;
  }

  if (loading) {
    return (
      <div className={`flex items-center gap-2 px-4 py-2 ${className}`}>
        <div className="animate-spin rounded-full h-5 w-5 border-2 border-blue-500 border-t-transparent" />
        <span className="text-sm text-slate-600 dark:text-slate-400">
          Loading...
        </span>
      </div>
    );
  }

  return (
    <div className={className}>
      {/* Google rendered button */}
      <div ref={buttonRef} className="google-signin-button" />

      {/* Fallback button if Google doesn't render */}
      <button
        onClick={loginWithPopup}
        className="hidden fallback-login-btn items-center gap-3 px-4 py-3 bg-white dark:bg-slate-800 border border-slate-300 dark:border-slate-600 rounded-xl hover:bg-slate-50 dark:hover:bg-slate-700 transition-all shadow-sm hover:shadow-md">
        <svg viewBox="0 0 24 24" className="w-5 h-5" aria-hidden="true">
          <path
            d="M22.56 12.25c0-.78-.07-1.53-.2-2.25H12v4.26h5.92c-.26 1.37-1.04 2.53-2.21 3.31v2.77h3.57c2.08-1.92 3.28-4.74 3.28-8.09z"
            fill="#4285F4"
          />
          <path
            d="M12 23c2.97 0 5.46-.98 7.28-2.66l-3.57-2.77c-.98.66-2.23 1.06-3.71 1.06-2.86 0-5.29-1.93-6.16-4.53H2.18v2.84C3.99 20.53 7.7 23 12 23z"
            fill="#34A853"
          />
          <path
            d="M5.84 14.09c-.22-.66-.35-1.36-.35-2.09s.13-1.43.35-2.09V7.07H2.18C1.43 8.55 1 10.22 1 12s.43 3.45 1.18 4.93l2.85-2.22.81-.62z"
            fill="#FBBC05"
          />
          <path
            d="M12 5.38c1.62 0 3.06.56 4.21 1.64l3.15-3.15C17.45 2.09 14.97 1 12 1 7.7 1 3.99 3.47 2.18 7.07l3.66 2.84c.87-2.6 3.3-4.53 6.16-4.53z"
            fill="#EA4335"
          />
        </svg>
        <span className="text-sm font-semibold text-slate-700 dark:text-slate-200">
          Sign in with Google
        </span>
      </button>
    </div>
  );
}
