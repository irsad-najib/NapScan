'use client';

import { useEffect, useState } from 'react';

// Helper function to get cookie value
function getCookie(name: string): string | null {
  if (typeof document === 'undefined') return null;
  const value = `; ${document.cookie}`;
  const parts = value.split(`; ${name}=`);
  if (parts.length === 2) {
    return parts.pop()?.split(';').shift() || null;
  }
  return null;
}

export default function AuthPopupCallback() {
  const [status, setStatus] = useState<'loading' | 'success' | 'error'>('loading');
  const [errorMsg, setErrorMsg] = useState('');

  useEffect(() => {
    // Try to get the auth token from cookie
    const token = getCookie('napscan_access_token');

    console.log('[AuthPopupCallback] Checking for auth token...');
    console.log('[AuthPopupCallback] Document cookies:', document.cookie);
    console.log('[AuthPopupCallback] Token found:', token ? 'yes (length: ' + token.length + ')' : 'no');

    if (window.opener) {
      if (token) {
        // Pass token to parent window so it can store it
        console.log('[AuthPopupCallback] Sending token to parent window');
        window.opener.postMessage(
          { type: 'AUTH_SUCCESS', token },
          window.location.origin
        );
        setStatus('success');
      } else {
        // No token in cookie, but still notify parent to try fetching /me
        console.log('[AuthPopupCallback] No token found, notifying parent anyway');
        window.opener.postMessage(
          { type: 'AUTH_SUCCESS' },
          window.location.origin
        );
        setStatus('success');
      }
      // Close popup after a short delay
      setTimeout(() => window.close(), 500);
    } else {
      // Not in a popup - redirect to dashboard
      console.log('[AuthPopupCallback] Not in popup, redirecting to dashboard');
      if (token) {
        // Store token before redirecting
        localStorage.setItem('napscan_auth_token', token);
      }
      setStatus('success');
      setTimeout(() => {
        window.location.href = '/';
      }, 500);
    }
  }, []);

  return (
    <div className="flex min-h-screen items-center justify-center bg-slate-950 text-white">
      <div className="text-center">
        {status === 'loading' && (
          <>
            <div className="w-8 h-8 border-4 border-blue-500 border-t-transparent rounded-full animate-spin mx-auto mb-4" />
            <p className="text-lg font-medium">Processing authentication...</p>
          </>
        )}
        {status === 'success' && (
          <>
            <span className="material-symbols-outlined text-4xl text-emerald-400 mb-2">check_circle</span>
            <p className="text-lg font-medium">Authentication successful!</p>
            <p className="text-sm text-slate-400">Closing window...</p>
          </>
        )}
        {status === 'error' && (
          <>
            <span className="material-symbols-outlined text-4xl text-red-400 mb-2">error</span>
            <p className="text-lg font-medium">Authentication failed</p>
            <p className="text-sm text-red-400">{errorMsg}</p>
          </>
        )}
      </div>
    </div>
  );
}
